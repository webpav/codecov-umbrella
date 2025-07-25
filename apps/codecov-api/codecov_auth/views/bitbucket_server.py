"""
Bitbucket Server OAuth Authentication View

This module handles OAuth 1.0 and OAuth 2.0 authentication flows for Bitbucket Server/Data Center.

Key Implementation Details:
1. Supports both OAuth 1.0 (legacy) and OAuth 2.0 flows
2. Uses Bitbucket Server personal projects to extract username
3. Every user in Bitbucket Server automatically gets a personal project with key ~username
4. This approach doesn't require admin permissions and works with standard user permissions

Username Extraction Strategy:
- Call /api/latest/projects endpoint (requires basic REPO_READ permission)
- Filter projects where key starts with "~" (personal projects)
- Extract username by removing "~" prefix from project key
- This is much more reliable than using admin-only endpoints

OAuth Flow Handling:
- OAuth 2.0: Uses PKCE flow with state parameter for security
- OAuth 1.0: Legacy flow for backwards compatibility
- Automatic detection of callback type based on request parameters
"""

import base64
import logging
import secrets
import threading
from urllib.parse import urlencode

from asgiref.sync import async_to_sync
from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse
from django.views import View

from codecov_auth.models import SERVICE_BITBUCKET_SERVER
from codecov_auth.views.base import LoginMixin
from shared.torngit import BitbucketServer
from shared.torngit.exceptions import TorngitServerFailureError
from utils.encryption import encryptor

log = logging.getLogger(__name__)


class BitbucketServerLoginView(View, LoginMixin):
    service = SERVICE_BITBUCKET_SERVER
    
    def _is_oauth2_enabled(self):
        """Check if OAuth 2.0 is enabled from settings"""
        return BitbucketServer.is_oauth2_enabled()
    
    def _get_redirect_uri(self, request):
        return f"{settings.CODECOV_URL}/login/bbs"
    
    def _generate_state(self):
        """Generate secure state parameter for OAuth 2.0"""
        return secrets.token_urlsafe(32)

    async def fetch_user_data(self, token):
        """Fetch user data supporting both OAuth 1.0 and OAuth 2.0 tokens"""
        repo_service = BitbucketServer(
            oauth_consumer_token={
                "key": settings.BITBUCKET_SERVER_CLIENT_ID,
                "secret": settings.BITBUCKET_SERVER_CLIENT_SECRET,
            },
            token=token,
        )
        
        # Determine token type for appropriate API calls
        token_type = self._determine_token_type(token)
        
        if token_type == "oauth2":
            return await self._fetch_oauth2_user_data(repo_service, token)
        else:
            return await self._fetch_oauth1_user_data(repo_service, token)
    
    def _determine_token_type(self, token):
        """Determine if token is OAuth 1.0 or OAuth 2.0 format"""
        if isinstance(token, dict) and "access_token" in token:
            return "oauth2"
        elif isinstance(token, dict) and "key" in token and "secret" in token:
            return "oauth1"
        else:
            return "unknown"
    
    async def _fetch_oauth2_user_data(self, repo_service, token):
        """Fetch user data using OAuth 2.0 Bearer token with Bitbucket Server personal projects approach"""
        try:
            # SOLUTION: Use personal projects to extract username
            # In Bitbucket Server, every user automatically gets a personal project with key ~username
            # This is documented behavior and doesn't require admin permissions
            
            log.info("Fetching OAuth 2.0 user data using personal projects approach")
            
            # Step 1: Get all projects that the authenticated user can access
            # FIXED: Use correct path without /api/latest prefix since base URL already includes /rest/api/1.0
            projects_response = await repo_service.api("GET", "/projects", limit=100)
            
            if not projects_response or not projects_response.get("values"):
                raise Exception("No projects found for the authenticated user")
            
            # Step 2: Find personal project (key starts with ~)
            personal_projects = [
                project for project in projects_response["values"]
                if project.get("key", "").startswith("~")
            ]
            
            if not personal_projects:
                raise Exception("No personal projects found. User may not have a personal project.")
            
            # Step 3: Extract username from personal project key (~username)
            personal_project = personal_projects[0]  # User should only have one personal project
            project_key = personal_project.get("key", "")
            
            if not project_key.startswith("~"):
                raise Exception("Invalid personal project key format")
            
            # Extract username by removing the ~ prefix
            username = project_key[1:]  # Remove the ~ prefix
            
            if not username:
                raise Exception("Could not extract username from personal project key")
            
            log.info(f"Successfully extracted username from personal project: {username}")
            
            # Step 4: Get user organizations/teams
            user_orgs = await repo_service.list_teams()
            
            # Step 5: Build user object using personal project information
            user = {
                "id": personal_project.get("owner", {}).get("id"),
                "name": username,
                "slug": username,
                "displayName": personal_project.get("owner", {}).get("displayName", username),
                "emailAddress": personal_project.get("owner", {}).get("emailAddress"),
            }
            
            # Build authenticated user structure for OAuth 2.0
            authenticated_user = {
                "access_token": token.get("access_token"),
                "refresh_token": token.get("refresh_token"),
                "expires_at": token.get("expires_at"),
                "token_type": token.get("token_type", "Bearer"),
                "id": user.get("id"),
                "login": username,
                "username": username,
            }
            
            return {
                "user": authenticated_user,
                "orgs": user_orgs,
                "is_student": False,
                "has_private_access": True,
            }
            
        except Exception as e:
            log.error(f"Failed to fetch OAuth 2.0 user data using personal projects: {e}")
            raise
    
    async def _fetch_oauth1_user_data(self, repo_service, token):
        """Fetch user data using OAuth 1.0 signed requests with Bitbucket Server personal projects approach"""
        try:
            # SOLUTION: Use personal projects to extract username
            # Same approach as OAuth 2.0 but with OAuth 1.0 token format
            
            log.info("Fetching OAuth 1.0 user data using personal projects approach")
            
            # Step 1: Get all projects that the authenticated user can access
            # FIXED: Use correct path without /api/latest prefix since base URL already includes /rest/api/1.0
            projects_response = await repo_service.api("GET", "/projects", limit=100)
            
            if not projects_response or not projects_response.get("values"):
                raise Exception("No projects found for the authenticated user")
            
            # Step 2: Find personal project (key starts with ~)
            personal_projects = [
                project for project in projects_response["values"]
                if project.get("key", "").startswith("~")
            ]
            
            if not personal_projects:
                raise Exception("No personal projects found. User may not have a personal project.")
            
            # Step 3: Extract username from personal project key (~username)
            personal_project = personal_projects[0]  # User should only have one personal project
            project_key = personal_project.get("key", "")
            
            if not project_key.startswith("~"):
                raise Exception("Invalid personal project key format")
            
            # Extract username by removing the ~ prefix
            username = project_key[1:]  # Remove the ~ prefix
            
            if not username:
                raise Exception("Could not extract username from personal project key")
            
            log.info(f"Successfully extracted username from personal project: {username}")
            
            # Step 4: Get user organizations/teams
            user_orgs = await repo_service.list_teams()
            
            # Step 5: Build user object using personal project information
            user = {
                "id": personal_project.get("owner", {}).get("id"),
                "name": username,
                "slug": username,
                "displayName": personal_project.get("owner", {}).get("displayName", username),
                "emailAddress": personal_project.get("owner", {}).get("emailAddress"),
            }
            
            # Build authenticated user structure for OAuth 1.0
            authenticated_user = {
                "key": token["key"],
                "secret": token["secret"],
                "id": user.get("id"),
                "login": username,
                "username": username,
            }
            
            return {
                "user": authenticated_user,
                "orgs": user_orgs,
                "is_student": False,
                "has_private_access": True,
            }
            
        except Exception as e:
            log.error(f"Failed to fetch OAuth 1.0 user data using personal projects: {e}")
            raise

    async def redirect_to_bitbucket_server_step(self, request):
        # Check if OAuth 2.0 is enabled
        if self._is_oauth2_enabled():
            return await self._redirect_oauth2_step(request)
        else:
            return await self._redirect_oauth1_step(request)
    
    async def _redirect_oauth2_step(self, request):
        """Handle OAuth 2.0 authorization redirect"""
        repo_service = BitbucketServer(
            oauth_consumer_token={
                "key": settings.BITBUCKET_SERVER_CLIENT_ID,
                "secret": settings.BITBUCKET_SERVER_CLIENT_SECRET,
            }
        )
        
        # Generate OAuth 2.0 authorization URL using library function
        redirect_uri = self._get_redirect_uri(request)
        state = self._generate_state()
        scopes = getattr(settings, 'BITBUCKET_SERVER_OAUTH2_SCOPE', ['PUBLIC_REPOS'])
        
        try:
            auth_url, code_verifier = repo_service.generate_oauth2_authorization_url(
                redirect_uri=redirect_uri,
                state=state,
                scopes=scopes
            )
            
            # Store state and code_verifier in secure cookies
            response = redirect(auth_url)
            
            # Store OAuth 2.0 state and code verifier
            oauth2_data = f"{state}|{code_verifier}"
            response.set_signed_cookie(
                "_oauth2_state",
                encryptor.encode(oauth2_data).decode(),
                domain=settings.COOKIES_DOMAIN,
            )
            
            self.store_to_cookie_utm_tags(response)
            return response
            
        except Exception as e:
            log.error(f"Failed to generate OAuth 2.0 authorization URL: {e}")
            return redirect(settings.CODECOV_DASHBOARD_URL + "/bbs")
    
    async def _redirect_oauth1_step(self, request):
        """Handle OAuth 1.0 authorization redirect (legacy)"""
        # And the consumer needs to have the defined client id. The secret is ignored.
        # https://developer.atlassian.com/server/jira/platform/oauth/
        repo_service = BitbucketServer(
            oauth_consumer_token={
                "key": settings.BITBUCKET_SERVER_CLIENT_ID,
                "secret": "",
            }
        )
        # In this part we make a request for the unauthorized request token.
        # Here the user will be redirected to the authorize page and allow our app to be used.
        # At the end of this step client will see a screen saying "you have authorized this application. Return to application and click continue."
        request_token_url = (
            f"{settings.BITBUCKET_SERVER_URL}/plugins/servlet/oauth/request-token"
        )
        request_token = await repo_service.api("POST", request_token_url)

        auth_token = request_token["oauth_token"]
        auth_token_secret = request_token["oauth_token_secret"]

        data = (
            base64.b64encode(auth_token.encode())
            + b"|"
            + base64.b64encode(auth_token_secret.encode())
        ).decode()

        # Use OAuth 1.0 authorize endpoint
        url_params = urlencode({"oauth_token": auth_token})
        authorize_url = f"{settings.BITBUCKET_SERVER_URL}/plugins/servlet/oauth/authorize?{url_params}"
        response = redirect(authorize_url)
        response.set_signed_cookie(
            "_oauth_request_token",
            encryptor.encode(data).decode(),
            domain=settings.COOKIES_DOMAIN,
        )
        self.store_to_cookie_utm_tags(response)
        return response

    async def actual_login_step(self, request):
        # Determine which OAuth flow to use based on actual callback type, not just configuration
        has_oauth2_callback = (
            request.GET.get('code') and
            request.GET.get('state') and
            request.COOKIES.get("_oauth2_state")
        )
        has_oauth1_callback = request.COOKIES.get("_oauth_request_token")

        if has_oauth2_callback:
            return await self._oauth2_login_step(request)
        elif has_oauth1_callback:
            return await self._oauth1_login_step(request)
        else:
            # No valid callback detected, redirect to start authorization
            log.warning("No valid OAuth callback detected in actual_login_step")
            return redirect(reverse("bbs-login"))
    
    async def _oauth2_login_step(self, request):
        """Handle OAuth 2.0 login step"""
        # Check for OAuth 2.0 state cookie
        oauth2_cookie = request.get_signed_cookie("_oauth2_state", default=None)
        if not oauth2_cookie:
            log.warning("OAuth 2.0 request arrived without proper state cookie")
            return redirect(reverse("bbs-login"))
        
        # Extract state and code verifier from cookie
        try:
            oauth2_data = encryptor.decode(oauth2_cookie)
            stored_state, code_verifier = oauth2_data.split("|", 1)
        except Exception as e:
            log.error(f"Failed to decode OAuth 2.0 state cookie: {e}")
            return redirect(reverse("bbs-login"))
        
        # Verify state parameter
        request_state = request.GET.get('state')
        if not request_state or request_state != stored_state:
            log.warning("OAuth 2.0 state parameter mismatch")
            return redirect(reverse("bbs-login"))
        
        # Get authorization code
        auth_code = request.GET.get('code')
        if not auth_code:
            log.warning("OAuth 2.0 authorization code not found")
            return redirect(reverse("bbs-login"))
        
        # Exchange code for token using library function
        repo_service = BitbucketServer(
            oauth_consumer_token={
                "key": settings.BITBUCKET_SERVER_CLIENT_ID,
                "secret": settings.BITBUCKET_SERVER_CLIENT_SECRET,
            }
        )
        
        try:
            redirect_uri = self._get_redirect_uri(request)
            access_token = await repo_service.exchange_code_for_token(
                code=auth_code,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier
            )
            
            # Fetch user data with OAuth 2.0 token
            user_dict = await self.fetch_user_data(access_token)
            
            # Clean up cookies and redirect
            response = redirect(settings.CODECOV_DASHBOARD_URL + "/bbs")
            response.delete_cookie("_oauth2_state", domain=settings.COOKIES_DOMAIN)
            
            def async_login():
                user = self.get_and_modify_owner(user_dict, request)
                self.login_owner(user, request, response)
                log.info(
                    "User (OAuth 2.0) successfully logged in", extra={"ownerid": user.ownerid}
                )

            force_sync = threading.Thread(target=async_login)
            force_sync.start()
            force_sync.join()
            return response
            
        except Exception as e:
            log.error(f"OAuth 2.0 token exchange failed: {e}")
            response = redirect(settings.CODECOV_DASHBOARD_URL + "/bbs")
            response.delete_cookie("_oauth2_state", domain=settings.COOKIES_DOMAIN)
            return response
    
    async def _oauth1_login_step(self, request):
        """Handle OAuth 1.0 login step (legacy)"""
        # Retrieve the authorized request_token and create a new client
        # This new client has the same consumer as before, but uses the request token.
        # ! Each request_token can only be used once
        request_cookie = request.get_signed_cookie("_oauth_request_token", default=None)
        if not request_cookie:
            log.warning(
                "OAuth 1.0 request arrived with proper url params but not the proper cookies"
            )
            return redirect(reverse("bbs-login"))

        request_cookie = encryptor.decode(request_cookie)
        cookie_key, cookie_secret = [
            base64.b64decode(i).decode() for i in request_cookie.split("|")
        ]
        token = {"key": cookie_key, "secret": cookie_secret}
        repo_service = BitbucketServer(
            oauth_consumer_token={
                "key": settings.BITBUCKET_SERVER_CLIENT_ID,
                "secret": settings.BITBUCKET_SERVER_CLIENT_SECRET,
            },
            token=token,
        )
        # Get the access token from the request token
        # The access token can be stored and reused.
        response = redirect(settings.CODECOV_DASHBOARD_URL + "/bbs")
        response.delete_cookie("_oauth_request_token", domain=settings.COOKIES_DOMAIN)
        
        # Use OAuth 1.0 access token endpoint
        access_token_url = (
            f"{settings.BITBUCKET_SERVER_URL}/plugins/servlet/oauth/access-token"
        )
        access_token = await repo_service.api("POST", access_token_url)
        auth_token = access_token["oauth_token"]
        auth_token_secret = access_token["oauth_token_secret"]

        user_dict = await self.fetch_user_data(
            {"key": auth_token, "secret": auth_token_secret}
        )

        def async_login():
            user = self.get_and_modify_owner(user_dict, request)
            self.login_owner(user, request, response)
            log.info(
                "User (OAuth 1.0) successfully logged in", extra={"ownerid": user.ownerid}
            )

        force_sync = threading.Thread(target=async_login)
        force_sync.start()
        force_sync.join()
        return response

    @async_to_sync
    async def get(self, request):
        try:
            # First check if OAuth 2.0 is enabled in configuration
            oauth2_enabled = self._is_oauth2_enabled()
            
            # Check for OAuth 2.0 callback (code parameter) or OAuth 1.0 callback (oauth_token cookie)
            has_oauth2_callback = (
                request.GET.get('code') and 
                request.GET.get('state') and 
                request.COOKIES.get("_oauth2_state")
            )
            has_oauth1_callback = request.COOKIES.get("_oauth_request_token")
            
            # If OAuth 2.0 is enabled but we have OAuth 1.0 callback, prioritize OAuth 2.0
            if oauth2_enabled and has_oauth1_callback and not has_oauth2_callback:
                log.warning("OAuth 2.0 is enabled but OAuth 1.0 callback detected, cleaning up old cookies and redirecting")
                # Clear old OAuth 1.0 cookies and redirect to start fresh OAuth 2.0 flow
                response = redirect(reverse("bbs-login"))
                response.delete_cookie("_oauth_request_token", domain=settings.COOKIES_DOMAIN)
                return response
            
            if has_oauth2_callback:
                log.info("Logging into bitbucket_server after OAuth 2.0 authorization")
                return await self.actual_login_step(request)
            elif has_oauth1_callback and not oauth2_enabled:
                log.info("Logging into bitbucket_server after OAuth 1.0 authorization")
                return await self.actual_login_step(request)
            else:
                log.info("Redirecting user to bitbucket_server for authorization")
                return await self.redirect_to_bitbucket_server_step(request)
        except TorngitServerFailureError:
            log.warning("Bitbucket Server not available for login")
            return redirect(settings.CODECOV_DASHBOARD_URL + "/bbs")
