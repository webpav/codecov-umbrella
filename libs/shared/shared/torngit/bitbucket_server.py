import base64
import hashlib
import logging
import os
import secrets
import urllib.parse
from datetime import datetime
from typing import Optional

import httpx
from oauthlib import oauth1

from shared.config import get_config
from shared.torngit.base import TorngitBaseAdapter
from shared.torngit.exceptions import (
    TorngitClientError,
    TorngitClientGeneralError,
    TorngitObjectNotFoundError,
    TorngitServer5xxCodeError,
    TorngitServerUnreachableError,
)
from shared.torngit.status import Status
from shared.utils.urls import url_concat

log = logging.getLogger(__name__)


class BitbucketServer(TorngitBaseAdapter):
    # https://developer.atlassian.com/server/bitbucket/rest/v903/intro/#about
    service = "bitbucket_server"

    @classmethod
    def get_service_url(cls):
        return get_config("bitbucket_server", "url")

    @property
    def service_url(self):
        return self.get_service_url()
    
    @classmethod
    def is_oauth2_enabled(cls):
        """Check if OAuth 2.0 is enabled for Bitbucket Server"""
        return get_config("bitbucket_server", "oauth2", "enabled", default=False)
    
    def _generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge pair"""
        # Generate code verifier (43-128 characters, URL-safe)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate code challenge using S256 method
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def _get_oauth2_endpoints(self) -> dict:
        """Get OAuth 2.0 endpoints from configuration"""
        base_url = self.service_url
        return {
            "authorize": get_config(
                "bitbucket_server", "oauth2", "authorize_url",
                default=f"{base_url}/rest/oauth2/latest/authorize"
            ),
            "token": get_config(
                "bitbucket_server", "oauth2", "token_url", 
                default=f"{base_url}/rest/oauth2/latest/token"
            )
        }
    
    def _determine_token_type(self, token: Optional[dict]) -> str:
        """Determine if token is OAuth 1.0 or OAuth 2.0 format"""
        if not token:
            return "none"
        
        # OAuth 2.0 tokens have 'access_token' field
        if isinstance(token, dict) and "access_token" in token:
            return "oauth2"
        
        # OAuth 1.0 tokens have 'key' and 'secret' fields
        if isinstance(token, dict) and "key" in token and "secret" in token:
            return "oauth1"
        
        return "unknown"
    
    async def _refresh_oauth2_token_if_needed(self, token: dict) -> dict:
        """Refresh OAuth 2.0 token if expired and refresh token is available"""
        if self._determine_token_type(token) != "oauth2":
            return token
        
        # Check if token is expired or about to expire
        expires_at = token.get("expires_at")
        if not expires_at:
            return token  # No expiration info, assume valid
        
        try:
            from datetime import datetime, timedelta
            expires_datetime = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
            if datetime.now() < (expires_datetime - timedelta(minutes=5)):
                return token  # Token still valid for at least 5 minutes
        except (ValueError, TypeError):
            pass  # Invalid date format, proceed with refresh
        
        # Attempt to refresh token
        refresh_token = token.get("refresh_token")
        if not refresh_token:
            log.warning("OAuth 2.0 token expired but no refresh token available")
            return token
        
        try:
            new_token = await self._perform_token_refresh(refresh_token)
            log.info("Successfully refreshed OAuth 2.0 token")
            return new_token
        except Exception as e:
            log.warning(f"Failed to refresh OAuth 2.0 token: {e}")
            return token
    
    async def _perform_token_refresh(self, refresh_token: str) -> dict:
        """Perform OAuth 2.0 token refresh"""
        endpoints = self._get_oauth2_endpoints()
        
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": get_config("bitbucket_server", "client_id"),
            "client_secret": get_config("bitbucket_server", "client_secret")
        }
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": os.getenv("USER_AGENT", "Default"),
        }
        
        async with self.get_client() as client:
            response = await client.post(
                endpoints["token"],
                data=data,
                headers=headers
            )
            
            if response.status_code != 200:
                raise Exception(f"Token refresh failed: {response.status_code} {response.text}")
            
            token_data = response.json()
            
            # Add expiration timestamp if expires_in is provided
            if "expires_in" in token_data:
                from datetime import datetime, timedelta
                expires_at = datetime.now() + timedelta(seconds=token_data["expires_in"])
                token_data["expires_at"] = expires_at.isoformat()
            
            return token_data

    urls = {
        "user": "users/%(username)s",
        "owner": "projects/%(username)s",
        "repo": "projects/%(username)s/repos/%(name)s",
        "issues": "projects/%(username)s/repos/%(name)s/issues/%(issueid)s",
        "commit": "projects/%(username)s/repos/%(name)s/commits/%(commitid)s",
        "commits": "projects/%(username)s/repos/%(name)s/commits",
        "src": "projects/%(username)s/repos/%(name)s/browse/%(path)s?at=%(commitid)s",
        "tree": "projects/%(username)s/repos/%(name)s/browse?at=%(commitid)s",
        "create_file": None,
        "branch": "projects/%(username)s/repos/%(name)s/browser?at=%(branch)s",
        "pull": "projects/%(username)s/repos/%(name)s/pull-requests/%(pullid)s/overview",
        "compare": "",
    }

    @property
    def project(self):
        if self.data["owner"].get("service_id", "?")[0] == "U":
            return "/projects/~{}".format(self.data["owner"]["username"].upper())
        else:
            return "/projects/{}".format(self.data["owner"]["username"].upper())

    def diff_to_json(self, diff_json):
        results = {}
        for _diff in diff_json:
            if not _diff.get("destination"):
                results[_diff["source"]["toString"]] = {"type": "deleted"}

            else:
                fname = _diff["destination"]["toString"]
                _before = _diff["source"]["toString"] if _diff.get("source") else None
                _file = results.setdefault(
                    fname,
                    {
                        "before": _before if _before != fname else None,
                        "type": "new" if _before is None else "modified",
                        "segments": [],
                    },
                )
                for hunk in _diff.get("hunks", []):
                    segment = {
                        "header": [
                            str(hunk["sourceLine"]),
                            str(hunk["sourceSpan"]),
                            str(hunk["destinationLine"]),
                            str(hunk["destinationSpan"]),
                        ],
                        "lines": [],
                    }
                    _file["segments"].append(segment)
                    for seg in hunk["segments"]:
                        t = seg["type"][0]
                        for ln in seg["lines"]:
                            segment["lines"].append(
                                ("-" if t == "R" else "+" if t == "A" else " ")
                                + ln["line"]
                            )

        if results:
            return {"files": self._add_diff_totals(results)}
        else:
            return {"files": []}

    async def api(self, method, url, body=None, token=None, **kwargs):
        # process desired api path
        if not url.startswith("http"):
            url = f"{self.service_url}/rest/api/1.0{url}"

        # process inline arguments
        if kwargs:
            url = url_concat(url, kwargs)

        token_to_use = token or self.token
        
        # Determine token type and prepare headers accordingly
        token_type = self._determine_token_type(token_to_use)
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": os.getenv("USER_AGENT", "Default"),
        }
        
        # Handle OAuth 2.0 authentication
        if token_type == "oauth2":
            # Refresh token if needed
            token_to_use = await self._refresh_oauth2_token_if_needed(token_to_use)
            
            # Add Bearer token to headers
            access_token = token_to_use.get("access_token")
            if access_token:
                headers["Authorization"] = f"Bearer {access_token}"
            else:
                log.warning("OAuth 2.0 token missing access_token field")
                
        # Handle OAuth 1.0 authentication (fallback)
        elif token_type == "oauth1":
            try:
                oauth_client = oauth1.Client(
                    self._oauth_consumer_token()["key"],
                    client_secret=self._oauth_consumer_token()["secret"],
                    resource_owner_key=token_to_use["key"],
                    resource_owner_secret=token_to_use["secret"],
                    signature_type=oauth1.SIGNATURE_TYPE_QUERY,
                )
                url, headers, _oauth_body = oauth_client.sign(
                    url, http_method=method, headers=headers
                )
            except Exception as e:
                log.error(f"OAuth 1.0 signature generation failed: {e}")
                raise TorngitClientError(f"Authentication failed: {e}")
        
        # Handle case where no valid token is available
        elif token_type in ["none", "unknown"]:
            log.warning(f"No valid authentication token available (type: {token_type})")

        log_dict = {
            "event": "api",
            "endpoint": url,
            "method": method,
            "auth_type": token_type,
            "bot": token_to_use.get("username") if isinstance(token_to_use, dict) else None,
            "repo_slug": self.slug,
        }

        try:
            async with self.get_client() as client:
                res = await client.request(
                    method.upper(), url, json=body, headers=headers
                )
            logged_body = None
            if res.status_code >= 300 and res.text is not None:
                logged_body = res.text
            log.log(
                logging.WARNING if res.status_code >= 300 else logging.INFO,
                "Bitbucket HTTP %s",
                res.status_code,
                extra=dict(body=logged_body, **log_dict),
            )
        except (httpx.NetworkError, httpx.TimeoutException):
            raise TorngitServerUnreachableError("Bitbucket was not able to be reached.")
        
        # Handle authentication errors specifically
        if res.status_code == 401:
            if token_type == "oauth2":
                log.warning("OAuth 2.0 authentication failed, token may be invalid")
            elif token_type == "oauth1":
                log.warning("OAuth 1.0 authentication failed, credentials may be invalid")
            raise TorngitClientError("Authentication failed", code=401)
            
        if res.status_code == 599:
            raise TorngitServerUnreachableError(
                "Bitbucket was not able to be reached, server timed out."
            )
        elif res.status_code >= 500:
            raise TorngitServer5xxCodeError("Bitbucket is having 5xx issues")
        elif res.status_code >= 300:
            message = f"Bitbucket API: {res.reason_phrase}"
            raise TorngitClientGeneralError(
                res.status_code, response_data={"content": res.content}, message=message
            )
        if res.status_code == 204:
            return None
        elif "application/json" in res.headers.get("Content-Type"):
            return res.json()
        else:
            return res.text

    async def get_authenticated(self, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp1889424
        if self.data["repo"]["private"]:
            await self.api(
                "get",
                "{}/repos/{}".format(self.project, self.data["repo"]["name"]),
                token=token,
            )
        return (True, True)

    async def get_is_admin(self, user, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp3389568
        res = await self.api(
            "get",
            f"{self.project}/permissions/users",
            filter=user["username"],
            token=token,
        )
        userid = str(user["service_id"]).replace("U", "")
        # PROJECT_READ, PROJECT_WRITE, PROJECT_ADMIN, ADMIMN
        res = any(
            filter(
                lambda v: str(v["user"]["id"]) == userid and "ADMIN" in v["permission"],
                res["values"],
            )
        )
        return res

    async def get_repository(self, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp1889424
        res = await self.api(
            "get",
            "{}/repos/{}".format(self.project, self.data["repo"]["name"]),
            token=token,
        )
        owner_service_id = res["project"]["id"]
        if res["project"]["type"] == "PERSONAL":
            owner_service_id = f"U{res['project']['owner']['id']}"

        fork = None
        if res.get("origin"):
            _fork_owner_service_id = res["origin"]["project"]["id"]
            if res["origin"]["project"]["type"] == "PERSONAL":
                _fork_owner_service_id = f"U{res['origin']['project']['owner']['id']}"

            fork = {
                "owner": {
                    "service_id": _fork_owner_service_id,
                    "username": res["origin"]["project"]["key"],
                },
                "repo": {
                    "service_id": res["origin"]["id"],
                    "language": None,
                    "private": (not res["origin"]["public"]),
                    "branch": "main",
                    "fork": fork,
                    "name": res["origin"]["slug"],
                },
            }

        return {
            "owner": {
                "service_id": owner_service_id,
                "username": res["project"]["key"],
            },
            "repo": {
                "service_id": res["id"],
                "language": None,
                "private": (not res.get("public", res.get("origin", {}).get("public"))),
                "branch": "main",
                "name": res["slug"],
            },
        }

    async def get_repo_languages(
        self, token=None, language: str | None = None
    ) -> list[str]:
        """
        Gets the languages belonging to this repository. Bitbucket has no way to
        track languages, so we'll return a list with the existing language
        Param:
            language: the language belonging to the repository.language key
        Returns:
            List[str]: A list of language names
        """
        languages = []

        if language:
            languages.append(language.lower())

        return languages

    async def get_source(self, path, ref, token=None):
        content, start = [], 0
        while True:
            # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp2028128
            try:
                res = await self.api(
                    "get",
                    "{}/repos/{}/browse/{}".format(
                        self.project,
                        self.data["repo"]["name"],
                        path.replace(" ", "%20"),
                    ),
                    at=ref,
                    start=start,
                    token=token,
                )
            except TorngitClientError as ce:
                if ce.code == 404:
                    raise TorngitObjectNotFoundError(
                        response_data=ce.response_data,
                        message=f"Path {path} not found at {ref}",
                    )
                raise

            content.extend(res["lines"])
            if res["isLastPage"] or res.get("nextPageStart") is None:
                break
            else:
                start = res["nextPageStart"]

        return {
            "commitid": None,  # [FUTURE] unknown atm
            "content": "\n".join(a.get("text", "") for a in content),
        }

    async def get_ancestors_tree(self, commitid, token=None):
        res = await self.api(
            "get",
            "{}/repos/{}/commits/".format(self.project, self.data["repo"]["name"]),
            token=token,
            until=commitid,
        )
        start = res["values"][0]["id"]
        commit_mapping = {
            val["id"]: [k["id"] for k in val["parents"]] for val in res["values"]
        }
        return self.build_tree_from_commits(start, commit_mapping)
    
    # OAuth 2.0 public methods
    def generate_oauth2_authorization_url(self, redirect_uri: str, state: str = None, scopes: list = None) -> tuple[str, str]:
        """Generate OAuth 2.0 authorization URL with PKCE support"""
        if not self.is_oauth2_enabled():
            raise ValueError("OAuth 2.0 is not enabled for Bitbucket Server")
        
        endpoints = self._get_oauth2_endpoints()
        code_verifier, code_challenge = self._generate_pkce_pair()
        
        # Default scopes if not provided
        if scopes is None:
            scopes = get_config("bitbucket_server", "oauth2", "scope", default=["PUBLIC_REPOS"])
        
        params = {
            "response_type": "code",
            "client_id": get_config("bitbucket_server", "client_id"),
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes) if isinstance(scopes, list) else scopes,
        }
        
        # Add state parameter if provided
        if state:
            params["state"] = state
        
        # Add PKCE parameters if enabled
        if get_config("bitbucket_server", "oauth2", "use_pkce", default=True):
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = get_config(
                "bitbucket_server", "oauth2", "pkce_code_challenge_method", default="S256"
            )
        
        # Build authorization URL
        auth_url = endpoints["authorize"] + "?" + urllib.parse.urlencode(params)
        
        return auth_url, code_verifier
    
    async def exchange_code_for_token(self, code: str, redirect_uri: str, code_verifier: str = None) -> dict:
        """Exchange authorization code for OAuth 2.0 access token"""
        if not self.is_oauth2_enabled():
            raise ValueError("OAuth 2.0 is not enabled for Bitbucket Server")
        
        endpoints = self._get_oauth2_endpoints()
        
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": get_config("bitbucket_server", "client_id"),
            "client_secret": get_config("bitbucket_server", "client_secret"),
        }
        
        # Add PKCE verifier if provided
        if code_verifier and get_config("bitbucket_server", "oauth2", "use_pkce", default=True):
            data["code_verifier"] = code_verifier
        
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": os.getenv("USER_AGENT", "Default"),
        }
        
        try:
            async with self.get_client() as client:
                response = await client.post(
                    endpoints["token"],
                    data=data,
                    headers=headers
                )
                
                if response.status_code != 200:
                    error_text = response.text
                    log.error(f"OAuth 2.0 token exchange failed: {response.status_code} {error_text}")
                    raise TorngitClientError(f"Token exchange failed: {response.status_code}", code=response.status_code)
                
                token_data = response.json()
                
                # Add expiration timestamp if expires_in is provided
                if "expires_in" in token_data:
                    from datetime import datetime, timedelta
                    expires_at = datetime.now() + timedelta(seconds=token_data["expires_in"])
                    token_data["expires_at"] = expires_at.isoformat()
                
                log.info("Successfully exchanged authorization code for OAuth 2.0 token")
                return token_data
                
        except (httpx.NetworkError, httpx.TimeoutException) as e:
            log.error(f"Network error during token exchange: {e}")
            raise TorngitServerUnreachableError("Failed to reach Bitbucket Server during token exchange")
        except Exception as e:
            log.error(f"Unexpected error during token exchange: {e}")
            raise TorngitClientError(f"Token exchange failed: {e}")

    async def get_commit(self, commit, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp3530560
        res = await self.api(
            "get",
            "{}/repos/{}/commits/{}".format(
                self.project, self.data["repo"]["name"], commit
            ),
            token=token,
        )

        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp2598928
        author = await self.api(
            "get", "/users", filter=res["author"]["emailAddress"], token=token
        )
        if not author["size"]:
            author = await self.api("get", "/users", filter=res["author"]["name"])
        author = author["values"][0] if author["size"] else {}

        return {
            "author": {
                "id": ("U{}".format(author.get("id"))) if author.get("id") else None,
                "username": author.get("name"),
                "email": res["author"]["emailAddress"],
                "name": res["author"]["name"],
            },
            "commitid": commit,
            "parents": [p["id"] for p in res["parents"]],
            "message": res["message"],
            "timestamp": datetime.fromtimestamp(
                int(str(res["authorTimestamp"])[:10])
            ).strftime("%Y-%m-%d %H:%M:%S"),
        }

    async def get_pull_request_commits(self, pullid, token=None, _in_loop=None):
        commits, start = [], 0
        while True:
            # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp2519392
            res = await self.api(
                "get",
                "{}/repos/{}/pull-requests/{}/commits".format(
                    self.project, self.data["repo"]["name"], pullid
                ),
                start=start,
                token=token,
            )
            if len(res["values"]) == 0:
                break
            commits.extend([c["id"] for c in res["values"]])
            if res["isLastPage"] or res.get("nextPageStart") is None:
                break
            else:
                start = res["nextPageStart"]

        # order is NEWEST...OLDEST
        return commits

    async def get_commit_diff(self, commit, context=None, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp3120016
        diff = await self.api(
            "get",
            "{}/repos/{}/commits/{}/diff".format(
                self.project, self.data["repo"]["name"], commit
            ),
            withComments=False,
            whitespace="ignore-all",
            contextLines=context or -1,
            token=None,
        )
        return self.diff_to_json(diff["diffs"])

    async def get_compare(
        self, base, head, context=None, with_commits=True, token=None
    ):
        # get diff
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp3370768
        diff = (
            await self.api(
                "get",
                "{}/repos/{}/commits/{}/diff".format(
                    self.project, self.data["repo"]["name"], head
                ),
                withComments=False,
                whitespace="ignore-all",
                contextLines=context or -1,
                since=base,
                token=token,
            )
        )["diffs"]

        # get commits
        commits, start = [], 0
        while with_commits:
            # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp3513104
            res = await self.api(
                "get",
                "{}/repos/{}/commits".format(self.project, self.data["repo"]["name"]),
                start=start,
                token=token,
                since=base,
                until=head,
            )
            #  listed [newest...oldest]
            commits.extend(
                [
                    {
                        "commitid": c["id"],
                        "message": c["message"],
                        "timestamp": c["authorTimestamp"],
                        "author": {
                            "name": c["author"]["name"],
                            "email": c["author"]["emailAddress"],
                        },
                    }
                    for c in res["values"]
                ]
            )
            if res["isLastPage"] or res.get("nextPageStart") is None:
                break
            else:
                start = res["nextPageStart"]

        return {"diff": self.diff_to_json(diff), "commits": commits[::-1]}

    async def post_webhook(self, name, url, events, secret, token=None):
        # https://docs.atlassian.com/bitbucket-server/rest/6.0.1/bitbucket-rest.html#idp325
        # https://confluence.atlassian.com/bitbucketserver066/event-payload-978197889.html
        res = await self.api(
            "post",
            "{}/repos/{}/webhooks".format(self.project, self.data["repo"]["name"]),
            body={"description": name, "active": True, "events": events, "url": url},
            json=True,
            token=token,
        )
        return res

    async def get_pull_request(self, pullid, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp2167824
        res = await self.api(
            "get",
            "{}/repos/{}/pull-requests/{}".format(
                self.project, self.data["repo"]["name"], pullid
            ),
            token=token,
        )
        # need to get all commits, shit.
        pull_commitids = await self.get_pull_request_commits(
            pullid, token=token, _in_loop=True
        )
        first_commit = (
            await self.api(
                "get",
                "{}/repos/{}/commits/{}".format(
                    self.project, self.data["repo"]["name"], pull_commitids[-1]
                ),
                token=token,
            )
        )["parents"][0]["id"]
        return {
            "title": res["title"],
            "state": {"OPEN": "open", "DECLINED": "close", "MERGED": "merged"}.get(
                res["state"]
            ),
            "id": str(pullid),
            "number": str(pullid),
            "base": {"branch": res["toRef"]["displayId"], "commitid": first_commit},
            "head": {
                "branch": res["fromRef"]["displayId"],
                "commitid": pull_commitids[0],
            },
        }

    async def list_top_level_files(self, ref, token=None):
        return await self.list_files(ref, dir_path="", token=None)

    async def list_files(self, ref, dir_path, token=None):
        page = None
        has_more = True
        files = []
        while has_more:
            # https://developer.atlassian.com/bitbucket/api/2/reference/resource/repositories/%7Busername%7D/%7Brepo_slug%7D/src#get
            kwargs = {}

            if page is not None:
                kwargs["page"] = page

            if ref not in [None, ""]:
                kwargs["at"] = ref

            results = await self.api(
                "get",
                "{}/repos/{}/files/{}".format(
                    self.project, self.data["repo"]["name"], dir_path
                ),
                **kwargs,
            )
            files.extend(results["values"])
            page = results["nextPageStart"]
            has_more = not results["isLastPage"]
        return [{"path": f, "type": "file"} for f in files]

    async def _fetch_page_of_repos(self, start, token):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp1847760
        res = await self.api("get", "/repos", start=start, token=token)

        repos = []
        for repo in res["values"]:
            ownerid = str(repo["project"]["id"])
            if repo["project"]["type"] == "PERSONAL":
                ownerid = "U" + str(repo["project"]["owner"]["id"])

            repos.append(
                {
                    "owner": {
                        "service_id": ownerid,
                        "username": repo["project"]["key"].lower().replace("~", ""),
                    },
                    "repo": {
                        "service_id": repo["id"],
                        "name": repo["slug"].lower(),
                        "language": None,
                        "private": (
                            not repo.get("public", repo.get("origin", {}).get("public"))
                        ),
                        "branch": "main",
                    },
                }
            )

        next_page_start = res.get("nextPageStart") if not res["isLastPage"] else None
        return (repos, next_page_start)

    async def list_repos(self, username=None, token=None):
        data, start = [], 0
        while True:
            repos, next_page_start = await self._fetch_page_of_repos(start, token)

            if len(repos) == 0 or next_page_start is None:
                break
            else:
                start = next_page_start

        return data

    async def list_repos_generator(self, username=None, token=None):
        """
        New version of list_repos() that should replace the old one after safely
        rolling out in the worker.
        """
        start = 0
        while True:
            repos, next_page_start = await self._fetch_page_of_repos(start, token)

            if len(repos) == 0:
                break

            yield repos

            if next_page_start is None:
                break
            else:
                start = next_page_start

    async def list_teams(self, token=None):
        data, start = [], 0
        while True:
            # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp2301216
            res = await self.api("get", "/projects", start=start, token=token)
            if len(res["values"]) == 0:
                break
            data.extend(
                [
                    {"id": row["id"], "username": row["key"], "name": row["name"]}
                    for row in res["values"]
                ]
            )
            if res["isLastPage"] or res.get("nextPageStart") is None:
                break
            else:
                start = res["nextPageStart"]

        return data

    async def get_commit_statuses(self, commit, _merge=None, token=None):
        # https://developer.atlassian.com/stash/docs/latest/how-tos/updating-build-status-for-commits.html
        start, data = 0, []
        while True:
            res = await self.api(
                "get",
                f"{self.service_url}/rest/build-status/1.0/commits/{commit}",
                start=start,
                token=token,
            )
            if len(res["values"]) == 0:
                break
            data.extend(
                [
                    {
                        "time": s["dateAdded"],
                        "state": s["state"],
                        "url": s["url"],
                        "description": s["description"],
                        "context": s["name"],
                    }
                    for s in res["values"]
                ]
            )
            if res["isLastPage"] or res.get("nextPageStart") is None:
                break
            else:
                start = res["nextPageStart"]

        return Status(data)

    async def set_commit_status(
        self,
        commit,
        status,
        context,
        description,
        url=None,
        merge_commit=None,
        token=None,
        coverage=None,
    ):
        # https://developer.atlassian.com/stash/docs/latest/how-tos/updating-build-status-for-commits.html
        assert status in ("pending", "success", "error", "failure"), "status not valid"
        res = await self.api(
            "post",
            f"{self.service_url}/rest/build-status/1.0/commits/{commit}",
            body={
                "state": {
                    "pending": "INPROGRESS",
                    "success": "SUCCESSFUL",
                    "error": "FAILED",
                    "failure": "FAILED",
                }.get(status),
                "key": context,
                "name": context,
                "url": url,
                "description": description,
            },
            token=token,
        )
        if merge_commit:
            await self.api(
                "post",
                f"{self.service_url}/rest/build-status/1.0/commits/{merge_commit[0]}",
                body={
                    "state": {
                        "pending": "INPROGRESS",
                        "success": "SUCCESSFUL",
                        "error": "FAILED",
                        "failure": "FAILED",
                    }.get(status),
                    "key": merge_commit[1],
                    "name": merge_commit[1],
                    "url": url,
                    "description": description,
                },
                token=token,
            )
        return {"id": res.get("id", "NO-ID") if res else "NO-ID"}

    async def post_comment(self, pullid, body, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp3165808
        res = await self.api(
            "post",
            "{}/repos/{}/pull-requests/{}/comments".format(
                self.project, self.data["repo"]["name"], pullid
            ),
            body={"text": body},
            token=token,
        )
        return {"id": "{id}:{version}".format(**res)}

    async def edit_comment(self, pullid, commentid, body, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp3184624
        commentid, version = commentid.split(":", 1)
        res = await self.api(
            "put",
            "{}/repos/{}/pull-requests/{}/comments/{}".format(
                self.project, self.data["repo"]["name"], pullid, commentid
            ),
            body={"text": body, "version": version},
            token=token,
        )
        return {"id": "{id}:{version}".format(**res)}

    async def delete_comment(self, issueid, commentid, token=None):
        # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp3189408
        commentid, version = commentid.split(":", 1)
        await self.api(
            "delete",
            "{}/repos/{}/pull-requests/{}/comments/{}".format(
                self.project, self.data["repo"]["name"], issueid, commentid
            ),
            version=version,
            token=token,
        )
        return True

    async def get_branches(self, token=None):
        branches, start = [], 0
        while True:
            # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp2243696
            res = await self.api(
                "get",
                "{}/repos/{}/branches".format(self.project, self.data["repo"]["name"]),
                start=start,
                token=token,
            )
            if len(res["values"]) == 0:
                break
            branches.extend(
                [
                    (b["displayId"].encode("utf-8", "replace"), b["latestCommit"])
                    for b in res["values"]
                ]
            )
            if res["isLastPage"] or res.get("nextPageStart") is None:
                break
            else:
                start = res["nextPageStart"]
        return branches

    async def find_pull_request(
        self, commit=None, branch=None, state="open", token=None
    ):
        start = 0
        state = {"open": "OPEN", "close": "DECLINED", "merged": "MERGED"}.get(
            state, "ALL"
        )
        if branch:
            while True:
                # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp2048560
                res = await self.api(
                    "get",
                    "{}/repos/{}/pull-requests".format(
                        self.project, self.data["repo"]["name"]
                    ),
                    state=state,
                    withAttributes=False,
                    withProperties=False,
                    start=start,
                    token=token,
                )
                if len(res["values"]) == 0:
                    break

                for pull in res["values"]:
                    if pull["fromRef"]["displayId"] == branch:
                        return pull["id"]

                if res["isLastPage"] or res.get("nextPageStart") is None:
                    break

                else:
                    start = res["nextPageStart"]

    async def get_pull_requests(self, state="open", token=None):
        pulls, start = [], 0
        state = {"open": "OPEN", "close": "DECLINED", "merged": "MERGED"}.get(
            state, "ALL"
        )
        while True:
            # https://developer.atlassian.com/static/rest/bitbucket-server/4.0.1/bitbucket-rest.html#idp2048560
            res = await self.api(
                "get",
                "{}/repos/{}/pull-requests".format(
                    self.project, self.data["repo"]["name"]
                ),
                state=state,
                withAttributes=False,
                withProperties=False,
                start=start,
                token=token,
            )
            if len(res["values"]) == 0:
                break
            pulls.extend([pull["id"] for pull in res["values"]])
            if res["isLastPage"] or res.get("nextPageStart") is None:
                break
            else:
                start = res["nextPageStart"]
        return pulls
