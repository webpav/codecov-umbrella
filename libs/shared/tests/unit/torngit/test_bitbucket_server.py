from urllib.parse import parse_qsl, urlparse

import pytest
from oauthlib import oauth1

from shared.config import MissingConfigException
from shared.torngit.bitbucket_server import BitbucketServer
from shared.torngit.exceptions import (
    TorngitClientGeneralError,
    TorngitObjectNotFoundError,
)
from shared.utils.test_utils import mock_config_helper

MOCK_BASE = "https://bitbucketserver.codecov.dev"
MOCK_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDCFqq2ygFh9UQU/6PoDJ6L9e4ovLPCHtlBt7vzDwyfwr3XGxln
0VbfycVLc6unJDVEGZ/PsFEuS9j1QmBTTEgvCLR6RGpfzmVuMO8wGVEO52pH73h9
rviojaheX/u3ZqaA0di9RKy8e3L+T0ka3QYgDx5wiOIUu1wGXCs6PhrtEwICBAEC
gYBu9jsi0eVROozSz5dmcZxUAzv7USiUcYrxX007SUpm0zzUY+kPpWLeWWEPaddF
VONCp//0XU8hNhoh0gedw7ZgUTG6jYVOdGlaV95LhgY6yXaQGoKSQNNTY+ZZVT61
zvHOlPynt3GZcaRJOlgf+3hBF5MCRoWKf+lDA5KiWkqOYQJBAMQp0HNVeTqz+E0O
6E0neqQDQb95thFmmCI7Kgg4PvkS5mz7iAbZa5pab3VuyfmvnVvYLWejOwuYSp0U
9N8QvUsCQQD9StWHaVNM4Lf5zJnB1+lJPTXQsmsuzWvF3HmBkMHYWdy84N/TdCZX
Cxve1LR37lM/Vijer0K77wAx2RAN/ppZAkB8+GwSh5+mxZKydyPaPN29p6nC6aLx
3DV2dpzmhD0ZDwmuk8GN+qc0YRNOzzJ/2UbHH9L/lvGqui8I6WLOi8nDAkEA9CYq
ewfdZ9LcytGz7QwPEeWVhvpm0HQV9moetFWVolYecqBP4QzNyokVnpeUOqhIQAwe
Z0FJEQ9VWsG+Df0noQJBALFjUUZEtv4x31gMlV24oiSWHxIRX4fEND/6LpjleDZ5
C/tY+lZIEO1Gg/FxSMB+hwwhwfSuE3WohZfEcSy+R48=
-----END RSA PRIVATE KEY-----"""


@pytest.fixture
def valid_handler(mock_configuration, mocker):
    mock_configuration._params["bitbucket_server"] = {"url": MOCK_BASE}
    mock_config_helper(
        mocker,
        configs={
            "bitbucket_server.url": MOCK_BASE,
            "bitbucket_server.private_key": MOCK_PRIVATE_KEY,
        },
    )
    return BitbucketServer(
        repo={"name": "example-python"},
        owner={
            "username": "ThiagoCodecov",
            "service_id": "6ef29b63-aaaa-aaaa-aaaa-aaaa03f5cd49",
        },
        oauth_consumer_token={
            "key": "arubajamaicaohiwan",
            "secret": "natakeyoubermudabahamacomeonpret",
        },
        token={"secret": "KeyLargoMontegobabywhydontwego", "key": "waydowntokokomo"},
    )


class TestBitbucketServer:
    def test_service_url(self, mock_configuration):
        mock_configuration._params["bitbucket_server"] = {
            "url": "https://bitbucketserver.codecov.dev"
        }
        bbs = BitbucketServer()
        assert bbs.service_url == "https://bitbucketserver.codecov.dev"
        assert (
            BitbucketServer.get_service_url() == "https://bitbucketserver.codecov.dev"
        )

    @pytest.mark.asyncio
    @pytest.mark.respx(base_url=MOCK_BASE)
    async def test_api_uses_rsa_sha1_signature(self, valid_handler, respx_mock):
        respx_mock.get("/rest/api/1.0/random_url").respond(status_code=200, json={})

        await valid_handler.api("GET", "/random_url")

        request = respx_mock.calls.last.request
        query = dict(parse_qsl(urlparse(str(request.url)).query))
        assert query["oauth_signature_method"] == "RSA-SHA1"

    def test_oauth_client_uses_configured_rsa_key(self, valid_handler, mocker):
        oauth_client = mocker.patch("shared.torngit.bitbucket_server.oauth1.Client")

        valid_handler._oauth_client(valid_handler.token)

        oauth_client.assert_called_once()
        kwargs = oauth_client.call_args.kwargs
        assert kwargs["signature_method"] == oauth1.SIGNATURE_RSA
        assert kwargs["rsa_key"] == MOCK_PRIVATE_KEY

    def test_oauth_client_raises_without_rsa_key(self, mocker):
        mock_config_helper(mocker, configs={"bitbucket_server.url": MOCK_BASE})
        handler = BitbucketServer(
            oauth_consumer_token={"key": "consumer-key", "secret": ""},
            token={"secret": "token-secret", "key": "token-key"},
        )

        with pytest.raises(MissingConfigException):
            handler._oauth_client(handler.token)

    def test_oauth_client_supports_legacy_hmac_auth(self, valid_handler, mocker):
        mock_config_helper(
            mocker,
            configs={
                "bitbucket_server.url": MOCK_BASE,
                "bitbucket_server.auth_method": "oauth1_hmac",
            },
        )
        oauth_client = mocker.patch("shared.torngit.bitbucket_server.oauth1.Client")

        valid_handler._oauth_client(valid_handler.token)

        oauth_client.assert_called_once()
        kwargs = oauth_client.call_args.kwargs
        assert "signature_method" not in kwargs
        assert "rsa_key" not in kwargs
        assert kwargs["client_secret"] == "natakeyoubermudabahamacomeonpret"

    @pytest.mark.asyncio
    @pytest.mark.respx(base_url=MOCK_BASE)
    async def test_api_parses_oauth_token_response(self, valid_handler, respx_mock):
        respx_mock.post("/plugins/servlet/oauth/request-token").respond(
            status_code=200,
            content=b"oauth_token=SomeToken&oauth_token_secret=SomeTokenSecret",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        result = await valid_handler.api(
            "POST", f"{MOCK_BASE}/plugins/servlet/oauth/request-token"
        )

        assert result == {
            "oauth_token": "SomeToken",
            "oauth_token_secret": "SomeTokenSecret",
        }

    @pytest.mark.asyncio
    @pytest.mark.respx(base_url=MOCK_BASE)
    async def test_fetch_uses_proper_endpoint(self, valid_handler, respx_mock):
        respx_mock.post(
            "/rest/api/1.0/projects/THIAGOCODECOV/repos/example-python/pull-requests/pullid/comments"
        ).respond(status_code=201, json={"id": 198, "version": 3})

        res = await valid_handler.post_comment("pullid", "body")
        assert res == {"id": "198:3"}

    @pytest.mark.asyncio
    async def test_api_client_not_found(self, valid_handler, respx_mock):
        respx_mock.get("/rest/api/1.0/random_url").respond(status_code=404, json={})

        with pytest.raises(TorngitClientGeneralError):
            await valid_handler.api("GET", "/random_url")

    @pytest.mark.asyncio
    async def test_get_repo_languages(self):
        expected_result = ["javascript"]
        handler = BitbucketServer(
            repo={"name": "example-python", "private": True},
        )
        res = await handler.get_repo_languages(None, "JavaScript")
        assert res == expected_result

    @pytest.mark.asyncio
    async def test_get_repo_no_languages(self):
        expected_result = []
        handler = BitbucketServer(
            repo={"name": "example-python", "private": True},
        )
        res = await handler.get_repo_languages(None, None)
        assert res == expected_result

    @pytest.mark.asyncio
    @pytest.mark.respx(base_url=MOCK_BASE)
    async def test_get_source_object_not_found(self, valid_handler, respx_mock):
        respx_mock.get(
            "/rest/api/1.0/projects/THIAGOCODECOV/repos/example-python/browse/some/path/"
        ).respond(status_code=404, json={})

        with pytest.raises(TorngitObjectNotFoundError):
            await valid_handler.get_source("some/path/", "commitsha")
