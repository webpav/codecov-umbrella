import logging
from collections.abc import Coroutine
from typing import Any

from codecov.commands.base import BaseInteractor
from core.models import Commit
from services.repo_providers import RepoProviderService

log = logging.getLogger(__name__)


class GetFileContentInteractor(BaseInteractor):
    async def get_file_from_service(self, commit: Commit, path: str) -> str | None:
        try:
            repository_service = await RepoProviderService().async_get_adapter(
                owner=self.current_owner,
                repo=commit.repository,
                should_use_sentry_app=self.should_use_sentry_app,
            )
            content = await repository_service.get_source(path, commit.commitid)

            # When a file received from GH that is larger than 1MB the result will be
            # pre-decoded and of string type; no need to decode again in that case
            if isinstance(content.get("content"), str):
                return content.get("content")
            return content.get("content").decode("utf-8")
        # TODO raise this to the API so we can handle it.
        except Exception as e:
            log.warning(
                "GetFileContentInteractor - exception raised",
                extra={
                    "commitid": commit.commitid,
                    "path": path,
                    "error_name": type(e).__name__,
                    "error_message": str(e),
                },
            )
            return None

    def execute(self, commit: Commit, path: str) -> Coroutine[Any, Any, str | None]:
        return self.get_file_from_service(commit, path)
