import json
from unittest.mock import MagicMock, PropertyMock, patch

from sqlalchemy.orm import Session

from database.models import (
    Account,
    Branch,
    Commit,
    CommitNotification,
    Owner,
    Pull,
    Repository,
)
from database.models.core import (
    AccountsUsers,
)
from database.tests.factories import (
    BranchFactory,
    CommitFactory,
    CommitNotificationFactory,
    CompareCommitFactory,
    OwnerFactory,
    PullFactory,
    RepositoryFactory,
)
from database.tests.factories.core import GithubAppInstallationFactory, UserFactory
from shared.plan.constants import DEFAULT_FREE_PLAN
from shared.storage.exceptions import FileNotInStorageError


class TestReprModels:
    def test_owner_repr(self, dbsession):
        simple_owner = Owner()
        assert "Owner<None@service<None>>" == repr(simple_owner)
        factoried_owner = OwnerFactory.create(service="github")
        assert "Owner<None@service<github>>" == repr(factoried_owner)
        dbsession.add(factoried_owner)
        dbsession.flush()
        dbsession.refresh(factoried_owner)
        assert f"Owner<{factoried_owner.ownerid}@service<github>>" == repr(
            factoried_owner
        )

    def test_repo_repr(self, dbsession):
        simple_repo = Repository()
        assert "Repo<None>" == repr(simple_repo)
        factoried_repo = RepositoryFactory.create()
        assert "Repo<None>" == repr(factoried_repo)
        dbsession.add(factoried_repo)
        dbsession.flush()
        dbsession.refresh(factoried_repo)
        assert f"Repo<{factoried_repo.repoid}>" == repr(factoried_repo)

    def test_commit_repr(self, dbsession):
        simple_commit = Commit()
        assert "Commit<None@repo<None>>" == repr(simple_commit)
        factoried_commit = CommitFactory.create(
            commitid="327993f5d81eda4bac19ea6090fe68c8eb313066"
        )
        assert "Commit<327993f5d81eda4bac19ea6090fe68c8eb313066@repo<None>>" == repr(
            factoried_commit
        )
        dbsession.add(factoried_commit)
        dbsession.flush()
        dbsession.refresh(factoried_commit)
        assert (
            f"Commit<327993f5d81eda4bac19ea6090fe68c8eb313066@repo<{factoried_commit.repoid}>>"
            == repr(factoried_commit)
        )

    def test_branch_repr(self, dbsession):
        simple_branch = Branch()
        assert "Branch<None@repo<None>>" == repr(simple_branch)
        factoried_branch = BranchFactory.create(branch="thisoakbranch")
        assert "Branch<thisoakbranch@repo<None>>" == repr(factoried_branch)
        dbsession.add(factoried_branch)
        dbsession.flush()
        dbsession.refresh(factoried_branch)
        assert f"Branch<thisoakbranch@repo<{factoried_branch.repoid}>>" == repr(
            factoried_branch
        )

    def test_pull_repr(self, dbsession):
        simple_pull = Pull()
        assert "Pull<None@repo<None>>" == repr(simple_pull)
        factoried_pull = PullFactory.create()
        assert f"Pull<{factoried_pull.pullid}@repo<None>>" == repr(factoried_pull)
        dbsession.add(factoried_pull)
        dbsession.flush()
        dbsession.refresh(factoried_pull)
        assert f"Pull<{factoried_pull.pullid}@repo<{factoried_pull.repoid}>>" == repr(
            factoried_pull
        )

    def test_notification_repr(self, dbsession):
        simple_notification = CommitNotification()
        assert "Notification<None@commit<None>>" == repr(simple_notification)
        factoried_notification = CommitNotificationFactory.create()
        assert (
            f"Notification<{factoried_notification.notification_type}@commit<{factoried_notification.commit_id}>>"
            == repr(factoried_notification)
        )
        dbsession.add(factoried_notification)
        dbsession.flush()
        dbsession.refresh(factoried_notification)
        assert (
            f"Notification<{factoried_notification.notification_type}@commit<{factoried_notification.commit_id}>>"
            == repr(factoried_notification)
        )

    def test_commit_compare_repr(self, dbsession):
        compare_commit = CompareCommitFactory()
        assert "CompareCommit<None...None>" == repr(compare_commit)

    def test_commit_notified(self, dbsession):
        commit = CommitFactory.create()
        dbsession.add(commit)
        dbsession.flush()
        assert commit.notified is None
        commit.notified = True
        dbsession.flush()
        dbsession.refresh(commit)
        assert commit.notified is True


class TestPullModel:
    def test_updatestamp_update(self, dbsession):
        factoried_pull = PullFactory.create(updatestamp=None)
        assert factoried_pull.updatestamp is None
        dbsession.add(factoried_pull)
        dbsession.flush()
        assert factoried_pull.updatestamp is not None
        val = factoried_pull.updatestamp
        factoried_pull.title = "Super Mario Bros"
        dbsession.flush()
        assert factoried_pull.updatestamp is not None
        assert factoried_pull.updatestamp > val


class TestOwnerModel:
    def test_upload_token_required_for_public_repos(self, dbsession):
        # Create an owner with upload_token_required_for_public_repos specified
        tokens_required_owner = Owner(
            name="Token Owner",
            email="token_owner@example.com",
            username="tokenuser",
            upload_token_required_for_public_repos=True,
            service="github",
            service_id="abc",
        )
        dbsession.add(tokens_required_owner)
        dbsession.commit()

        # Refresh from the database to verify persistence
        dbsession.refresh(tokens_required_owner)
        assert tokens_required_owner.upload_token_required_for_public_repos is True

        # Update other field, upload_token_required_for_public_repos is unchanged
        assert tokens_required_owner.onboarding_completed is False
        tokens_required_owner.onboarding_completed = True
        dbsession.commit()
        dbsession.refresh(tokens_required_owner)
        assert tokens_required_owner.onboarding_completed is True
        assert tokens_required_owner.upload_token_required_for_public_repos is True

        # Create an owner without upload_token_required_for_public_repos specified
        tokens_not_required_owner = Owner(
            name="Tokenless Owner",
            email="tokenless_owner@example.com",
            username="tokenlessuser",
            service="github",
            service_id="defg",
        )
        dbsession.add(tokens_not_required_owner)
        dbsession.commit()
        dbsession.refresh(tokens_not_required_owner)
        assert tokens_not_required_owner.upload_token_required_for_public_repos is False

        # Update other field, upload_token_required_for_public_repos is unchanged
        assert tokens_not_required_owner.onboarding_completed is False
        tokens_not_required_owner.onboarding_completed = True
        dbsession.commit()
        dbsession.refresh(tokens_not_required_owner)
        assert tokens_not_required_owner.onboarding_completed is True
        assert tokens_not_required_owner.upload_token_required_for_public_repos is False

    def test_root_organization(self, dbsession):
        gitlab_root_group = OwnerFactory.create(
            username="root_group",
            service="gitlab",
            plan="users-pr-inappm",
        )
        dbsession.add(gitlab_root_group)
        gitlab_middle_group = OwnerFactory.create(
            username="mid_group",
            service="gitlab",
            parent_service_id=gitlab_root_group.service_id,
            root_parent_service_id=None,
        )
        dbsession.add(gitlab_middle_group)
        gitlab_subgroup = OwnerFactory.create(
            username="subgroup",
            service="gitlab",
            parent_service_id=gitlab_middle_group.service_id,
            root_parent_service_id=None,
        )
        dbsession.add(gitlab_subgroup)
        github_org = OwnerFactory.create(
            username="gh",
            service="github",
        )
        dbsession.add(github_org)
        dbsession.flush()

        assert gitlab_root_group.root_organization is None
        assert gitlab_root_group.root_parent_service_id is None

        assert gitlab_middle_group.root_organization == gitlab_root_group
        assert (
            gitlab_middle_group.root_parent_service_id == gitlab_root_group.service_id
        )

        assert gitlab_subgroup.root_organization == gitlab_root_group
        assert gitlab_subgroup.root_parent_service_id == gitlab_root_group.service_id

        assert github_org.root_organization is None
        assert github_org.root_parent_service_id is None


class TestAccountModels:
    def test_create_account(self, dbsession):
        account = Account(
            name="test_name",
        )
        dbsession.add(account)
        dbsession.commit()
        dbsession.refresh(account)
        assert account.name == "test_name"
        assert account.is_active is True
        assert account.plan == DEFAULT_FREE_PLAN
        assert account.plan_seat_count == 1
        assert account.free_seat_count == 0
        assert account.plan_auto_activate is True
        assert account.is_delinquent is False
        assert account.users == []
        assert account.organizations == []

    def test_account_fks(self, dbsession):
        user = UserFactory()
        owner_person = OwnerFactory()
        owner_org = OwnerFactory()
        account = Account(
            name="test_name",
        )
        dbsession.add_all([user, owner_person, owner_org, account])
        dbsession.commit()

        # this is the evaluation from shared that was breaking
        assert owner_org.account is None
        has_account = owner_org.account is not None
        assert has_account is False

        owner_person.user = user
        account.users.append(user)
        account.organizations.append(owner_org)
        dbsession.add_all([owner_person, account])
        dbsession.commit()

        dbsession.refresh(user)
        dbsession.refresh(owner_person)
        dbsession.refresh(owner_org)
        dbsession.refresh(account)

        assert user.accounts == [account]
        assert owner_person.account is None
        assert owner_org.account == account
        assert account.users == [user]
        assert account.organizations == [owner_org]
        # this is the evaluation from shared that was breaking
        has_account = owner_org.account is not None
        assert has_account is True

        through_table_obj = dbsession.query(AccountsUsers).first()
        assert through_table_obj.user_id == user.id
        assert through_table_obj.account_id == account.id


class TestCommitModel:
    sample_report = {
        "files": {
            "different/test_file.py": [
                2,
                [0, 10, 8, 2, 0, "80.00000", 0, 0, 0, 0, 0, 0, 0],
                [[0, 10, 8, 2, 0, "80.00000", 0, 0, 0, 0, 0, 0, 0]],
                [0, 2, 1, 1, 0, "50.00000", 0, 0, 0, 0, 0, 0, 0],
            ],
        },
        "sessions": {
            "0": {
                "N": None,
                "a": "v4/raw/2019-01-10/4434BC2A2EC4FCA57F77B473D83F928C/abf6d4df662c47e32460020ab14abf9303581429/9ccc55a1-8b41-4bb1-a946-ee7a33a7fb56.txt",
                "c": None,
                "d": 1547084427,
                "e": None,
                "f": ["unittests"],
                "j": None,
                "n": None,
                "p": None,
                "t": [3, 20, 17, 3, 0, "85.00000", 0, 0, 0, 0, 0, 0, 0],
                "": None,
            }
        },
    }

    @patch("database.utils.ArchiveService")
    def test_get_report_from_db(self, mock_archive, dbsession):
        commit = CommitFactory()
        mock_read_file = MagicMock()
        mock_archive.return_value.read_file = mock_read_file
        commit._report_json = self.sample_report
        dbsession.add(commit)
        dbsession.flush()

        fetched = dbsession.query(Commit).get(commit.id_)
        assert fetched.report_json == self.sample_report
        mock_archive.assert_not_called()
        mock_read_file.assert_not_called()

    @patch("database.utils.ArchiveService")
    def test_get_report_from_storage(self, mock_archive, dbsession):
        commit = CommitFactory()
        storage_path = "https://storage/path/report.json"
        mock_read_file = MagicMock(return_value=json.dumps(self.sample_report))
        mock_archive.return_value.read_file = mock_read_file
        commit._report_json = None
        commit._report_json_storage_path = storage_path
        dbsession.add(commit)
        dbsession.flush()

        fetched = dbsession.query(Commit).get(commit.id_)
        assert fetched.report_json == self.sample_report
        mock_archive.assert_called()
        mock_read_file.assert_called_with(storage_path)
        # Calls it again to test caching
        assert fetched.report_json == self.sample_report
        assert mock_archive.call_count == 1
        assert mock_read_file.call_count == 1
        # This one to help us understand caching across different instances
        # different instances if they are the same
        assert commit.report_json == self.sample_report
        assert mock_archive.call_count == 1
        assert mock_read_file.call_count == 1
        # Let's see for objects with different IDs
        diff_commit = CommitFactory()
        storage_path = "https://storage/path/files_array.json"
        diff_commit._report_json = None
        diff_commit._report_json_storage_path = storage_path
        dbsession.add(diff_commit)
        dbsession.flush()
        assert diff_commit.report_json == self.sample_report
        assert mock_archive.call_count == 2
        assert mock_read_file.call_count == 2

    @patch("database.utils.ArchiveService")
    def test_get_report_from_storage_file_not_found(
        self, mock_archive, dbsession, mocker
    ):
        mocker.patch(
            "database.utils.ArchiveField.read_timeout",
            new_callable=PropertyMock,
            return_value=0.1,
        )
        commit = CommitFactory()
        storage_path = "https://storage/path/files_array.json"

        def side_effect(*args, **kwargs):
            raise FileNotInStorageError()

        mock_read_file = MagicMock(side_effect=side_effect)
        mock_archive.return_value.read_file = mock_read_file
        commit._report_json = None
        commit._report_json_storage_path = storage_path
        dbsession.add(commit)
        dbsession.flush()

        fetched = dbsession.query(Commit).get(commit.id_)
        assert fetched._report_json_storage_path == storage_path
        assert fetched.report_json == {}
        mock_archive.assert_called()
        mock_read_file.assert_called_with(storage_path)


class TestGithubAppInstallationModel:
    def test_covers_all_repos(self, dbsession: Session):
        owner = OwnerFactory.create()
        other_owner = OwnerFactory.create()
        repo1 = RepositoryFactory.create(owner=owner)
        repo2 = RepositoryFactory.create(owner=owner)
        repo3 = RepositoryFactory.create(owner=owner)
        other_repo_different_owner = RepositoryFactory.create(owner=other_owner)
        installation_obj = GithubAppInstallationFactory(
            owner=owner,
            installation_id=100,
        )
        dbsession.add_all([owner, other_owner, repo1, repo2, repo3, installation_obj])
        dbsession.flush()
        assert installation_obj.covers_all_repos() == True
        assert installation_obj.is_repo_covered_by_integration(repo1) == True
        assert other_repo_different_owner.ownerid != repo1.ownerid
        assert (
            installation_obj.is_repo_covered_by_integration(other_repo_different_owner)
            == False
        )
        assert owner.github_app_installations == [installation_obj]
        assert installation_obj.repository_queryset(dbsession).count() == 3
        assert set(installation_obj.repository_queryset(dbsession).all()) == {
            repo1,
            repo2,
            repo3,
        }

    def test_covers_some_repos(self, dbsession: Session):
        owner = OwnerFactory()
        repo = RepositoryFactory(owner=owner)
        same_owner_other_repo = RepositoryFactory(owner=owner)
        other_repo_different_owner = RepositoryFactory()
        installation_obj = GithubAppInstallationFactory(
            owner=owner,
            repository_service_ids=[repo.service_id],
            installation_id=100,
        )
        dbsession.add_all(
            [
                owner,
                repo,
                same_owner_other_repo,
                other_repo_different_owner,
                installation_obj,
            ]
        )
        dbsession.flush()
        assert installation_obj.covers_all_repos() == False
        assert installation_obj.is_repo_covered_by_integration(repo) == True
        assert (
            installation_obj.is_repo_covered_by_integration(other_repo_different_owner)
            == False
        )
        assert (
            installation_obj.is_repo_covered_by_integration(same_owner_other_repo)
            == False
        )
        assert owner.github_app_installations == [installation_obj]
        assert installation_obj.repository_queryset(dbsession).count() == 1
        assert list(installation_obj.repository_queryset(dbsession).all()) == [repo]

    def test_is_configured(self, dbsession: Session):
        owner = OwnerFactory()
        installation_obj_default = GithubAppInstallationFactory(
            owner=owner,
            installation_id=100,
        )
        installation_obj_configured = GithubAppInstallationFactory(
            owner=owner,
            name="my_installation",
            installation_id=100,
            app_id=10,
            pem_path="some_path",
        )
        installation_obj_not_configured = GithubAppInstallationFactory(
            owner=owner,
            installation_id=100,
            name="my_installation",
        )
        dbsession.add_all(
            [
                installation_obj_default,
                installation_obj_configured,
                installation_obj_not_configured,
            ]
        )
        assert installation_obj_default.is_configured() == True
        assert installation_obj_configured.is_configured() == True
        assert installation_obj_not_configured.is_configured() == False
