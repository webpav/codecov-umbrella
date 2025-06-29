from uuid import uuid4

import factory
from django.utils import timezone
from factory.django import DjangoModelFactory

from shared.django_apps.codecov_auth.models import (
    GITHUB_APP_INSTALLATION_DEFAULT_NAME,
    Account,
    AccountsUsers,
    GithubAppInstallation,
    InvoiceBilling,
    OktaSettings,
    OktaUser,
    OrganizationLevelToken,
    Owner,
    OwnerProfile,
    Plan,
    SentryUser,
    Session,
    StripeBilling,
    Tier,
    TokenTypeChoices,
    User,
    UserToken,
)
from shared.encryption.oauth import get_encryptor_from_configuration
from shared.plan.constants import PlanName, TierName, TrialStatus

encryptor = get_encryptor_from_configuration()


class UserFactory(DjangoModelFactory):
    class Meta:
        model = User

    email = factory.Faker("email")
    name = factory.Faker("name")
    terms_agreement = False
    terms_agreement_at = None
    customer_intent = "Business"


class OwnerFactory(DjangoModelFactory):
    class Meta:
        model = Owner
        exclude = ("unencrypted_oauth_token",)

    name = factory.Faker("name")
    email = factory.Faker("email")
    username = factory.Faker("user_name")
    service = "github"
    service_id = factory.Sequence(lambda n: f"{n}")
    updatestamp = factory.LazyFunction(timezone.now)
    plan_activated_users = []
    admins = []
    permission = []
    free = 0
    onboarding_completed = False
    unencrypted_oauth_token = factory.LazyFunction(lambda: uuid4().hex)
    cache = {"stats": {"repos": 1, "members": 2, "users": 1}}
    oauth_token = factory.LazyAttribute(
        lambda o: encryptor.encode(o.unencrypted_oauth_token).decode()
    )
    student = False
    user = factory.SubFactory(UserFactory)
    trial_status = TrialStatus.NOT_STARTED.value


class SentryUserFactory(DjangoModelFactory):
    class Meta:
        model = SentryUser

    email = factory.Faker("email")
    name = factory.Faker("name")
    sentry_id = factory.LazyFunction(lambda: uuid4().hex)
    access_token = factory.LazyFunction(lambda: uuid4().hex)
    refresh_token = factory.LazyFunction(lambda: uuid4().hex)
    user = factory.SubFactory(UserFactory)


class OktaUserFactory(DjangoModelFactory):
    class Meta:
        model = OktaUser

    email = factory.Faker("email")
    name = factory.Faker("name")
    okta_id = factory.LazyFunction(lambda: uuid4().hex)
    access_token = factory.LazyFunction(lambda: uuid4().hex)
    user = factory.SubFactory(UserFactory)


class OwnerProfileFactory(DjangoModelFactory):
    class Meta:
        model = OwnerProfile

    owner = factory.SubFactory(OwnerFactory)
    default_org = factory.SubFactory(OwnerFactory)


class SessionFactory(DjangoModelFactory):
    class Meta:
        model = Session

    owner = factory.SubFactory(OwnerFactory)
    lastseen = timezone.now()
    type = Session.SessionType.API.value
    token = factory.Faker("uuid4")


class OrganizationLevelTokenFactory(DjangoModelFactory):
    class Meta:
        model = OrganizationLevelToken

    owner = factory.SubFactory(OwnerFactory)
    token = uuid4()
    token_type = TokenTypeChoices.UPLOAD


class GetAdminProviderAdapter:
    def __init__(self, result=False):
        self.result = result
        self.last_call_args = None

    async def get_is_admin(self, user):
        self.last_call_args = user
        return self.result


class UserTokenFactory(DjangoModelFactory):
    class Meta:
        model = UserToken

    owner = factory.SubFactory(OwnerFactory)
    token = factory.LazyAttribute(lambda _: uuid4())


class AccountFactory(DjangoModelFactory):
    class Meta:
        model = Account

    name = factory.Faker("name")


class AccountsUsersFactory(DjangoModelFactory):
    class Meta:
        model = AccountsUsers

    user = factory.SubFactory(UserFactory)
    account = factory.SubFactory(Account)


class OktaSettingsFactory(DjangoModelFactory):
    class Meta:
        model = OktaSettings

    account = factory.SubFactory(Account)
    client_id = factory.Faker("pyint")
    client_secret = factory.Faker("pyint")
    url = factory.Faker("pystr")


class StripeBillingFactory(DjangoModelFactory):
    class Meta:
        model = StripeBilling

    account = factory.SubFactory(Account)
    customer_id = factory.Faker("pyint")


class InvoiceBillingFactory(DjangoModelFactory):
    class Meta:
        model = InvoiceBilling

    account = factory.SubFactory(Account)


class TierFactory(DjangoModelFactory):
    class Meta:
        model = Tier

    tier_name = TierName.BASIC.value
    bundle_analysis = False
    test_analytics = False
    flaky_test_detection = False
    project_coverage = False
    private_repo_support = False


class PlanFactory(DjangoModelFactory):
    class Meta:
        model = Plan

    tier = factory.SubFactory(TierFactory)
    base_unit_price = 0
    benefits = factory.LazyFunction(lambda: ["Benefit 1", "Benefit 2", "Benefit 3"])
    billing_rate = None
    is_active = True
    marketing_name = factory.Faker("catch_phrase")
    max_seats = 1
    monthly_uploads_limit = None
    name = PlanName.BASIC_PLAN_NAME.value
    paid_plan = False
    stripe_id = None


class GithubAppInstallationFactory(DjangoModelFactory):
    class Meta:
        model = GithubAppInstallation

    installation_id = factory.Sequence(lambda n: n + 1000)
    name = GITHUB_APP_INSTALLATION_DEFAULT_NAME
    repository_service_ids = None
    app_id = factory.Sequence(lambda n: n + 100)
    pem_path = None
    owner = factory.SubFactory(OwnerFactory)
