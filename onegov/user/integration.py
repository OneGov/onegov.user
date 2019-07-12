from morepath import App
from onegov.core.security import Public
from onegov.user.auth.provider import AUTHENTICATION_PROVIDERS
from onegov.user.auth.provider import AuthenticationProvider
from onegov.user.models.user import User
from webob.exc import HTTPForbidden
from webob.response import Response


class UserApp(App):
    """ Provides user integration.

    Historically it was not necessary to use this app for user integration,
    and most features are still possible without it. However, third-party
    authentication providers only work if the UserApp is integrated.

    The following configuration options are accepted:

    :authentication_providers:

        A dictionary of provider-specific configuration settings, see
        :mod:`onegov.user.auth.provider` for more information.

    """

    @property
    def providers(self):
        """ Returns a tuple of availabe providers. """

        return getattr(self, 'available_providers', ())

    def configure_authentication_providers(self, **cfg):

        available = AUTHENTICATION_PROVIDERS.values()
        available = (cls.configure(**cfg) for cls in available)
        available = (obj for obj in available if obj is not None)

        self.available_providers = tuple(available)


@UserApp.path(
    model=AuthenticationProvider,
    path='/authentication-providers/{name}')
def authentication_provider(app, name):
    return next((p for p in app.providers if p.metadata.name == name), None)


@UserApp.view(
    model=AuthenticationProvider,
    permission=Public)
def handle_authentication(self, request):
    response = self.handle_authentication(request)

    # the provider returned its own response
    if isinstance(response, Response):
        return response

    # the provider failed to authenticate
    if response is None:
        return HTTPForbidden()

    # the provider found a user
    if isinstance(response, User):
        raise NotImplementedError()

    # the provider returned something illegal
    raise RuntimeError(
        f"Invalid response from {self.metadata.name}: {response}")
