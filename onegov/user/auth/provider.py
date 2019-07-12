import kerberos
import os

from abc import ABCMeta, abstractmethod
from contextlib import contextmanager
from onegov.user import _, log
from onegov.user.models.user import User
from webob.exc import HTTPUnauthorized


AUTHENTICATION_PROVIDERS = {}


class ProviderMetadata(object):
    """ Holds provider-specific metadata. """

    def __init__(self, name, title):
        self.name = name
        self.title = title


class AuthenticationProvider(metaclass=ABCMeta):
    """ Base class and registry for third party authentication providers. """

    def __init_subclass__(cls, metadata, **kwargs):
        global AUTHENTICATION_PROVIDERS
        assert metadata.name not in AUTHENTICATION_PROVIDERS

        cls.metadata = metadata
        AUTHENTICATION_PROVIDERS[metadata.name] = cls

        super().__init_subclass__(**kwargs)

    @abstractmethod
    def authenticate_request(self, request):
        """ Authenticates the given request in one or many steps.

        Providers are expected to return one of the following values:

        * A valid user (if the authentication was successful)
        * None (if the authentication failed)
        * A webob response (to perform handshakes)

        This function is called whenever the authentication is initiated by
        the user. If the provider returns a webob response, it is returned
        as is by the calling view.

        Therefore, `authenticate_request` must take care to return responses
        in a way that eventually end up fulfilling the authentication. At the
        very least, providers should ensure that all parameters of the original
        request are kept when asking external services to call back.

        """

    def available_users(self, request):
        """ Returns a query limited to users which may be authenticated
        using the given provider.

        This should be used as a base for the identification, rather than
        building your own query, as inactive users and ones without the
        proper configuration are excluded.

        """
        return request.session.query(User)\
            .filter_by(active=True)\
            .filter(User['authentication_provider']['type'] == self.type)

    @classmethod
    def configure(cls, **kwargs):
        """ This function gets called with the per-provider configuration
        defined in onegov.yml. Authentication providers may optionally
        access these values.

        The return value is either a provider instance, or none if the
        provider is not available.

        """

        return cls()

    @property
    def user_fields(self):
        """ Optional fields required by the provider on the user. Should return
        something that is iterable (even if only one or no fields are used).

        See :class:`UserField`.
        """

        return ()


class UserField(object):
    """ Defines user-specific field.

    The following properties are required:

        * attr => the attribute name of the field ([a-z_]+)
        * name => the translatable name of the field
        * type => the type of the field (currently only 'string')
        * note => an optional text or callable

    If the note is callable, it receives the current request before the form is
    rendered. This gives the provider the ability to render something helpful
    (like the current user id in kerberos).

    """

    def __init__(self, attr, name, type='string', note=None):
        self.attr = attr
        self.name = name
        self.type = type
        self.note = note


class KerberosProvider(AuthenticationProvider, metadata=ProviderMetadata(
    name='kerberos', title=_("Kerberos (v5)")
)):
    """ Kerberos is a computer-network authentication protocol that works on
    the basis of tickets to allow nodes communicating over a non-secure network
    to prove their identity to one another in a secure manner.

    """

    def __init__(self, keytab, hostname, service):
        self.keytab = keytab
        self.hostname = hostname
        self.service = service
        self.principal = f'{self.service}@{self.self.hostname}'

    @property
    def user_fields(self):
        yield UserField('username', _("Kerberos username"), self.username)

    @classmethod
    def configure(cls, **cfg):
        keytab = cfg.get('keytab', None)
        hostname = cfg.get('hostname', None)
        service = cfg.get('service', None)

        if not keytab:
            return None

        if not hostname:
            return None

        if not service:
            return None

        provider = cls(keytab, hostname, service)

        with provider.context() as krb:
            try:
                krb.getServerPrincipalDetails(provider.principal)
            except krb.KrbError as e:
                log.warning(f"Kerberos config error: {e}")
            else:
                return provider

    @contextmanager
    def context(self):
        """ Runs the block inside the context manager with the keytab
        set to the provider's keytab.

        All functions that interact with kerberos must be run inside
        this context.

        For convenience, this context returns the kerberos module
        when invoked.

        """
        previous = os.environ.pop('KRB5_KTNAME', None)
        os.environ['KRB5_KTNAME'] = self.keytab

        yield kerberos

        if previous is not None:
            os.environ['KRB5_KTNAME'] = previous

    def authenticate_request(self, request):
        """ Authenticates the kerberos request.

        The kerberos handshake is as follows:

        1. An HTTPUnauthorized response (401) is returned, with the
           WWW-Authenticate header set to "Negotiate"

        2. The client sends a request with the Authorization header set
           to the kerberos ticket.

        """

        # extract the token
        token = request.headers.get('Authorization')
        token = token and ''.join(token.split()[1:]).strip()

        def with_header(response=None):
            negotiate = token and f'Negotiate {token}' or 'Negotiate'
            response.headers['WWW-Authenticate'] = negotiate

            return response

        def negotiate():
            return with_header(HTTPUnauthorized())

        # ask for a token
        if not token:
            return negotiate()

        # verify the token
        with self.context() as krb:

            # initialization step
            result, state = krb.authGSSServerInit(self.service)

            if result != krb.AUTH_GSS_COMPLETE:
                return negotiate()

            # challenge step
            result = krb.authGSSServerStep(state, token)

            if result != krb.AUTH_GSS_COMPLETE:
                return negotiate()

            # extract the final token
            token = krb.authGSSServerResponse(state)

            # include the token in the response
            request.after(with_header)

            # extract the user if possible
            username = krb.authGSSServerUserName(state)
            selector = User.authentication_provider['data']['username']

            return self.available_users().filter(selector == username).first()
