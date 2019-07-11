import kerberos
import os

from abc import ABCMeta, abstractmethod
from contextlib import contextmanager
from onegov.user import _, log
from onegov.user.models.user import User


AUTHENTICATION_PROVIDERS = {}


class AuthenticationProvider(metaclass=ABCMeta):
    """ Base class and registry for third party authentication providers. """

    def __init_subclass__(cls, type, **kwargs):
        global AUTHENTICATION_PROVIDERS
        assert type not in AUTHENTICATION_PROVIDERS
        assert hasattr(cls, 'title')

        cls.type = type

        AUTHENTICATION_PROVIDERS[type] = cls

        super().__init_subclass__(**kwargs)

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

    @abstractmethod
    def identify(self, request):
        """ Returns the user model identified by this request or None. """

    @property
    @abstractmethod
    def title(self):
        """ Defines the translatable title of the provider. """

    @property
    @abstractmethod
    def configuration(self):
        """ A list of configuration attributes required from onegov.yml.

        Those attributes are automatically loaded from the app configuration
        and made available on the instance itself as properties.

        """

    @property
    def user_fields(self):
        """ Optional fields required by the provider on the user. """


class UserData(object):
    """ Holds the user-specific fields of a provider. """

    def __init__(self, fields):
        self.fields = fields


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


class KerberosProvider(AuthenticationProvider, type='kerberos'):

    title = _("Kerberos (v5)")

    def __init__(self, keytab, hostname, service):
        self.keytab = keytab
        self.hostname = hostname
        self.service = service
        self.principal = f'{self.service}@{self.self.hostname}'

    @property
    def user_data(self):
        return UserData(tuple(self.user_fields))

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

    def token(self, request):
        """ Gets the token from the given request, or None. """
        auth = request.headers.get('Authorization')
        return auth and ''.join(auth.split()[1:]).strip()

    def include_header(self, request, token=None):
        """ Adds the 'WWW-Authenticate' header, with or without token. """

        content = token and f'Negotiate {token}' or 'Negotiate'

        @request.after
        def include(response):
            response.headers['WWW-Authenticate'] = content

    def username(self, request):
        """ Returns the username, if authenticated, or None.

        Causes the response to include the kerberos token if successful.

        """
        token = self.token(request)

        def with_header(result):
            content = token and f'Negotiate {token}' or 'Negotiate'

            @request.after
            def include(response):
                response.headers['WWW-Authenticate'] = content

            return result

        if not token:
            return with_header(None)

        with self.context() as krb:

            # initialization step
            try:
                result, state = krb.authGSSServerInit(self.service)
            except krb.GSSError as e:
                log.debug(f"Kerberos init error: {e}")
                return with_header(None)
            if result != krb.AUTH_GSS_COMPLETE:
                log.debug(f"Kerberos init error: {result}")
                return with_header(None)

            # challenge step
            try:
                result = krb.authGSSServerStep(state, token)
            except krb.GSSError as e:
                log.debug(f"Kerberos challenge error: {e}")
                return with_header(None)
            if result != krb.AUTH_GSS_COMPLETE:
                log.debug(f"Kerberos challenge error: {result}")
                return with_header(None)

            # extract token
            try:
                token = krb.authGSSServerResponse(state)
            except krb.GSSError as e:
                log.debug(f"Kerberos response error: {e}")
                return with_header(None)

            # extract username
            try:
                username = krb.authGSSServerUserName(state)
            except krb.GSSError as e:
                log.debug(f"Kerberos username error: {e}")
                return with_header(None)

        return with_header(username)

    def identify(self, request):
        """ Returns the user for the given request, or None. """

        username = self.username(request)

        if not username:
            return None

        selector = User.authentication_provider['data']['username']
        return self.available_users().filter(selector == username).first()
