import morepath
from onegov.core.utils import relative_url
from onegov.user import log
from onegov.user.collection import UserCollection
from yubico_client import Yubico
from yubico_client.yubico_exceptions import (
    StatusCodeError,
    SignatureVerificationError
)


def is_valid_yubikey(client_id, secret_key, expected_yubikey_id, yubikey):
    """ Asks the yubico validation servers if the given yubikey OTP is valid.

    :client_id:
        The yubico API client id.

    :secret_key:
        The yubico API secret key.

    :expected_yubikey_id:
        The expected yubikey id. The yubikey id is defined as the first twelve
        characters of any yubikey value. Each user should have a yubikey
        associated with it's account. If the yubikey value comes from a
        different key, the key is invalid.

    :yubikey:
        The actual yubikey value that should be verified.

    :return: True if yubico confirmed the validity of the key.

    """
    assert client_id and secret_key and expected_yubikey_id and yubikey
    assert len(expected_yubikey_id) == 12

    # if the yubikey doesn't start with the expected yubikey id we do not
    # need to make a roundtrip to the validation server
    if not yubikey.startswith(expected_yubikey_id):
        return False

    try:
        return Yubico(client_id, secret_key).verify(yubikey)
    except StatusCodeError as e:
        if e.status_code != 'REPLAYED_OTP':
            raise e

        return False
    except SignatureVerificationError as e:
        return False


class Auth(object):
    """ Defines a model for authentication methods like login/logout.
    Applications should use this model to implement authentication views.

    """

    identity_class = morepath.Identity

    def __init__(self, session, application_id, to='/',
                 yubikey_client_id=None, yubikey_secret_key=None):
        assert application_id  # may not be empty!

        self.session = session
        self.application_id = application_id

        # never redirect to an external page, this might potentially be used
        # to trick the user into thinking he's on our page after entering his
        # password and being redirected to a phising site.
        self.to = relative_url(to)

        self.yubikey_client_id = yubikey_client_id
        self.yubikey_secret_key = yubikey_secret_key

    @classmethod
    def from_app(cls, app, to='/'):
        return cls(
            session=app.session(),
            application_id=app.application_id,
            yubikey_client_id=getattr(app, 'yubikey_client_id', None),
            yubikey_secret_key=getattr(app, 'yubikey_secret_key', None),
            to=to
        )

    @classmethod
    def from_request(cls, request, to='/'):
        return cls.from_app(request.app, to)

    @property
    def users(self):
        return UserCollection(self.session)

    def is_valid_second_factor(self, user, second_factor_value):
        if not user.second_factor:
            return True

        if not second_factor_value:
            return False

        if user.second_factor['type'] == 'yubikey':
            return is_valid_yubikey(
                client_id=self.yubikey_client_id,
                secret_key=self.yubikey_secret_key,
                expected_yubikey_id=user.second_factor['data'],
                yubikey=second_factor_value
            )
        else:
            raise NotImplementedError

    def login(self, username, password, client='unknown', second_factor=None):
        """ Takes the given username and password and matches them against
        the users collection.

        :meth:`login_to` should be the preferred method in most cases, as it
        sets up automatic logging of login attempts and provides optional
        login/logout messages.

        :return: An identity bound to the ``application_id`` if the username
        and password match.

        """

        user = self.users.by_username_and_password(username, password)

        def fail():
            log.info("Failed login by {} ({})".format(client, username))
            return None

        if user is None:
            return fail()

        if not self.is_valid_second_factor(user, second_factor):
            return fail()

        log.info("Successful login by {} ({})".format(client, username))

        return self.identity_class(
            userid=user.username,
            role=user.role,
            application_id=self.application_id
        )

    def login_to(self, username, password, request, second_factor=None):
        """ Matches the username and password against the users collection,
        just like :meth:`login`. Unlike said method it returns no identity
        however, instead a redirect response is returned which will remember
        the identity.

        :return: A redirect response to ``self.to`` with the identity
        remembered as a cookie. If not successful, None is returned.

        """

        identity = self.login(username, password, request.client_addr,
                              second_factor)

        if identity is None:
            return None

        response = morepath.redirect(self.to)
        morepath.remember_identity(response, request, identity)

        return response

    def logout_to(self, request):
        """ Logs the current user out and redirects to ``self.to``.

        :return: A response redirecting to ``self.to`` with the identity
        forgotten.

        """

        response = morepath.redirect(self.to)
        morepath.forget_identity(response, request)

        return response
