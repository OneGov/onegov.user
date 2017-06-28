from json import dumps, loads
from onegov.user.collection import UserCollection
from onegov.user.forms import LoginForm
from onegov.user.forms import PasswordResetForm
from onegov.user.forms import RegistrationForm
from onegov.user.forms import RequestPasswordResetForm
from onegov.user.model import User


class DummyApp():
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class DummyRequest():
    def __init__(self, session):
        self.app = DummyApp(session)
        self.client_addr = '127.0.0.1'

    def load_url_safe_token(self, token, **kwargs):
        if not token:
            return None

        return loads(token)


class DummyPostData(dict):
    def getlist(self, key):
        v = self[key]
        if not isinstance(v, (list, tuple)):
            v = [v]
        return v


def test_login_form():
    # Test validation
    form = LoginForm()
    assert not form.validate()

    form.process(DummyPostData({
        'username': 'info@example.com',
        'password': 'much_secret'
    }))
    assert form.validate()
    assert form.login_data == {
        'username': 'info@example.com',
        'password': 'much_secret',
        'second_factor': None,
    }

    form.process(DummyPostData({
        'username': 'info@example.com',
        'password': 'much_secret',
        'yubikey': 'abcdefghijklmnopqrstuvwxyz'
    }))
    assert form.validate()
    assert form.login_data == {
        'username': 'info@example.com',
        'password': 'much_secret',
        'second_factor': 'abcdefghijklmnopqrstuvwxyz',
    }


def test_registration_form(session):
    # Test validation
    form = RegistrationForm()
    assert not form.validate()

    form.process(DummyPostData({
        'username': 'info@example.com',
        'password': 'much_secret',
        'confirm': 'very_secret'
    }))
    assert not form.validate()

    form.process(DummyPostData({
        'username': 'info@example.com',
        'password': 'much_secret',
        'confirm': 'much_secret',
        'roboter_falle': 'fooled'
    }))
    assert not form.validate()

    form.process(DummyPostData({
        'username': 'info@example.com',
        'password': 'much_secret',
        'confirm': 'much_secret'
    }))
    assert form.validate()

    # Test register user
    form.register_user(DummyRequest(session))
    assert session.query(User).filter_by(username='info@example.com').one()


def test_request_password_reset_form():
    # Test validation
    form = RequestPasswordResetForm()
    assert not form.validate()

    form.process(DummyPostData({
        'email': 'name',
    }))
    assert not form.validate()

    form.process(DummyPostData({
        'email': 'info@example.com',
    }))
    assert form.validate()


def test_password_reset_form(session):
    # Test validation
    request = DummyRequest(session)
    form = PasswordResetForm()
    assert not form.validate()

    form.process(DummyPostData({
        'email': 'name',
        'password': 'secret',
    }))
    assert not form.validate()

    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'secret',
    }))
    assert not form.validate()

    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'much_secret',
    }))
    assert form.validate()
    assert not form.update_password(request)

    # Test update password
    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'much_secret',
        'token': dumps({'username': 'username'})
    }))
    assert form.validate()
    assert not form.update_password(request)

    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'much_secret',
        'token': dumps({'username': 'info@example.com'})
    }))
    assert form.validate()
    assert not form.update_password(request)

    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'much_secret',
        'token': dumps({'username': 'info@example.com'})
    }))
    assert form.validate()
    assert not form.update_password(request)

    assert UserCollection(session).register(
        'info@example.com', 'very_secret', request
    )
    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'much_secret',
        'token': dumps({'username': 'info@example.com'})
    }))
    assert form.validate()
    assert not form.update_password(request)

    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'much_secret',
        'token': dumps({
            'username': 'info@example.com',
            'modified': 'now'
        })
    }))
    assert form.validate()
    assert not form.update_password(request)

    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'much_secret',
        'token': dumps({
            'username': 'info@example.com',
            'modified': ''
        })
    }))
    assert form.validate()
    assert form.update_password(request)

    form.process(DummyPostData({
        'email': 'info@example.com',
        'password': 'much_secret',
        'token': dumps({
            'username': 'info@example.com',
            'modified': ''
        })
    }))
    assert form.validate()
    assert not form.update_password(request)