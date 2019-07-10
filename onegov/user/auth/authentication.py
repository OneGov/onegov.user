from abc import ABCMeta, abstractmethod


AUTHENTICATION_PROVIDERS = {}


class AuthenticationProvider(metaclass=ABCMeta):
    """ Base class and registry for third party authentication providers. """

    def __init_subclass__(cls, type, **kwargs):
        global AUTHENTICATION_PROVIDERS
        assert type not in AUTHENTICATION_PROVIDERS

        AUTHENTICATION_PROVIDERS[type] = cls

        super().__init_subclass__(**kwargs)

    @abstractmethod
    def identify(self, request):
        """ Returns the user model identified by this request or None. """
