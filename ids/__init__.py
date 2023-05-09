from base64 import b64encode
import apns
from . import profile
from . import _helpers
#from .profile import _get_auth_cert, _get_auth_token, _get_handles

class IDSUser:
    def _authenticate_for_token(
        self, username: str, password: str, factor_callback: callable = None
    ):
        self.user_id, self._auth_token = profile._get_auth_token(
            username, password, factor_callback
        )

    def _authenticate_for_cert(self):
        self._auth_keypair = profile._get_auth_cert(self.user_id, self._auth_token)

    # Factor callback will be called if a 2FA code is necessary
    def __init__(
        self,
        push_connection: apns.APNSConnection,
        username: str,
        password: str,
        factor_callback: callable = None,
    ):
        self.push_connection = push_connection
        self._authenticate_for_token(username, password, factor_callback)
        self._authenticate_for_cert()
        self.handles = profile._get_handles(
            b64encode(self.push_connection.token),
            self.user_id,
            self._auth_keypair,
            _helpers.KeyPair(self.push_connection.private_key, self.push_connection.cert),
        )

    def __str__(self):
        return f"IDSUser(user_id={self.user_id}, handles={self.handles}, push_token={b64encode(self.push_connection.token).decode()})"