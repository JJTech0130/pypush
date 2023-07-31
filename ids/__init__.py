from base64 import b64encode

import apns

from . import _helpers, identity, profile, query


class IDSUser:
    # Sets self.user_id and self._auth_token
    def _authenticate_for_token(
        self, username: str, password: str, factor_callback: callable = None
    ):
        self.user_id, self._auth_token = profile.get_auth_token(
            username, password, factor_callback
        )

    # Sets self._auth_keypair using self.user_id and self._auth_token
    def _authenticate_for_cert(self):
        self._auth_keypair = profile.get_auth_cert(self.user_id, self._auth_token)

    # Factor callback will be called if a 2FA code is necessary
    def __init__(
        self,
        push_connection: apns.APNSConnection,
    ):
        self.push_connection = push_connection
        self._push_keypair = _helpers.KeyPair(
            self.push_connection.private_key, self.push_connection.cert
        )

        self.ec_key = self.rsa_key = None

    def __str__(self):
        return f"IDSUser(user_id={self.user_id}, handles={self.handles}, push_token={b64encode(self.push_connection.token).decode()})"

    # Authenticates with a username and password, to create a brand new authentication keypair
    def authenticate(
        self, username: str, password: str, factor_callback: callable = None
    ):
        self._authenticate_for_token(username, password, factor_callback)
        self._authenticate_for_cert()
        self.handles = profile.get_handles(
            b64encode(self.push_connection.token),
            self.user_id,
            self._auth_keypair,
            self._push_keypair,
        )
        self.current_handle = self.handles[0]


    # Uses an existing authentication keypair
    def restore_authentication(
        self, auth_keypair: _helpers.KeyPair, user_id: str, handles: dict
    ):
        self._auth_keypair = auth_keypair
        self.user_id = user_id
        self.handles = handles 
        self.current_handle = self.handles[0]

    # This is a separate call so that the user can make sure the first part succeeds before asking for validation data
    def register(self, validation_data: str):
        """
        self.ec_key, self.rsa_key will be set to a randomly gnenerated EC and RSA keypair
        if they are not already set
        """
        if self.encryption_identity is None:
            self.encryption_identity = identity.IDSIdentity()
        
        
        cert = identity.register(
            b64encode(self.push_connection.token),
            self.handles,
            self.user_id,
            self._auth_keypair,
            self._push_keypair,
            self.encryption_identity,
            validation_data,
        )
        self._id_keypair = _helpers.KeyPair(self._auth_keypair.key, cert)

    def restore_identity(self, id_keypair: _helpers.KeyPair):
        self._id_keypair = id_keypair

    def lookup(self, uris: list[str], topic: str = "com.apple.madrid") -> any:
        return query.lookup(self.push_connection, self.current_handle, self._id_keypair, uris, topic)
        
