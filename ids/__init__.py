from base64 import b64encode

import apns

from . import _helpers, identity, profile, query
from typing import Callable, Any

    
import dataclasses
import apns
from . import profile, _helpers
from base64 import b64encode
from typing import Callable

@dataclasses.dataclass
class IDSUser:
    push_connection: apns.APNSConnection

    user_id: str

    auth_keypair: _helpers.KeyPair
    """
    Long-lived authentication keypair
    """

    encryption_identity: identity.IDSIdentity | None = None

    id_cert: bytes | None = None
    """
    Short-lived identity certificate,
    same private key as auth_keypair
    """

    handles: list[str] = dataclasses.field(default_factory=list)
    """
    List of usable handles. Not equivalent to the current result of possible_handles, as the user
    may have added or removed handles since registration, which we can't use.
    """

    def possible_handles(self) -> list[str]:
        """
        Returns a list of possible handles for this user.
        """
        return profile.get_handles(
            b64encode(self.push_connection.credentials.token),
            self.user_id,
            self.auth_keypair,
            _helpers.KeyPair(self.push_connection.credentials.private_key, self.push_connection.credentials.cert),
        )
    
    async def lookup(self, handle: str, uris: list[str], topic: str = "com.apple.madrid") -> Any:
        if handle not in self.handles:
            raise Exception("Handle not registered to user")
        return await query.lookup(self.push_connection, handle, _helpers.KeyPair(self.auth_keypair.key, self.id_cert), uris, topic)


@dataclasses.dataclass
class IDSAppleUser(IDSUser):
    """
    An IDSUser that is authenticated with an Apple ID
    """

    @staticmethod
    def authenticate(push_connection: apns.APNSConnection, username: str, password: str, factor_callback: Callable | None = None) -> IDSUser:
        user_id, auth_token = profile.get_auth_token(username, password, factor_callback)
        auth_keypair = profile.get_auth_cert(user_id, auth_token)

        return IDSAppleUser(push_connection, user_id, auth_keypair)
    
@dataclasses.dataclass
class IDSPhoneUser(IDSUser):
    """
    An IDSUser that is authenticated with a phone number
    """

    @staticmethod
    def authenticate(push_connection: apns.APNSConnection, phone_number: str, phone_sig: bytes) -> IDSUser:
        auth_keypair = profile.get_phone_cert(phone_number, push_connection.credentials.token, [phone_sig])

        return IDSPhoneUser(push_connection, "P:" + phone_number, auth_keypair)
    
DEFAULT_CLIENT_DATA = {
    'is-c2k-equipment': True,
    'optionally-receive-typing-indicators': True,
    'public-message-identity-version':2,
    'show-peer-errors': True,
    'supports-ack-v1': True,
    'supports-activity-sharing-v1': True,
    'supports-audio-messaging-v2': True,
    "supports-autoloopvideo-v1": True,
    'supports-be-v1': True,
    'supports-ca-v1': True,
    'supports-fsm-v1': True,
    'supports-fsm-v2': True,
    'supports-fsm-v3': True,
    'supports-ii-v1': True,
    'supports-impact-v1': True,
    'supports-inline-attachments': True,
    'supports-keep-receipts': True,
    "supports-location-sharing": True,
    'supports-media-v2': True,
    'supports-photos-extension-v1': True,
    'supports-st-v1': True,
    'supports-update-attachments-v1': True,
}

import uuid

def register(push_connection: apns.APNSConnection, users: list[IDSUser], validation_data: str):
    signing_users = [(user.user_id, user.auth_keypair) for user in users]

    # Create new encryption identity for each user
    for user in users:
         if user.encryption_identity is None:
            user.encryption_identity = identity.IDSIdentity()

    # Construct user payloads
    user_payloads = []
    for user in users:
        if user.handles == []:
            user.handles = user.possible_handles()
        if user.encryption_identity is not None:
            special_data = DEFAULT_CLIENT_DATA.copy()
            special_data["public-message-identity-key"] = user.encryption_identity.encode()
        else:
            special_data = DEFAULT_CLIENT_DATA
        user_payloads.append({
            "client-data": special_data,
            "tag": "SIM" if user.user_id.startswith("P:") else None,
            "uris": [{"uri": handle} for handle in user.handles],
            "user-id": user.user_id,
        })

    _helpers.recursive_del_none(user_payloads)

    certs = identity.register(
        push_connection,
        signing_users,
        user_payloads,
        validation_data,
        uuid.uuid4()
    )

    for user in users:
        user.id_cert = certs[user.user_id]

    return users