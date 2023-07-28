
# LOW LEVEL imessage function, decryption etc
# Don't handle APNS etc, accept it already setup

## HAVE ANOTHER FILE TO SETUP EVERYTHING AUTOMATICALLY, etc
# JSON parsing of keys, don't pass around strs??

import apns
import ids

import plistlib
from io import BytesIO

from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import gzip

from hashlib import sha1
import logging
logger = logging.getLogger("imessage")

NORMAL_NONCE = b"\x00" * 15 + b"\x01"

class BalloonBody:
    def __init__(self, type: str, data: bytes):
        self.type = type
        self.data = data

        # TODO : Register handlers based on type id

class iMessage:
    text: str
    xml: str | None = None
    participants: list[str]
    sender: str
    id: str
    group_id: str
    body: BalloonBody | None = None

    _raw: dict | None = None

    def from_raw(message: dict) -> 'iMessage':
        self = iMessage()

        self._raw = message

        self.text = message.get('t')
        self.xml = message.get('x')
        self.participants = message.get('p', [])
        if self.participants != []:
            self.sender = self.participants[-1]
        else:
            self.sender = None

        self.id = message.get('r')
        self.group_id = message.get('gid')

        if 'bid' in message:
            # This is a message extension body
            self.body = BalloonBody(message['bid'], message['b'])

        return self

    def to_raw(self) -> dict:
        return {
            "t": self.text,
            "x": self.xml,
            "p": self.participants,
            "r": self.id,
            "gid": self.group_id,
        }
    
    def __str__(self):
        if self._raw is not None:
            return str(self._raw)
        else:
            return f"iMessage({self.text} from {self.sender})"

class iMessageUser:

    def __init__(self, connection: apns.APNSConnection, user: ids.IDSUser):
        self.connection = connection
        self.user = user

    def _get_raw_message(self):
        """
        Returns a raw APNs message corresponding to the next conforming notification in the queue
        Returns None if no conforming notification is found
        """
        def check_response(x):
            if x[0] != 0x0A:
                return False
            if apns._get_field(x[1], 2) != sha1("com.apple.madrid".encode()).digest():
                return False
            resp_body = apns._get_field(x[1], 3)
            if resp_body is None:
                #logger.debug("Rejecting madrid message with no body")
                return False
            resp_body = plistlib.loads(resp_body)
            if "P" not in resp_body:
                #logger.debug(f"Rejecting madrid message with no payload : {resp_body}")
                return False
            return True
        
        payload = self.connection.incoming_queue.pop_find(check_response)
        if payload is None:
            return None
        id = apns._get_field(payload[1], 4)

        return payload

    def _send_raw_message(self, message: dict):
        pass

    def _encrypt_message(self, message: dict) -> dict:
        pass

    def _sign_message(self, message: dict) -> dict:
        pass

    def _parse_payload(payload: bytes) -> tuple[bytes, bytes]:
        payload = BytesIO(payload)

        tag = payload.read(1)
        body_length = int.from_bytes(payload.read(2), "big")
        body = payload.read(body_length)
        
        signature_len = payload.read(1)[0]
        signature = payload.read(signature_len)

        return (body, signature)
    
    def _decrypt_payload(self, payload: bytes) -> dict:
        payload = iMessageUser._parse_payload(payload)

        body = BytesIO(payload[0])
        rsa_body = ids._helpers.parse_key(self.user.encryption_identity.encryption_key).decrypt(
            body.read(160),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

        cipher = Cipher(algorithms.AES(rsa_body[:16]), modes.CTR(NORMAL_NONCE))
        decrypted = cipher.decryptor().update(rsa_body[16:] + body.read())
        
        # Try to gzip decompress the payload
        try:
            decrypted = gzip.decompress(decrypted)
        except:
            pass

        return plistlib.loads(decrypted)

    def _verify_payload(self, payload: bytes, sender: str, sender_token: str) -> bool:
        # Get the public key for the sender
        lookup = self.user.lookup([sender])[sender]

        sender_iden = None
        for identity in lookup['identities']:
            if identity['push-token'] == sender_token:
                sender_iden = identity
                break

        identity_keys = sender_iden['client-data']['public-message-identity-key']
        identity_keys = ids.identity.IDSIdentity.decode(identity_keys)

        sender_ec_key = ids._helpers.parse_key(identity_keys.signing_public_key)


        payload = iMessageUser._parse_payload(payload)

        try:
            # Verify the signature (will throw an exception if it fails)
            sender_ec_key.verify(
                payload[1],
                payload[0],
                ec.ECDSA(hashes.SHA1()),
            )
            return True
        except:
            return False

    def receive(self) -> iMessage | None:
        """
        Will return the next iMessage in the queue, or None if there are no messages
        """
        raw = self._get_raw_message()
        if raw is None:
            return None
        body = apns._get_field(raw[1], 3)
        body = plistlib.loads(body)
        payload = body["P"]
        decrypted = self._decrypt_payload(payload)
        if "p" in decrypted:
            if not self._verify_payload(payload, decrypted["p"][-1], body["t"]):
                raise Exception("Failed to verify payload")
        else:
            logger.warning("Unable to verify, couldn't determine sender! Dropping message! (TODO work out a way to verify these anyway)")
            return self.receive() # Call again to get the next message
        return iMessage.from_raw(decrypted)
    
    def send(self, message: iMessage):
        logger.error(f"Sending {message}")