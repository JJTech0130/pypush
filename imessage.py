
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

NORMAL_NONCE = b"\x00" * 15 + b"\x01"

class iMessageUser:

    def __init__(self, connection: apns.APNSConnection, user: ids.IDSUser):
        self.connection = connection
        self.user = user

    def _get_raw_message(self):
        """
        Returns a raw APNs message corresponding to the next conforming notification in the queue
        """
        def check_response(x):
            if x[0] != 0x0A:
                return False
            resp_body = apns._get_field(x[1], 3)
            if resp_body is None:
                return False
            resp_body = plistlib.loads(resp_body)
            if "P" not in resp_body:
                return False
            return True
        
        payload = self.connection.incoming_queue.wait_pop_find(check_response)
        id = apns._get_field(payload[1], 4)
        self.connection._send_ack(id)

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

    def receive(self) -> dict:
        raw = self._get_raw_message()
        body = apns._get_field(raw[1], 3)
        body = plistlib.loads(body)
        payload = body["P"]
        decrypted = self._decrypt_payload(payload)
        if not self._verify_payload(payload, decrypted["p"][-1], body["t"]):
            raise Exception("Failed to verify payload")
        return decrypted
