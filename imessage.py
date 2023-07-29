
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
import uuid
import random

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
    text: str = ""
    xml: str | None = None
    participants: list[str] = []
    sender: str | None = None
    id: str | None = None
    group_id: str | None = None
    body: BalloonBody | None = None

    _compressed: bool = True

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

        if 'compressed' in message: # This is a hack, not a real field
            self._compressed = message['compressed']

        return self

    def to_raw(self) -> dict:
        return {
            "t": self.text,
            "x": self.xml,
            "p": self.participants,
            "r": self.id,
            "gid": self.group_id,
            "compressed": self._compressed,
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

    def _sign_message(self, message: dict) -> dict:
        pass

    def _parse_payload(payload: bytes) -> tuple[bytes, bytes]:
        payload = BytesIO(payload)

        tag = payload.read(1)
        print("TAG", tag)
        body_length = int.from_bytes(payload.read(2), "big")
        body = payload.read(body_length)
        
        signature_len = payload.read(1)[0]
        signature = payload.read(signature_len)

        return (body, signature)
    
    def _construct_payload(body: bytes, signature: bytes) -> bytes:
        payload = b"\x02" + len(body).to_bytes(2, "big") + body + len(signature).to_bytes(1, "big") + signature
        return payload
    
    # Look up the public keys for the participants (except the sender)
    # def test():
    #     lookup = self.user.lookup(message['p'][:-1])

    #     # Get the public keys for the participants
    #     public_keys = {}
    #     for participant in message['p'][:-1]:
    #         for identity in lookup[participant]['identities']:
    #             logger.debug(identity)
    #             if 'client-data' in identity and 'public-message-identity-key' in identity['client-data'] and 'push-token' in identity:
    #                 public_keys[identity['push-token']] = identity['client-data']['public-message-identity-key']

    #     logger.debug(public_keys)

    def _encrypt_sign_payload(self, key: ids.identity.IDSIdentity, message: dict) -> dict[str, bytes]:
        # Dump the message plist
        compressed = message.get('compressed', False)
        message = plistlib.dumps(message, fmt=plistlib.FMT_BINARY)

        # Compress the message
        if compressed:
            message = gzip.compress(message, mtime=0)

        # Generate a random AES key
        aes_key = random.randbytes(16)

        # Encrypt the message with the AES key
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(NORMAL_NONCE))
        encrypted = cipher.encryptor().update(message)

        # Encrypt the AES key with the public key of the recipient
        recipient_key = ids._helpers.parse_key(key.encryption_public_key)
        rsa_body = recipient_key.encrypt(
             aes_key + encrypted[:100],
             padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
        )

        # Construct the payload
        body = rsa_body + encrypted[100:]
        sig = ids._helpers.parse_key(self.user.encryption_identity.signing_key).sign(body, ec.ECDSA(hashes.SHA1()))
        payload = iMessageUser._construct_payload(body, sig)

        return payload
    
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

        logger.debug(f"RSA BODY LEN: {len(rsa_body)}")

        cipher = Cipher(algorithms.AES(rsa_body[:16]), modes.CTR(NORMAL_NONCE))
        decrypted = cipher.decryptor().update(rsa_body[16:] + body.read())
        
        # Try to gzip decompress the payload
        compressed = False
        try:
            decrypted = gzip.decompress(decrypted)
            compressed = True
        except:
            pass

        pl = plistlib.loads(decrypted)
        pl['compressed'] = compressed # This is a hack so that messages can be re-encrypted with the same compression

        return pl

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
        logger.debug(f"Got body message {body}")
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
        # Set the sender, if it isn't already
        if message.sender is None:
            message.sender = self.user.handles[0] # TODO : Which handle to use?
        if message.sender not in message.participants:
            message.participants.append(message.sender)

        # Set the group id, if it isn't already
        if message.group_id is None:
            message.group_id = str(uuid.uuid4()).upper() # TODO: Keep track of group ids?
        mid = uuid.uuid4()
        if message.id is None:
            message.id = str(mid).upper()

        # Turn the message into a raw message
        raw = message.to_raw()

        # Encrypt the message for each participant
        lookup = self.user.lookup(message.participants[:-1])
        for participant in message.participants[:-1]:            
            for identity in lookup[participant]['identities']:
                if 'client-data' in identity and 'public-message-identity-key' in identity['client-data'] and 'push-token' in identity:
                    push_token = identity['push-token']
                    identity_keys = ids.identity.IDSIdentity.decode(identity['client-data']['public-message-identity-key'])
                    payload = self._encrypt_sign_payload(identity_keys, raw)
                    import time
                    body = {
                        "t": self.connection.token,
                        "P": payload,
                        "c": 100,
                        "E": "pair",
                        "sP": self.user.handles[0],
                        "tP": participant,
                        "U": mid.bytes,
                        'v': 8,
                        'D': True,
                        'e': time.time_ns(),
                        'htu': True
                        #'e': 1,
                        # missing 'e'????
                    }
                    logger.debug(f"body {body}")
                    body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)
                    from base64 import b64encode
                    logger.debug(f"Sending message to {participant} with payload {body} and token {b64encode(push_token)}")
                    self.connection.send_message("com.apple.madrid", body)

                    # Wait for a response
                    def check_response(x):
                        if x[0] != 0x0A:
                            return False
                        if apns._get_field(x[1], 2) != sha1("com.apple.madrid".encode()).digest():
                            return False
                        resp_body = apns._get_field(x[1], 3)
                        if resp_body is None:
                            return False
                        resp_body = plistlib.loads(resp_body)
                        return True
                    
                    # Wait for a few sec to wait for it
                    for i in range(10):
                        payload = self.connection.incoming_queue.wait_pop_find(check_response)
                        if payload is not None:
                            break
                        time.sleep(0.1)

                    if payload is None:
                        raise Exception("Failed to send message")
                    
                    # Check the response
                    resp_body = apns._get_field(payload[1], 3)
                    resp_body = plistlib.loads(resp_body)
                    logger.error(resp_body)
                    

        logger.error(f"Sent {message}")