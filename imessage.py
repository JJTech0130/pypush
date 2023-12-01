# LOW LEVEL imessage function, decryption etc
# Don't handle APNS etc, accept it already setup

## HAVE ANOTHER FILE TO SETUP EVERYTHING AUTOMATICALLY, etc
# JSON parsing of keys, don't pass around strs??

import base64
import gzip
import logging
import plistlib
import random
from typing import Union
import uuid
from dataclasses import dataclass, field
from hashlib import sha1, sha256
from io import BytesIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from xml.etree import ElementTree

import apns
import ids

logger = logging.getLogger("imessage")

NORMAL_NONCE = b"\x00" * 15 + b"\x01"  # This is always used as the AES nonce


class BalloonBody:
    """Represents the special parts of message extensions etc."""

    def __init__(self, type: str, data: bytes):
        self.type = type
        self.data = data

        # TODO : Register handlers based on type id


class AttachmentFile:
    def data(self) -> bytes:
        raise NotImplementedError()


@dataclass
class MMCSFile(AttachmentFile):
    url: Union[str, None] = None
    size: Union[int, None] = None
    owner: Union[str, None] = None
    signature: Union[bytes, None] = None
    decryption_key: Union[bytes, None] = None

    def data(self) -> bytes:
        import requests
        logger.info(requests.get(
            url=self.url,
            headers={
                "User-Agent": f"IMTransferAgent/900 CFNetwork/596.2.3 Darwin/12.2.0 (x86_64) (Macmini5,1)",
                # "MMCS-Url": self.url,
                # "MMCS-Signature": str(base64.encodebytes(self.signature)),
                # "MMCS-Owner": self.owner
            },
        ).headers)
        return b""


@dataclass
class InlineFile(AttachmentFile):
    _data: bytes

    def data(self) -> bytes:
        return self._data


@dataclass
class Attachment:
    name: str
    mime_type: str
    versions: list[AttachmentFile]

    def __init__(self, message_raw_content: dict, xml_element: ElementTree.Element):
        attrs = xml_element.attrib

        self.name = attrs["name"] if "name" in attrs else None
        self.mime_type = attrs["mime-type"] if "mime-type" in attrs else None

        if "inline-attachment" in attrs:
            # just grab the inline attachment !
            self.versions = [InlineFile(message_raw_content[attrs["inline-attachment"]])]
        else:
            # suffer
            versions = []
            for attribute in attrs:
                if attribute.startswith("mmcs") or \
                   attribute.startswith("decryption-key") or \
                   attribute.startswith("file-size"):
                    segments = attribute.split('-')
                    if segments[-1].isnumeric():
                        index = int(segments[-1])
                        attribute_name = segments[:-1]
                    else:
                        index = 0
                        attribute_name = attribute

                    while index >= len(versions):
                        versions.append(MMCSFile())

                    val = attrs[attribute_name]
                    if attribute_name == "mmcs-url":
                        versions[index].url = val
                    elif attribute_name == "mmcs-owner":
                        versions[index].owner = val
                    elif attribute_name == "mmcs-signature-hex":
                        versions[index].signature = base64.b16decode(val)
                    elif attribute_name == "file-size":
                        versions[index].size = int(val)
                    elif attribute_name == "decryption-key":
                        versions[index].decryption_key = base64.b16decode(val)[1:]

            self.versions = versions

    def __repr__(self):
        return f'<Attachment name="{self.name}" type="{self.mime_type}">'


@dataclass
class iMessage:
    """Represents an iMessage"""

    text: str = ""
    """Plain text of message, always required, may be an empty string"""
    xml: Union[str, None] = None
    """XML portion of message, may be None"""
    participants: list[str] = field(default_factory=list)
    """List of participants in the message, including the sender"""
    sender: Union[str, None] = None
    """Sender of the message"""
    id: Union[uuid.UUID, None] = None
    """ID of the message, will be randomly generated if not provided"""
    group_id: Union[uuid.UUID, None] = None
    """Group ID of the message, will be randomly generated if not provided"""
    body: Union[BalloonBody, None] = None
    """BalloonBody, may be None"""
    effect: Union[str, None] = None
    """iMessage effect sent with this message, may be None"""

    _compressed: bool = True
    """Internal property representing whether the message should be compressed"""

    _raw: Union[dict, None] = None
    """Internal property representing the original raw message, may be None"""

    def attachments(self) -> list[Attachment]:
        if self.xml is not None:
            return [Attachment(self._raw, elem) for elem in ElementTree.fromstring(self.xml)[0] if elem.tag == "FILE"]
        else:
            return []

    def sanity_check(self):
        """Corrects any missing fields"""
        if self.id is None:
            self.id = uuid.uuid4()

        if self.group_id is None:
            self.group_id = uuid.uuid4()

        if self.sender is None:
            if len(self.participants) > 1:
                self.sender = self.participants[-1]
            else:
                logger.warning(
                    "Message has no sender, and only one participant, sanity check failed"
                )
                return False

        if self.sender not in self.participants:
            self.participants.append(self.sender)

        if self.xml != None:
            self._compressed = False  # XML is never compressed for some reason

        return True

    def from_raw(message: bytes, sender: Union[str, None] = None) -> "iMessage":
        """Create an `iMessage` from raw message bytes"""
        compressed = False
        try:
            message = gzip.decompress(message)
            compressed = True
        except:
            pass

        message = plistlib.loads(message)

        return iMessage(
            text=message.get("t", ""),
            xml=message.get("x"),
            participants=message.get("p", []),
            sender=sender if sender is not None else message.get("p", [])[-1] if "p" in message else None,
            id=uuid.UUID(message.get("r")) if "r" in message else None,
            group_id=uuid.UUID(message.get("gid")) if "gid" in message else None,
            body=BalloonBody(message["bid"], message["b"]) if "bid" in message and "b" in message else None,
            effect=message["iid"] if "iid" in message else None,
            _compressed=compressed,
            _raw=message,
        )

    def to_raw(self) -> bytes:
        """Convert an `iMessage` to raw message bytes"""
        if not self.sanity_check():
            raise ValueError("Message failed sanity check")

        d = {
            "t": self.text,
            "x": self.xml,
            "p": self.participants,
            "r": str(self.id).upper(),
            "gid": str(self.group_id).upper(),
            "pv": 0,
            "gv": "8",
            "v": "1",
            "iid": self.effect
        }

        # Remove keys that are None
        d = {k: v for k, v in d.items() if v is not None}

        # Serialize as a plist
        d = plistlib.dumps(d, fmt=plistlib.FMT_BINARY)

        # Compression
        if self._compressed:
            d = gzip.compress(d, mtime=0)

        return d

    def to_string(self) -> str:
        message_str = f"[{self.sender}] '{self.text}'"
        if self.effect is not None:
            message_str += f" with effect [{self.effect}]"
        return message_str


class iMessageUser:
    """Represents a logged in and connected iMessage user.
    This abstraction should probably be reworked into IDS some time..."""

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
                # logger.debug("Rejecting madrid message with no body")
                return False
            resp_body = plistlib.loads(resp_body)
            if "P" not in resp_body:
                # logger.debug(f"Rejecting madrid message with no payload : {resp_body}")
                return False
            return True

        payload = self.connection.incoming_queue.pop_find(check_response)
        if payload is None:
            return None
        id = apns._get_field(payload[1], 4)

        return payload

    def _parse_payload(payload: bytes) -> tuple[bytes, bytes]:
        payload = BytesIO(payload)

        tag = payload.read(1)
        #print("TAG", tag)
        body_length = int.from_bytes(payload.read(2), "big")
        body = payload.read(body_length)

        signature_len = payload.read(1)[0]
        signature = payload.read(signature_len)

        return (body, signature)

    def _construct_payload(body: bytes, signature: bytes) -> bytes:
        payload = (
            b"\x02"
            + len(body).to_bytes(2, "big")
            + body
            + len(signature).to_bytes(1, "big")
            + signature
        )
        return payload

    def _hash_identity(id: bytes) -> bytes:
        iden = ids.identity.IDSIdentity.decode(id)

        # TODO: Combine this with serialization code in ids.identity
        output = BytesIO()
        output.write(b"\x00\x41\x04")
        output.write(
            ids._helpers.parse_key(iden.signing_public_key)
            .public_numbers()
            .x.to_bytes(32, "big")
        )
        output.write(
            ids._helpers.parse_key(iden.signing_public_key)
            .public_numbers()
            .y.to_bytes(32, "big")
        )

        output.write(b"\x00\xAC")
        output.write(b"\x30\x81\xA9")
        output.write(b"\x02\x81\xA1")
        output.write(
            ids._helpers.parse_key(iden.encryption_public_key)
            .public_numbers()
            .n.to_bytes(161, "big")
        )
        output.write(b"\x02\x03\x01\x00\x01")

        return sha256(output.getvalue()).digest()

    def _encrypt_sign_payload(
        self, key: ids.identity.IDSIdentity, message: bytes
    ) -> bytes:
        # Generate a random AES key
        random_seed = random.randbytes(11)
        # Create the HMAC
        import hmac

        hm = hmac.new(
            random_seed,
            message
            + b"\x02"
            + iMessageUser._hash_identity(self.user.encryption_identity.encode())
            + iMessageUser._hash_identity(key.encode()),
            sha256,
        ).digest()

        aes_key = random_seed + hm[:5]

        # print(len(aes_key))

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
        sig = ids._helpers.parse_key(self.user.encryption_identity.signing_key).sign(
            body, ec.ECDSA(hashes.SHA1())
        )
        payload = iMessageUser._construct_payload(body, sig)

        return payload

    def _decrypt_payload(self, payload: bytes) -> dict:
        payload = iMessageUser._parse_payload(payload)

        body = BytesIO(payload[0])
        rsa_body = ids._helpers.parse_key(
            self.user.encryption_identity.encryption_key
        ).decrypt(
            body.read(160),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

        cipher = Cipher(algorithms.AES(rsa_body[:16]), modes.CTR(NORMAL_NONCE))
        decrypted = cipher.decryptor().update(rsa_body[16:] + body.read())

        return decrypted

    def _verify_payload(self, payload: bytes, sender: str, sender_token: str) -> bool:
        # Get the public key for the sender
        self._cache_keys([sender])

        if not sender_token in self.KEY_CACHE:
            logger.warning("Unable to find the public key of the sender, cannot verify")
            return False

        identity_keys = ids.identity.IDSIdentity.decode(self.KEY_CACHE[sender_token][0])
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

    def receive(self) -> Union[iMessage, None]:
        """
        Will return the next iMessage in the queue, or None if there are no messages
        """
        raw = self._get_raw_message()
        if raw is None:
            return None
        body = apns._get_field(raw[1], 3)
        body = plistlib.loads(body)
        #print(f"Got body message {body}")
        payload = body["P"]

        if not self._verify_payload(payload, body['sP'], body["t"]):
            raise Exception("Failed to verify payload")
        
        decrypted = self._decrypt_payload(payload)
        
        return iMessage.from_raw(decrypted, body['sP'])

    KEY_CACHE_HANDLE: str = ""
    KEY_CACHE: dict[bytes, tuple[bytes, bytes]] = {}
    """Mapping of push token : (public key, session token)"""
    USER_CACHE: dict[str, list[bytes]] = {}
    """Mapping of handle : [push tokens]"""

    def _cache_keys(self, participants: list[str]):
        # Clear the cache if the handle has changed
        if self.KEY_CACHE_HANDLE != self.user.current_handle:
            self.KEY_CACHE_HANDLE = self.user.current_handle
            self.KEY_CACHE = {}
            self.USER_CACHE = {}
        
        # Check to see if we have cached the keys for all of the participants
        if all([p in self.USER_CACHE for p in participants]):
            return

        # Look up the public keys for the participants, and cache a token : public key mapping
        lookup = self.user.lookup(participants)

        for key, participant in lookup.items():
            if not key in self.USER_CACHE:
                self.USER_CACHE[key] = []

            for identity in participant["identities"]:
                if not "client-data" in identity:
                    continue
                if not "public-message-identity-key" in identity["client-data"]:
                    continue
                if not "push-token" in identity:
                    continue
                if not "session-token" in identity:
                    continue

                self.USER_CACHE[key].append(identity["push-token"])

                # print(identity)

                self.KEY_CACHE[identity["push-token"]] = (
                    identity["client-data"]["public-message-identity-key"],
                    identity["session-token"],
                )

    def send(self, message: iMessage):
        # Set the sender, if it isn't already
        if message.sender is None:
            message.sender = self.user.handles[0]  # TODO : Which handle to use?

        message.sanity_check() # Sanity check MUST be called before caching keys, so that the sender is added to the list of participants
        self._cache_keys(message.participants)

        # Turn the message into a raw message
        raw = message.to_raw()
        import base64

        bundled_payloads = []
        for participant in message.participants:
            participant = participant.lower()
            for push_token in self.USER_CACHE[participant]:
                if push_token == self.connection.token:
                    continue # Don't send to ourselves

                identity_keys = ids.identity.IDSIdentity.decode(
                    self.KEY_CACHE[push_token][0]
                )
                payload = self._encrypt_sign_payload(identity_keys, raw)

                bundled_payloads.append(
                    {
                        "tP": participant,
                        "D": not participant
                        == message.sender,  # TODO: Should this be false sometimes? For self messages?
                        "sT": self.KEY_CACHE[push_token][1],
                        "P": payload,
                        "t": push_token,
                    }
                )

        msg_id = random.randbytes(4)
        body = {
            "fcn": 1,
            "c": 100,
            "E": "pair",
            "ua": "[macOS,13.4.1,22F82,MacBookPro18,3]",
            "v": 8,
            "i": int.from_bytes(msg_id, "big"),
            "U": message.id.bytes,
            "dtl": bundled_payloads,
            "sP": message.sender,
        }

        body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)

        self.connection.send_message("com.apple.madrid", body, msg_id)

        # This code can check to make sure we got a success response, but waiting for the response is annoying,
        # so for now we just YOLO it and assume it worked

        # def check_response(x):
        #     if x[0] != 0x0A:
        #         return False
        #     if apns._get_field(x[1], 2) != sha1("com.apple.madrid".encode()).digest():
        #         return False
        #     resp_body = apns._get_field(x[1], 3)
        #     if resp_body is None:
        #         return False
        #     resp_body = plistlib.loads(resp_body)
        #     if "c" not in resp_body or resp_body["c"] != 255:
        #         return False
        #     return True
        

        # num_recv = 0
        # while True:
        #     if num_recv == len(bundled_payloads):
        #         break
        #     payload = self.connection.incoming_queue.wait_pop_find(check_response)
        #     if payload is None:
        #         continue

        #     resp_body = apns._get_field(payload[1], 3)
        #     resp_body = plistlib.loads(resp_body)
        #     logger.error(resp_body)
        #     num_recv += 1
