# LOW LEVEL imessage function, decryption etc
# Don't handle APNS etc, accept it already setup

## HAVE ANOTHER FILE TO SETUP EVERYTHING AUTOMATICALLY, etc
# JSON parsing of keys, don't pass around strs??

import base64
import gzip
import logging
import plistlib
import random
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
    url: str | None = None
    size: int | None = None
    owner: str | None = None
    signature: bytes | None = None
    decryption_key: bytes | None = None

    def data(self) -> bytes:
        import requests

        logger.info(
            requests.get(
                url=self.url,
                headers={
                    "User-Agent": f"IMTransferAgent/900 CFNetwork/596.2.3 Darwin/12.2.0 (x86_64) (Macmini5,1)",
                    # "MMCS-Url": self.url,
                    # "MMCS-Signature": str(base64.encodebytes(self.signature)),
                    # "MMCS-Owner": self.owner
                },
            ).headers
        )
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
        attrib = xml_element.attrib

        self.name = attrib["name"] if "name" in attrib else None
        self.mime_type = attrib["mime-type"] if "mime-type" in attrib else None

        if "inline-attachment" in attrib:
            # just grab the inline attachment !
            self.versions = [
                InlineFile(message_raw_content[attrib["inline-attachment"]])
            ]
        else:
            # suffer

            versions = [InlineFile(b"")]

            print(attrib)
            # for attribute in attrs:
            #     if attribute.startswith("mmcs") or \
            #        attribute.startswith("decryption-key") or \
            #        attribute.startswith("file-size"):
            #         segments = attribute.split('-')
            #         if segments[-1].isnumeric():
            #             index = int(segments[-1])
            #             attribute_name = segments[:-1]
            #         else:
            #             index = 0
            #             attribute_name = attribute

            #         while index >= len(versions):
            #             versions.append(MMCSFile())

            #         val = attrs[attribute_name]
            #         match attribute_name:
            #             case "mmcs-url":
            #                 versions[index].url = val
            #             case "mmcs-owner":
            #                 versions[index].owner = val
            #             case "mmcs-signature-hex":
            #                 versions[index].signature = base64.b16decode(val)
            #             case "file-size":
            #                 versions[index].size = int(val)
            #             case "decryption-key":
            #                 versions[index].decryption_key = base64.b16decode(val)[1:]

            self.versions = versions

    def __repr__(self):
        return f'<Attachment name="{self.name}" type="{self.mime_type}">'

class Message:
    def __init__(self, text: str, sender: str, participants: list[str], id: uuid.UUID, _raw: dict, _compressed: bool = True):
        self.text = text
        self.sender = sender
        self.id = id
        self._raw = _raw
        self._compressed = _compressed
    
    def from_raw(message: bytes, sender: str | None = None) -> "Message":
        """Create a `Message` from raw message bytes"""

        raise NotImplementedError()
    
    def __str__():
        raise NotImplementedError()

class SMSReflectedMessage(Message):
    def from_raw(message: bytes, sender: str | None = None) -> "SMSReflectedMessage":
        """Create a `SMSIncomingMessage` from raw message bytes"""

        # Decompress the message
        try:
            message = gzip.decompress(message)
            compressed = True
        except:
            compressed = False

        message = plistlib.loads(message)

        return SMSReflectedMessage(
            text=message["mD"]["plain-body"],
            sender=sender,
            participants=[re["id"] for re in message["re"]] + [sender],
            id=uuid.UUID(message["mD"]["guid"]),
            _raw=message,
            _compressed=compressed,
        )
    
    def __str__(self):
        return f"[SMS {self.sender}] '{self.text}'"

class SMSIncomingMessage(Message):
    def from_raw(message: bytes, sender: str | None = None) -> "SMSIncomingMessage":
        """Create a `SMSIncomingMessage` from raw message bytes"""

        # Decompress the message
        try:
            message = gzip.decompress(message)
            compressed = True
        except:
            compressed = False

        message = plistlib.loads(message)

        logger.debug(f"Decompressed message : {message}")

        return SMSIncomingMessage(
            text=message["k"][0]["data"].decode(),
            sender=message["h"], # Don't use sender parameter, that is the phone that forwarded the message
            participants=[message["h"], message["co"]],
            id=uuid.UUID(message["g"]),
            _raw=message,
            _compressed=compressed,
        )

    def __str__(self):
        return f"[SMS {self.sender}] '{self.text}'"

class iMessage(Message):
    def from_raw(message: bytes, sender: str | None = None) -> "iMessage":
        """Create a `iMessage` from raw message bytes"""

        # Decompress the message
        try:
            message = gzip.decompress(message)
            compressed = True
        except:
            compressed = False

        message = plistlib.loads(message)

        return iMessage(
            text=message["t"],
            participants=message["p"],
            sender=sender,
            id=uuid.UUID(message["r"]),
            _raw=message,
            _compressed=compressed,
        )
    
    def __str__(self):
        return f"[iMessage {self.sender}] '{self.text}'"

@dataclass
class OldiMessage:
    """Represents an iMessage"""

    text: str = ""
    """Plain text of message, always required, may be an empty string"""
    xml: str | None = None
    """XML portion of message, may be None"""
    participants: list[str] = field(default_factory=list)
    """List of participants in the message, including the sender"""
    sender: str | None = None
    """Sender of the message"""
    id: uuid.UUID | None = None
    """ID of the message, will be randomly generated if not provided"""
    group_id: uuid.UUID | None = None
    """Group ID of the message, will be randomly generated if not provided"""
    body: BalloonBody | None = None
    """BalloonBody, may be None"""
    effect: str | None = None
    """iMessage effect sent with this message, may be None"""

    _compressed: bool = True
    """Internal property representing whether the message should be compressed"""

    _raw: dict | None = None
    """Internal property representing the original raw message, may be None"""

    def attachments(self) -> list[Attachment]:
        if self.xml is not None:
            return [
                Attachment(self._raw, elem)
                for elem in ElementTree.fromstring(self.xml)[0]
                if elem.tag == "FILE"
            ]
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

    def from_raw(message: bytes, sender: str | None = None) -> "OldiMessage":
        """Create an `iMessage` from raw message bytes"""
        compressed = False
        try:
            message = gzip.decompress(message)
            compressed = True
        except:
            pass

        message = plistlib.loads(message)

        logger.debug(f"Decompressed message : {message}")

        try:
            return OldiMessage(
                text=message[
                    "t"
                ],  # Cause it to "fail to parse" if there isn't any good text to display, temp hack
                xml=message.get("x"),
                participants=message.get("p", []),
                sender=sender
                if sender is not None
                else message.get("p", [])[-1]
                if "p" in message
                else None,
                id=uuid.UUID(message.get("r")) if "r" in message else None,
                group_id=uuid.UUID(message.get("gid")) if "gid" in message else None,
                body=BalloonBody(message["bid"], message["b"])
                if "bid" in message and "b" in message
                else None,
                effect=message["iid"] if "iid" in message else None,
                _compressed=compressed,
                _raw=message,
            )
        except:
            #import json

            dmp = str(message)
            return OldiMessage(text=f"failed to parse: {dmp}", _raw=message)

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
            "iid": self.effect,
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

    def _parse_payload(payload: bytes) -> tuple[bytes, bytes]:
        payload = BytesIO(payload)

        tag = payload.read(1)
        # print("TAG", tag)
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
        self._cache_keys([sender], "com.apple.madrid")

        if not sender_token in self.KEY_CACHE:
            logger.warning("Unable to find the public key of the sender, cannot verify")
            return False

        identity_keys = ids.identity.IDSIdentity.decode(
            self.KEY_CACHE[sender_token]["com.apple.madrid"][0]
        )
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

    def receive(self) -> Message | None:
        """
        Will return the next iMessage in the queue, or None if there are no messages
        """
        
        # Check for iMessages
        body = self._receive_raw(100, "com.apple.madrid")
        t = iMessage
        if body is None:
            # Check for SMS messages
            body = self._receive_raw(143, "com.apple.private.alloy.sms")
            t = SMSReflectedMessage
        if body is None:
            # Check for SMS incoming messages
            body = self._receive_raw(140, "com.apple.private.alloy.sms")
            t = SMSIncomingMessage
        if body is None:
            return None
        

        if not self._verify_payload(body["P"], body["sP"], body["t"]):
            raise Exception("Failed to verify payload")

        logger.debug(f"Encrypted body : {body}")

        decrypted = self._decrypt_payload(body["P"])

        return t.from_raw(decrypted, body["sP"])

    KEY_CACHE_HANDLE: str = ""
    KEY_CACHE: dict[bytes, dict[str, tuple[bytes, bytes]]] = {}
    """Mapping of push token : topic : (public key, session token)"""
    USER_CACHE: dict[str, list[bytes]] = {}
    """Mapping of handle : [push tokens]"""

    def _cache_keys(self, participants: list[str], topic: str):
        # Clear the cache if the handle has changed
        if self.KEY_CACHE_HANDLE != self.user.current_handle:
            self.KEY_CACHE_HANDLE = self.user.current_handle
            self.KEY_CACHE = {}
            self.USER_CACHE = {}

        # Check to see if we have cached the keys for all of the participants
        if all([p in self.USER_CACHE for p in participants]):
            return

        # Look up the public keys for the participants, and cache a token : public key mapping
        lookup = self.user.lookup(participants, topic=topic)

        logger.debug(f"Lookup response : {lookup}")
        for key, participant in lookup.items():
            if len(participant["identities"]) == 0:
                logger.warning(f"Participant {key} has no identities, this is probably not a real account")

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

                if not identity["push-token"] in self.KEY_CACHE:
                    self.KEY_CACHE[identity["push-token"]] = {}

                self.KEY_CACHE[identity["push-token"]][topic] = (
                    identity["client-data"]["public-message-identity-key"],
                    identity["session-token"],
                )

    def _send_raw(
        self,
        type: int,
        participants: list[str],
        topic: str,
        payload: bytes | None = None,
        id: uuid.UUID | None = None,
        extra: dict = {},
    ):
        self._cache_keys(participants, topic)

        dtl = []
        for participant in participants:
            for push_token in self.USER_CACHE[participant]:
                if push_token == self.connection.token:
                    continue  # Don't send to ourselves

                identity_keys = ids.identity.IDSIdentity.decode(
                    self.KEY_CACHE[push_token][topic][0]
                )

                p = {
                    "tP": participant,
                    "D": not participant == self.user.current_handle,
                    "sT": self.KEY_CACHE[push_token][topic][1],
                    "t": push_token,
                }

                if payload is not None:
                    p["P"] = self._encrypt_sign_payload(identity_keys, payload)

                logger.debug(f"Encoded payload : {p}")

                dtl.append(p)

        message_id = random.randbytes(4)

        if id is None:
            id = uuid.uuid4()

        body = {
            "c": type,
            "fcn": 1,
            "v": 8,
            "i": int.from_bytes(message_id, "big"),
            "U": id.bytes,
            "dtl": dtl,
            "sP": self.user.current_handle,
        }

        body.update(extra)

        body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)

        self.connection.send_message(topic, body, message_id)

    def _receive_raw(self, c: int | list[int], topic: str | list[str]) -> dict | None:
        def check_response(x):
            if x[0] != 0x0A:
                return False
            # Check if it matches any of the topics
            if isinstance(topic, list):
                for t in topic:
                    if apns._get_field(x[1], 2) == sha1(t.encode()).digest():
                        break
                else:
                    return False
            else:
                if apns._get_field(x[1], 2) != sha1(topic.encode()).digest():
                    return False
                
            resp_body = apns._get_field(x[1], 3)
            if resp_body is None:
                return False
            resp_body = plistlib.loads(resp_body)

            #logger.debug(f"See type {resp_body['c']}")

            if isinstance(c, list):
                if not resp_body["c"] in c:
                    return False
            elif resp_body["c"] != c:
                return False
            return True

        payload = self.connection.incoming_queue.pop_find(check_response)
        if payload is None:
            return None
        body = apns._get_field(payload[1], 3)
        body = plistlib.loads(body)
        return body

    def activate_sms(self) -> bool:
        """
        Try to activate SMS forwarding
        Returns True if we are able to perform SMS forwarding, False otherwise
        Call repeatedly until it returns True
        """

        act_message = self._receive_raw(145, "com.apple.private.alloy.sms")
        if act_message is None:
            return False
        
        self._send_raw(
            147,
            [self.user.current_handle],
            "com.apple.private.alloy.sms",
            extra={
                "nr": 1
            }
        )

    def send(self, message: OldiMessage):
        # Set the sender, if it isn't already
        if message.sender is None:
            message.sender = self.user.handles[0]  # TODO : Which handle to use?

        message.sanity_check()  # Sanity check MUST be called before caching keys, so that the sender is added to the list of participants
        self._cache_keys(message.participants, "com.apple.madrid")

        self._send_raw(
            100,
            message.participants,
            "com.apple.madrid",
            message.to_raw(),
            message.id,
            {
                "E": "pair",
            }
        )

        # Check for delivery
        count = 0
        total = 0

        import time
        start = time.time()

        for p in message.participants:
            for t in self.USER_CACHE[p]:
                if t == self.connection.token:
                    continue
                total += 1

        while count < total and time.time() - start < 2:
            resp = self._receive_raw(255, "com.apple.madrid")
            if resp is None:
                continue
            count += 1

            logger.debug(f"Received response : {resp}")

            if resp["s"] != 0:
                logger.warning(f"Message delivery to {base64.b64encode(resp['t']).decode()} failed : {resp['s']}")

        if count < total:
            logger.error(f"Unable to deliver message to all devices (got {count} of {total})")
