import base64
import gzip
import logging
import plistlib
import random
import uuid
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from typing import Any

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
                url=self.url, # type: ignore
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

        self.name = attrib["name"] if "name" in attrib else None # type: ignore
        self.mime_type = attrib["mime-type"] if "mime-type" in attrib else None # type: ignore

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

            self.versions = versions # type: ignore

    def __repr__(self):
        return f'<Attachment name="{self.name}" type="{self.mime_type}">'

@dataclass
class Message:
    text: str
    """Plain text of message, always required, may be an empty string"""
    sender: str
    """Sender of the message"""
    participants: list[str]
    """List of participants in the message, including the sender"""
    id: uuid.UUID
    """ID of the message, will be randomly generated if not provided"""
    _raw: dict | None = None
    """Internal property representing the original raw message, may be None"""
    _compressed: bool = True
    """Internal property representing whether the message should be compressed"""
    xml: str | None = None
    """XML portion of message, may be None"""
    group_name: str | None = None
    """iMessage group chat name, may be None"""
    group_id: int | None = None
    """The ID of the iMessage group chat, may be None"""

    @staticmethod
    def from_raw(message: bytes, sender: str | None = None) -> "Message":
        """Create a `Message` from raw message bytes"""

        raise NotImplementedError()

    def to_raw(self) -> bytes:
        """Convert a `Message` to raw message bytes"""

        raise NotImplementedError()

    def __str__(self):
        #raise NotImplementedError()
        return f"[Message {self.sender}] '{self.text}'"

@dataclass
class SMSReflectedMessage(Message):
    @staticmethod
    def from_raw(message: bytes, sender: str | None = None) -> "SMSReflectedMessage":
        """Create a `SMSReflectedMessage` from raw message bytes"""

        # Decompress the message
        try:
            message = gzip.decompress(message)
            compressed = True
        except:
            compressed = False

        message = plistlib.loads(message)

        logger.info(f"Decoding SMSReflectedMessage: {message}")

        return SMSReflectedMessage(
            text=message["mD"]["plain-body"],  # type: ignore
            sender=sender, # type: ignore
            participants=[re["id"] for re in message["re"]] + [sender], # type: ignore
            id=uuid.UUID(message["mD"]["guid"]), # type: ignore
            _raw=message, # type: ignore
            _compressed=compressed,
        )

    def to_raw(self) -> bytes:
        #  {'re': [{'id': '+14155086773', 'uID': '4155086773', 'n': 'us'}], 'ic': 0, 'mD': {'handle': '+14155086773', 'guid': imessage.py:201
        #            '35694E24-E265-4D5C-8CA7-9499E35D0402', 'replyToGUID': '4F9BC76B-B09C-2A60-B312-9029D529706B', 'plain-body': 'Test sms', 'service':
        #            'SMS', 'sV': '1'}, 'fR': True, 'chat-style': 'im'}
        #pass
        # Strip tel: from participants, making sure they are all phone numbers
        #participants = [p.replace("tel:", "") for p in self.participants]

        d = {
            "re": [{"id": p} for p in self.participants],
            "ic": 0,
            "mD": {
                "handle": self.participants[0] if len(self.participants) == 1 else None,
                #"handle": self.sender,
                "guid": str(self.id).upper(),
                #"replyToGUID": "3B4B465F-F419-40FD-A8EF-94A110518E9F",
                #"replyToGUID": str(self.id).upper(),
                "xhtml": f"<html><body>{self.text}</body></html>",
                "plain-body": self.text,
                "service": "SMS",
                "sV": "1",
            },
            #"fR": True,
            "chat-style": "im" if len(self.participants) == 1 else "chat"
        }

        # Dump as plist
        d = plistlib.dumps(d, fmt=plistlib.FMT_BINARY)

        # Compress
        if self._compressed:
            d = gzip.compress(d, mtime=0)

        return d

    def __str__(self):
        return f"[SMS {self.sender}] '{self.text}'"

@dataclass
class SMSIncomingMessage(Message):
    @staticmethod
    def from_raw(message: bytes, sender: str | None = None) -> "SMSIncomingMessage":
        """Create a `SMSIncomingMessage` from raw message bytes"""

        # Decompress the message
        try:
            message = gzip.decompress(message)
            compressed = True
        except:
            compressed = False

        message = plistlib.loads(message)

        logger.debug(f"Decoding SMSIncomingMessage: {message}")

        return SMSIncomingMessage(
            text=message["k"][0]["data"].decode(), # type: ignore
            sender=message["h"], # Don't use sender parameter, that is the phone that forwarded the message # type: ignore
            participants=[message["h"], message["co"]], # type: ignore
            id=uuid.UUID(message["g"]), # type: ignore
            _raw=message, # type: ignore
            _compressed=compressed,
        )

    def __str__(self):
        return f"[SMS {self.sender}] '{self.text}'"

@dataclass
class SMSIncomingImage(Message):
    @staticmethod
    def from_raw(message: bytes, sender: str | None = None) -> "SMSIncomingImage":
        """Create a `SMSIncomingImage` from raw message bytes"""

        # TODO: Implement this
        return "SMSIncomingImage"     # type: ignore

@dataclass
class iMessage(Message):
    """
    An iMessage

    Description of payload keys:
    t: The sender token. Normally just a big thing of data/bytes, doesn't need to be decoded in any way
    U: the id of the message (uuid) as bytes
    """
    effect: str | None = None

    @staticmethod
    def create(user: "iMessageUser", text: str, participants: list[str], effect: str | None, group_id: uuid.UUID | None) -> "iMessage":
        """Creates a basic outgoing `iMessage` from the given text and participants"""

        sender = user.user.current_handle
        if sender not in participants:
            participants += [sender]

        return iMessage(
            text=text,
            sender=sender,
            participants=participants,
            id=uuid.uuid4(),
            effect=effect,
            group_id=group_id
        )

    @staticmethod
    def from_raw(message: bytes, sender: str | None = None) -> "iMessage":
        """Create a `iMessage` from raw message bytes"""

        # Decompress the message
        try:
            message = gzip.decompress(message)
            compressed = True
        except:
            compressed = False

        message = plistlib.loads(message)

        logger.debug(f"Decoding iMessage: {message}")

        return iMessage(
            text=message["t"], # type: ignore
            participants=message["p"], # type: ignore
            sender=sender, # type: ignore
            id=uuid.UUID(message["r"]) if "r" in message else None, # type: ignore
            xml=message["x"] if "x" in message else None, # type: ignore
            _raw=message, # type: ignore
            _compressed=compressed,
            group_name=message["n"] if "n" in message else None,
            group_id=uuid.UUID(message["gid"]) if "gid" in message else None,
            effect=message["iid"] if "iid" in message else None, # type: ignore
        )

    def to_raw(self) -> bytes:
        """Convert an `iMessage` to raw message bytes"""

        d = {
            "t": self.text,
            "x": self.xml,
            "p": self.participants,
            "r": str(self.id).upper(),
            "gid": str(self.group_id).upper(),
            "n": self.group_name,
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

    def __str__(self):
        return f"[iMessage {self.group_name if self.group_name is not None else self.group_id} {self.sender}] '{self.text}'"

MESSAGE_TYPES = {
    100: ("com.apple.madrid", iMessage),
    101: ("com.apple.madrid", iMessage),
    140: ("com.apple.private.alloy.sms", SMSIncomingMessage),
    141: ("com.apple.private.alloy.sms", SMSIncomingImage),
    143: ("com.apple.private.alloy.sms", SMSReflectedMessage),
    144: ("com.apple.private.alloy.sms", SMSReflectedMessage),
}

def maybe_decompress(message: bytes) -> bytes:
    """Decompresses a message if it is compressed, otherwise returns the original message"""
    try:
        message = gzip.decompress(message)
    except:
        pass
    return message

class iMessageUser:
    """Represents a logged in and connected iMessage user.
    This abstraction should probably be reworked into IDS some time..."""

    def __init__(self, connection: apns.APNSConnection, user: ids.IDSUser):
        self.connection = connection
        self.user = user

    @staticmethod
    def _parse_payload(p: bytes) -> tuple[bytes, bytes]:
        payload = BytesIO(p)

        tag = payload.read(1)
        # print("TAG", tag)
        body_length = int.from_bytes(payload.read(2), "big")
        body = payload.read(body_length)

        signature_len = payload.read(1)[0]
        signature = payload.read(signature_len)

        return (body, signature)

    @staticmethod
    def _construct_payload(body: bytes, signature: bytes) -> bytes:
        payload = (
            b"\x02"
            + len(body).to_bytes(2, "big")
            + body
            + len(signature).to_bytes(1, "big")
            + signature
        )
        return payload

    @staticmethod
    def _hash_identity(id: bytes) -> bytes:
        iden = ids.identity.IDSIdentity.decode(id)

        # TODO: Combine this with serialization code in ids.identity
        output = BytesIO()
        output.write(b"\x00\x41\x04")
        output.write(
            ids._helpers.parse_key(iden.signing_public_key)
            .public_numbers().x.to_bytes(32, "big") # type: ignore
        )
        output.write(
            ids._helpers.parse_key(iden.signing_public_key)
            .public_numbers().y.to_bytes(32, "big") # type: ignore
        )

        output.write(b"\x00\xAC")
        output.write(b"\x30\x81\xA9")
        output.write(b"\x02\x81\xA1")
        output.write(
            ids._helpers.parse_key(iden.encryption_public_key)
            .public_numbers().n.to_bytes(161, "big") # type: ignore
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
        rsa_body = recipient_key.encrypt( # type: ignore
            aes_key + encrypted[:100],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )

        # Construct the payload
        body = rsa_body + encrypted[100:]
        sig = ids._helpers.parse_key(self.user.encryption_identity.signing_key).sign( # type: ignore
            body, ec.ECDSA(hashes.SHA1()) # type: ignore
        )
        payload = iMessageUser._construct_payload(body, sig)

        return payload

    def _decrypt_payload(self, p: bytes) -> bytes:
        payload = iMessageUser._parse_payload(p)

        body = BytesIO(payload[0])
        rsa_body = ids._helpers.parse_key(
            self.user.encryption_identity.encryption_key # type: ignore
        ).decrypt( # type: ignore
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

    async def _verify_payload(self, p: bytes, sender: str, sender_token: str) -> bool:
        # Get the public key for the sender
        await self._cache_keys([sender], "com.apple.madrid")

        if not sender_token in self.KEY_CACHE:
            logger.warning("Unable to find the public key of the sender, cannot verify")
            return False

        identity_keys = ids.identity.IDSIdentity.decode(
            self.KEY_CACHE[sender_token]["com.apple.madrid"][0]
        )
        sender_ec_key = ids._helpers.parse_key(identity_keys.signing_public_key)

        payload = iMessageUser._parse_payload(p)

        try:
            # Verify the signature (will throw an exception if it fails)
            sender_ec_key.verify( # type: ignore
                payload[1],
                payload[0],
                ec.ECDSA(hashes.SHA1()), # type: ignore
            )
            return True
        except:
            return False

    async def receive(self) -> Message:
        """
        Will return the next iMessage in the queue, or None if there are no messages
        """
        body: dict[str, Any] = await self._receive_raw(list(MESSAGE_TYPES.keys()), [t[0] for t in MESSAGE_TYPES.values()])
        t: type[Message] = MESSAGE_TYPES[body["c"]][1]

        if not "P" in body:
            return Message(text="No payload", sender="System", participants=[], id=uuid.uuid4(), _raw=body)

        if not await self._verify_payload(body["P"], body["sP"], body["t"]):
            return Message(text="Failed to verify payload", sender="System", participants=[], id=uuid.uuid4(), _raw=body)
            #raise Exception("Failed to verify payload")

        logger.debug(f"Encrypted body : {body}")

        try:
            decrypted: bytes = self._decrypt_payload(body["P"])
        except Exception as e:
            logger.error(f"Failed to decrypt message : {e}")
            return Message(text="Failed to decrypt message", sender="System", participants=[], id=uuid.uuid4(), _raw=body)

        try:
            return t.from_raw(decrypted, body["sP"])
        except Exception as e:
            logger.error(f"Failed to parse message : {e}")
            return Message(text="Failed to parse message", sender="System", participants=[], id=uuid.uuid4(), _raw=body)

    KEY_CACHE_HANDLE: str = ""
    KEY_CACHE: dict[bytes, dict[str, tuple[bytes, bytes]]] = {}
    """Mapping of push token : topic : (public key, session token)"""
    USER_CACHE: dict[str, list[bytes]] = {}
    """Mapping of handle : [push tokens]"""

    async def _cache_keys(self, participants: list[str], topic: str):
        # Clear the cache if the handle has changed
        if self.KEY_CACHE_HANDLE != self.user.current_handle:
            self.KEY_CACHE_HANDLE = self.user.current_handle
            self.KEY_CACHE = {}
            self.USER_CACHE = {}

        # Check to see if we have cached the keys for all of the participants
        #if all([p in self.USER_CACHE for p in participants]):
        #    return
        # TODO: This doesn't work since it doesn't check if they are cached for all topics

        # Look up the public keys for the participants, and cache a token : public key mapping
        lookup = await self.user.lookup(participants, topic=topic)

        logger.debug(f"Lookup response : {lookup}")
        for key, participant in lookup.items():
            if len(participant["identities"]) == 0:
                logger.warning(f"Participant {key} has no identities, this is probably not a real account")

        for key, participant in lookup.items():
            self.USER_CACHE[key] = [] # Clear so that we don't keep appending multiple times

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

    async def _send_raw(
        self,
        type: int,
        participants: list[str],
        topic: str,
        payload: bytes | None = None,
        id: uuid.UUID | None = None,
        extra: dict = {},
    ):
        await self._cache_keys(participants, topic)

        dtl = []
        for participant in participants:
            for push_token in self.USER_CACHE[participant]:
                if push_token == self.connection.credentials.token:
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

        # Remove keys that are None
        body = {k: v for k, v in body.items() if v is not None}

        body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)

        await self.connection.send_notification(topic, body, message_id)

    async def typing(self, participants: list[str], start=True):
        await self._cache_keys(participants, "com.apple.madrid")

        await self._send_raw(
            100,
            participants,
            "com.apple.madrid",
            extra={
                "eX": 0 if start else None, # expiration
                "nr": 1 if start else None, # no response
            },
        )
        
    async def _receive_raw(self, c: int | list[int], topics: str | list[str]) -> dict[str, Any]:
        def check(payload: apns.APNSPayload):
            # Check if the "c" key matches
            body = payload.fields_with_id(3)[0].value
            if body is None:
                return False
            body = plistlib.loads(body)
            if not "c" in body:
                return False
            if isinstance(c, int) and body["c"] != c:
                return False
            elif isinstance(c, list) and body["c"] not in c:
                return False
            return True

        payload = await self.connection.expect_notification(topics, check)

        body_bytes: bytes = payload.fields_with_id(3)[0].value
        body: dict[str, Any] = plistlib.loads(body_bytes)
        return body

    async def activate_sms(self):
        """
        Try to activate SMS forwarding
        Returns True if we are able to perform SMS forwarding, False otherwise
        Call repeatedly until it returns True
        """

        act_message: dict[str, Any] = await self._receive_raw(145, "com.apple.private.alloy.sms")

        logger.info(f"Received SMS activation message : {act_message}")
        # Decrypt the payload
        act_message_bytes: bytes = self._decrypt_payload(act_message["P"])
        act_message = plistlib.loads(maybe_decompress(act_message_bytes))

        if act_message == {'wc': False, 'ar': True}:
            logger.info("SMS forwarding activated, sending response")
        else:
            logger.info("SMS forwarding de-activated, sending response")

        await self._send_raw(
            147,
            [self.user.current_handle],
            "com.apple.private.alloy.sms",
            extra={
                "nr": 1
            }
        )

    async def send(self, message: Message):
        # Check what type of message we are sending
        for t, (topic, cls) in MESSAGE_TYPES.items():
            if isinstance(message, cls):
                break
        else:
            raise Exception("Unknown message type")

        send_to = message.participants if isinstance(message, iMessage) else [self.user.current_handle]

        await self._cache_keys(send_to, topic)

        await self._send_raw(
            t,
            send_to,
            topic,
            message.to_raw(),
            message.id,
            {
                "E": "pair", # TODO: Do we need the nr field for SMS?
            }
        )

        # Check for delivery
        count = 0
        total = 0

        import time
        start = time.time()

        for p in send_to:
            for t in self.USER_CACHE[p]:
                if t == self.connection.credentials.token:
                    continue
                total += 1

        while count < total and time.time() - start < 2:
            resp: dict[str, Any] = await self._receive_raw(255, topic)
            #if resp is None:
            #    continue
            count += 1

            logger.debug(f"Received response : {resp}")

            if resp["s"] != 0:
                logger.warning(f"Message delivery to {base64.b64encode(resp['t']).decode()} failed : {resp['s']}")

        if count < total:
            logger.error(f"Unable to deliver message to all devices (got {count} of {total})")
