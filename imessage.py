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

@dataclass
class Message:
    text: str
    sender: str
    participants: list[str]
    id: uuid.UUID
    _raw: dict | None = None
    _compressed: bool = True
    xml: str | None = None
    
    def from_raw(message: bytes, sender: str | None = None) -> "Message":
        """Create a `Message` from raw message bytes"""

        raise NotImplementedError()
    
    def __str__():
        raise NotImplementedError()

@dataclass
class SMSReflectedMessage(Message):
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
            text=message["mD"]["plain-body"],
            sender=sender,
            participants=[re["id"] for re in message["re"]] + [sender],
            id=uuid.UUID(message["mD"]["guid"]),
            _raw=message,
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
            text=message["k"][0]["data"].decode(),
            sender=message["h"], # Don't use sender parameter, that is the phone that forwarded the message
            participants=[message["h"], message["co"]],
            id=uuid.UUID(message["g"]),
            _raw=message,
            _compressed=compressed,
        )

    def __str__(self):
        return f"[SMS {self.sender}] '{self.text}'"
    
@dataclass
class SMSIncomingImage(Message):
    def from_raw(message: bytes, sender: str | None = None) -> "SMSIncomingImage":
        """Create a `SMSIncomingImage` from raw message bytes"""

        # TODO: Implement this
        return "SMSIncomingImage"    

@dataclass
class iMessage(Message):
    effect: str | None = None

    def create(user: "iMessageUser", text: str, participants: list[str]) -> "iMessage":
        """Creates a basic outgoing `iMessage` from the given text and participants"""

        sender = user.user.current_handle
        participants += [sender]

        return iMessage(
            text=text,
            sender=sender,
            participants=participants,
            id=uuid.uuid4(),
        )
    
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
            text=message["t"],
            participants=message["p"],
            sender=sender,
            id=uuid.UUID(message["r"]) if "r" in message else None,
            xml=message["x"] if "x" in message else None,
            _raw=message,
            _compressed=compressed,
            effect=message["iid"] if "iid" in message else None,
        )
    
    def to_raw(self) -> bytes:
        """Convert an `iMessage` to raw message bytes"""

        d = {
            "t": self.text,
            "x": self.xml,
            "p": self.participants,
            "r": str(self.id).upper(),
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
        return f"[iMessage {self.sender}] '{self.text}'"

MESSAGE_TYPES = {
    100: ("com.apple.madrid", iMessage),
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
        for type, (topic, cls) in MESSAGE_TYPES.items():
            body = self._receive_raw(type, topic)
            if body is not None:
                t = cls
                break
        else:
            return None
        

        if not self._verify_payload(body["P"], body["sP"], body["t"]):
            raise Exception("Failed to verify payload")

        logger.debug(f"Encrypted body : {body}")

        decrypted = self._decrypt_payload(body["P"])

        try:
            return t.from_raw(decrypted, body["sP"])
        except Exception as e:
            logger.error(f"Failed to parse message : {e}")
            return None

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
        #if all([p in self.USER_CACHE for p in participants]):
        #    return
        # TODO: This doesn't work since it doesn't check if they are cached for all topics

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

            #logger.info(f"See type {resp_body['c']}")

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
        
        logger.info(f"Received SMS activation message : {act_message}")
        # Decrypt the payload
        act_message = self._decrypt_payload(act_message["P"])
        act_message = plistlib.loads(maybe_decompress(act_message))

        if act_message == {'wc': False, 'ar': True}:
            logger.info("SMS forwarding activated, sending response")
        else:
            logger.info("SMS forwarding de-activated, sending response")
        
        self._send_raw(
            147,
            [self.user.current_handle],
            "com.apple.private.alloy.sms",
            extra={
                "nr": 1
            }
        )

    def send(self, message: Message):
        # Check what type of message we are sending
        for t, (topic, cls) in MESSAGE_TYPES.items():
            if isinstance(message, cls):
                break
        else:
            raise Exception("Unknown message type")
        
        send_to = message.participants if isinstance(message, iMessage) else [self.user.current_handle]

        self._cache_keys(send_to, topic)

        self._send_raw(
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
                if t == self.connection.token:
                    continue
                total += 1

        while count < total and time.time() - start < 2:
            resp = self._receive_raw(255, topic)
            if resp is None:
                continue
            count += 1

            logger.debug(f"Received response : {resp}")

            if resp["s"] != 0:
                logger.warning(f"Message delivery to {base64.b64encode(resp['t']).decode()} failed : {resp['s']}")

        if count < total:
            logger.error(f"Unable to deliver message to all devices (got {count} of {total})")
