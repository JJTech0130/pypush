import plistlib
from base64 import b64decode

import requests

from ._helpers import PROTOCOL_VERSION, KeyPair, parse_key, serialize_key
from .signing import add_auth_signature, armour_cert

from io import BytesIO

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from typing import Self

import logging
logger = logging.getLogger("ids")

class IDSIdentity:
    def __init__(
		self,
		signing_key: str | None = None,
		encryption_key: str | None = None,
		signing_public_key: str | None = None,
		encryption_public_key: str | None = None
	):
        if signing_key is not None:
            self.signing_key = signing_key
            self.signing_public_key = serialize_key(parse_key(signing_key).public_key())# type: ignore
        elif signing_public_key is not None:
            self.signing_key = None
            self.signing_public_key = signing_public_key
        else:
            # Generate a new key
            self.signing_key = serialize_key(ec.generate_private_key(ec.SECP256R1()))
            self.signing_public_key = serialize_key(parse_key(self.signing_key).public_key())# type: ignore

        if encryption_key is not None:
            self.encryption_key = encryption_key
            self.encryption_public_key = serialize_key(parse_key(encryption_key).public_key())# type: ignore
        elif encryption_public_key is not None:
            self.encryption_key = None
            self.encryption_public_key = encryption_public_key
        else:
            self.encryption_key = serialize_key(rsa.generate_private_key(65537, 1280))
            self.encryption_public_key = serialize_key(parse_key(self.encryption_key).public_key())# type: ignore

    @classmethod
    def decode(cls, inp: bytes) -> Self:
        input = BytesIO(inp)

        assert input.read(5) == b'\x30\x81\xF6\x81\x43' # DER header
        raw_ecdsa = input.read(67)
        assert input.read(3) == b'\x82\x81\xAE' # DER header
        raw_rsa = input.read(174)

        # Parse the RSA key
        raw_rsa = BytesIO(raw_rsa)
        assert raw_rsa.read(2) == b'\x00\xAC' # Not sure what this is
        assert raw_rsa.read(3) == b'\x30\x81\xA9' # Inner DER header
        assert raw_rsa.read(3) == b'\x02\x81\xA1'
        rsa_modulus = raw_rsa.read(161)
        rsa_modulus = int.from_bytes(rsa_modulus, "big")
        assert raw_rsa.read(5) == b'\x02\x03\x01\x00\x01' # Exponent, should always be 65537

        # Parse the EC key
        assert raw_ecdsa[:3] == b'\x00\x41\x04'
        raw_ecdsa = raw_ecdsa[3:]
        ec_x = int.from_bytes(raw_ecdsa[:32], "big")
        ec_y = int.from_bytes(raw_ecdsa[32:], "big")

        ec_key = ec.EllipticCurvePublicNumbers(ec_x, ec_y, ec.SECP256R1())
        ec_key = ec_key.public_key()

        rsa_key = rsa.RSAPublicNumbers(e=65537, n=rsa_modulus)
        rsa_key = rsa_key.public_key()

        return IDSIdentity(signing_public_key=serialize_key(ec_key), encryption_public_key=serialize_key(rsa_key))


    def encode(self) -> bytes:
        output = BytesIO()

        raw_rsa = BytesIO()
        raw_rsa.write(b'\x00\xAC')
        raw_rsa.write(b'\x30\x81\xA9')
        raw_rsa.write(b'\x02\x81\xA1')
        raw_rsa.write(parse_key(self.encryption_public_key).public_numbers().n.to_bytes(161, "big")) # type: ignore
        raw_rsa.write(b'\x02\x03\x01\x00\x01') # Hardcode the exponent

        output.write(b'\x30\x81\xF6\x81\x43')
        output.write(b'\x00\x41\x04')
        output.write(parse_key(self.signing_public_key).public_numbers().x.to_bytes(32, "big"))# type: ignore
        output.write(parse_key(self.signing_public_key).public_numbers().y.to_bytes(32, "big"))# type: ignore

        output.write(b'\x82\x81\xAE')
        output.write(raw_rsa.getvalue())

        return output.getvalue()

def register(
    push_token, handles, user_id, auth_key: KeyPair, push_key: KeyPair, identity: IDSIdentity, validation_data
):
    logger.debug(f"Registering IDS identity for {handles}")
    uris = [{"uri": handle} for handle in handles]
    import uuid
    body = {
        "device-name": "pypush",
        "hardware-version": "MacBookPro18,3",
        "language": "en-US",
        "os-version": "macOS,13.2.1,22D68",
        "software-version": "22D68",
        "private-device-data": {
            "u": uuid.uuid4().hex.upper(),
        },
        "services": [
            {
                "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
                "service": "com.apple.madrid",
                "sub-services": ["com.apple.private.alloy.sms",
                                 "com.apple.private.alloy.gelato",
                                 "com.apple.private.alloy.biz",
                                 "com.apple.private.alloy.gamecenter.imessage"],
                "users": [
                    {
                        "client-data": {
                            'is-c2k-equipment': True,
						    'optionally-receive-typing-indicators': True,
						    'public-message-identity-key': identity.encode(),
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
                        },
                        "uris": uris,
                        "user-id": user_id,
                    }
                ],
            },
            {
                "client-data": {
                    "supports-ack-v1": True,
                    "public-message-identity-key": identity.encode(),
                    "supports-update-attachments-v1": True,
                    "supports-keep-receipts": True,
                    "supports-people-request-messages-v2": True,
                    "supports-people-request-messages-v3": True,
                    "supports-impact-v1": True,
                    "supports-rem": True,
                    "nicknames-version": 1.0,
                    "ec-version": 1.0,
                    "supports-animoji-v2": True,
                    "supports-ii-v1": True,
                    "optionally-receive-typing-indicators": True,
                    "supports-inline-attachments": True,
                    "supports-people-request-messages": True,
                    "supports-cross-platform-sharing": True,
                    "public-message-ngm-device-prekey-data-key": b"\n \xb4\\\x15\x8e\xa4\xc8\xe5\x07\x98\tp\xd0\xa4^\x84k\x05#Ep\xa9*\xcd\xadt\xf5\xb0\xfb\xa6_ho\x12@\xe3\xf5\xcaOwh\xfd\xb9\xecD\t\x0e\x9e\xb8\xb0\xa1\x1c=\x92\x9dD/lmL\xde.\\o\xeb\x15>\x9f\xae\xd9\xf9\xd1\x9c*\x8dU\xe0\xd2\xdeo\xb2\xcb\xd8\xf8i\xd4\xd0a^\t!\x0fa\xb2\xddI\xfc_*\x19\xb2\xf0#\x12\xe0@\xd9A",
                    "supports-original-timestamp-v1": True,
                    "supports-sa-v1": True,
                    "supports-photos-extension-v2": True,
                    "supports-photos-extension-v1": True,
                    "prefers-sdr": False,
                    "supports-fsm-v1": True,
                    "supports-fsm-v3": True,
                    "supports-fsm-v2": True,
                    "supports-shared-exp": True,
                    "supports-location-sharing": True,
                    "device-key-signature": b'0c\x04\x14\x1d\xb02~\xefk&\xf8\r;R\xa4\x95c~\x8a\x90H\x85\xb0\x02\x01\x01\x04H0F\x02!\x00\xa7\x08\xf5"z.3/\xbe\xea\x8c\xce\x8dD\xb6\xf0v\xd0\x030\xac\xd1\xde\x88\x89q\x9ej\x1bJR\xce\x02!\x00\xb8^\xd9\x97`\x19|\xa8\x1d\\\xf9E\x1a`<0\x00\xab\x94\x0bs\xed\x8b\xc4h\xcb\r\x91\xdb\xb0W\xdc',
                    "supports-st-v1": True,
                    "supports-ca-v1": True,
                    "supports-protobuf-payload-data-v2": True,
                    "supports-hdr": True,
                    "supports-media-v2": True,
                    "supports-be-v1": True,
                    "public-message-identity-version": 2.0,
                    "supports-heif": True,
                    "supports-certified-delivery-v1": True,
                    "supports-autoloopvideo-v1": True,
                    "supports-dq-nr": True,
                    "public-message-identity-ngm-version": 12.0,
                    "supports-audio-messaging-v2": True,
                },
                "kt-loggable-data": b'\n"\n \rl\xbe\xca\xf7\xe8\xb2\x89k\x18\x1e\xb9,d\xf8\xe2\n\xbf\x8d\xe1E\xd6\xf3T\xcb\xd9\x99d\xd1mk\xeb\x10\x0c\x18\x05"E\x08\x01\x12A\x04\xe3\xe7Y.zW\x0f\x9d\x95\xc2\xc5\xd9\x9eC\x05\xa0\x95.\xa9DW\xa9\xfb\xa9\xaa\x1a\x868\x0e\xee\xe6\x8f%\x12\xa3\r\x01\xe1\xbb\x97M\x9a\x19\x16\x94D\xcdv\xeb\xefem?\xb3\xefzM#~a\x92\x0fO\xab',
                "kt-mismatch-account-flag": True,
            },
        ],
        "validation-data": b64decode(validation_data),
    }

    body = plistlib.dumps(body)

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id-0": user_id,
    }
    add_auth_signature(headers, body, "id-register", auth_key, push_key, push_token, 0)

    r = requests.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register",
        headers=headers,
        data=body,
        verify=False,
    )
    r = plistlib.loads(r.content)
    #print(f'Response code: {r["status"]}')
    logger.debug(f"Recieved response to IDS registration: {r}")
    if "status" in r and r["status"] == 6004:
        raise Exception("Validation data expired!")
    # TODO: Do validation of nested statuses
    if "status" in r and r["status"] != 0:
        raise Exception(f"Failed to register: {r}")
    if not "services" in r:
        raise Exception(f"No services in response: {r}")
    if not "users" in r["services"][0]:
        raise Exception(f"No users in response: {r}")
    if not "cert" in r["services"][0]["users"][0]:
        raise Exception(f"No cert in response: {r}")

    return armour_cert(r["services"][0]["users"][0]["cert"])
