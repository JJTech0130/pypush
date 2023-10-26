import plistlib
from base64 import b64decode

import requests

from ._helpers import PROTOCOL_VERSION, USER_AGENT, KeyPair, parse_key, serialize_key
from .signing import add_auth_signature, armour_cert

from io import BytesIO

from cryptography.hazmat.primitives.asymmetric import ec, rsa

import logging
logger = logging.getLogger("ids")

class IDSIdentity:
    def __init__(self, signing_key: str | None = None, encryption_key: str | None = None, signing_public_key: str | None = None, encryption_public_key: str | None = None):
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
    
    @staticmethod
    def decode(inp: bytes) -> 'IDSIdentity':
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
    


import apns
from . import _helpers
import uuid
from base64 import b64encode
def register(
    push_connection: apns.APNSConnection, signing_users: list[tuple[str, _helpers.KeyPair]], user_payloads: list[dict], validation_data, device_id: uuid.UUID
):
    body = {
        # TODO: Abstract this out
        "device-name": "iPhone",
        "hardware-version": "iPhone9,4",
        "language": "en-US",
        "os-version": "iPhone OS,15.7.5,19H332",
        "software-version": "19H332",

        # "private-device-data": {
        #     "ap": "1",
        #     "c": "#c8caca",
        #     "d": "717284928.014101",
        #     "dt": 2,
        #     "ec": "#dcdede",
        #     "gt": "0",
        #     "h": "1",
        #     "ktf": "0",
        #     "m": "1",
        #     "p": "1",
        #     "pb": "19H332",
        #     "pn": "iPhone OS",
        #     "pv": "15.7.5",
        #     "s": "1",
        #     "t": "1",
        #     "u": "68DCE294-AE02-4740-8AD8-9689A1470505",
        #     "v": "1",
        # },
        "services": [
            {
                "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
                "service": "com.apple.madrid",
                "sub-services": ["com.apple.private.alloy.sms",
                                 "com.apple.private.alloy.biz",
                                 "com.apple.private.alloy.gamecenter.imessage"],
                "users": user_payloads,
            }
        ],
        "validation-data": b64decode(validation_data),
#         "validation-data": b64decode("""
# Au1sqv8fuZVdB2nCX4pVx3/s6FLDr5+bIzK+NUsMkjEhAAAA4AYAAAAAAAAAgA1uoKC3
#       E4nBdWTD+QVCDx7Xu2Ih6ds2l02C5N1c2M2kCUHV1kMquP0ZtFe+UflhXdUJgapdkiN2
#       Hn/L8GRMvfwIKZcPUUZXRFcjtE5UkwnWoTQ6pO37eDGV0ioggZJG1lv/zCEJDodB6qRB
#       nqzdprSzIgQJKurqMkBqb8oCszd/AAAAAAAAAE8BbRfGn/FGhbN4rpbN/HDJu5yXCvcA
#       AAA2CABPOkmSAuxjuaJK7fou9SkxZRCv+WrtU73TrSBnDLgZ60wRnlDQ7pHtRpFOQe99
#       Us6D/TwC
#                                      """.replace("\n", "").replace(" ", "")),

    }
    
    logger.debug(f"Sending IDS registration request: {body}")

    body = plistlib.dumps(body)

    # Construct headers
    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
    }
    for i, (user_id, keypair) in enumerate(signing_users):
        headers[f"x-auth-user-id-{i}"] = user_id
        add_auth_signature(headers, body, "id-register", keypair, _helpers.get_key_pair(push_connection.credentials), b64encode(push_connection.credentials.token).decode(), i)

    logger.debug(f"Headers: {headers}")

    r = requests.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register",
        headers=headers,
        data=body,
        verify=False,
    )
    r = plistlib.loads(r.content)

    logger.debug(f"Received response to IDS registration: {r}")

    if "status" in r and r["status"] == 6004:
        raise Exception("Validation data expired!")
    # TODO: Do validation of nested statuses
    if "status" in r and r["status"] != 0:
        raise Exception(f"Failed to register: {r}")
    if not "services" in r:
        raise Exception(f"No services in response: {r}")
    if not "users" in r["services"][0]:
        raise Exception(f"No users in response: {r}")
    
    output = {}
    for user in r["services"][0]["users"]:
        if not "cert" in user:
            raise Exception(f"No cert in response: {r}")
        for uri in user["uris"]:
            if uri["status"] != 0:
                raise Exception(f"Failed to register URI {uri['uri']}: {r}")
        output[user["user-id"]] = armour_cert(user["cert"])

    return output