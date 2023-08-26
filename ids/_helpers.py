from collections import namedtuple

USER_AGENT = "com.apple.madrid-lookup [macOS,13.2.1,22D68,MacBookPro18,3]"
PROTOCOL_VERSION = "1640"


# KeyPair is a named tuple that holds a key and a certificate in PEM form
KeyPair = namedtuple("KeyPair", ["key", "cert"])

import apns

def get_key_pair(creds: apns.PushCredentials):
    return KeyPair(creds.private_key, creds.cert)

def recursive_del_none(d: dict | list):
    if isinstance(d, dict):
        for k, v in list(d.items()):
            if v is None:
                del d[k]
            else:
                recursive_del_none(v)
    elif isinstance(d, list):
        for i, v in enumerate(d):
            if v is None:
                del d[i]
            else:
                recursive_del_none(v)

#apns.PushCredentials.key_pair = get_key_pair # tydpe: ignore # Monkey patching


def dearmour(armoured: str) -> str:
    import re

    # Use a regex to remove the header and footer (generic so it work on more than just certificates)
    return re.sub(r"-----BEGIN .*-----|-----END .*-----", "", armoured).replace(
        "\n", ""
    )

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
def parse_key(key: str):
    # Check if it is a public or private key
    if "PUBLIC" in key:
        return serialization.load_pem_public_key(key.encode())
    else:
        return serialization.load_pem_private_key(key.encode(), None)

def serialize_key(key) -> str:
    if isinstance(key, ec.EllipticCurvePrivateKey) or isinstance(key, rsa.RSAPrivateKey):
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8").strip()
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8").strip()
    