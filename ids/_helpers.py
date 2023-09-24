from collections import namedtuple
import base64

USER_AGENT = "com.apple.madrid-lookup [macOS,13.2.1,22D68,MacBookPro18,3]"
PROTOCOL_VERSION = "1640"

# KeyPair is a named tuple that holds a key and a certificate in PEM form
KeyPair = namedtuple("KeyPair", ["key", "cert"])


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

def parse_encoded_compact_key(key: str):
    # Add = padding
    key = key + "=" * (4 - len(key) % 4)
    # Urlsafe base64 decode
    key = base64.urlsafe_b64decode(key)
    return parse_compact_key(key)

def parse_compact_key(key: bytes):
    # Parse as a P256 key
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Parse compressed key... need to add 0x02 prefix
    k = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x02" + key)
    # Serialize as PEM
    return serialize_key(k)

def create_compact_key():
    """
    Create a P256 keypair and return the public key as a URL-safe base64 string
    and the private key as a PEM string.
    """

    # Generate a P256 keypair
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Generate keys until we get one that is even
    key = None
    pub = None

    while True:
        key = ec.generate_private_key(ec.SECP256R1())
        pub = key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        if pub[0] == 0x02:
            pub = pub[1:]
            break

    return pub, serialize_key(key)

def compact_key(key: ec.EllipticCurvePrivateKey):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    k = key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    assert k[0] == 0x02
    return k[1:]


def create_compactable_key():
    # Generate a P256 keypair
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Generate keys until we get one that is even
    key = None

    while True:
        key = ec.generate_private_key(ec.SECP256R1())
        pub = key.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        if pub[0] == 0x02:
            break
    
    return serialize_key(key)

def create_encoded_compact_key() -> tuple[str, str]:
    pub, key = create_compact_key()
    # URL-safe base64 encode
    pub = base64.urlsafe_b64encode(pub).decode()
    # Remove padding
    pub = pub.replace("=", "")

    return pub, key