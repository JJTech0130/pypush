from ids import IDSUser
import logging
logger = logging.getLogger("ids")
import plistlib
from ids._helpers import PROTOCOL_VERSION, KeyPair, parse_key, serialize_key
from ids.signing import add_auth_signature, armour_cert, add_id_signature, add_push_signature
import requests
import base64 
import time

TEST_TOPICS = ["com.apple.ess",
                "com.apple.private.alloy.facetime.video",
                "com.apple.private.alloy.facetime.sync",
                "com.apple.private.alloy.facetime.lp",
                "com.apple.private.alloy.facetime.mw",
                "com.apple.private.alloy.facetime.multi",
                "com.apple.ids"
                ]
async def provision_alias(user: IDSUser):
    logger.debug(f"Adding new temp alias")
    body = {
        "attributes": {
            "allowedServices": {
                "com.apple.private.alloy.facetime.multi": []
            },
            # Unix timestamp in seconds, with decimal places, for 1 year from now
            "expiry-epoch-seconds": time.time() + 31536000,
            "featureId": "Gondola"
        },
        "operation": "create"
    }
    body = plistlib.dumps(body)

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-id-self-uri": user.current_handle,
    }
    add_push_signature(headers, body, "id-provision-alias", user._push_keypair, base64.b64encode(user.push_connection.credentials.token))
    # Create ID keypair with facetime cert
    keypair = KeyPair(
        user._id_keypair.key,
        user._facetime_cert,
    )
    add_id_signature(headers, body, "id-provision-alias", keypair, base64.b64encode(user.push_connection.credentials.token))

    r = requests.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/provisionAlias",
        headers=headers,
        data=body,
        verify=False,
    )
    r = plistlib.loads(r.content)

    print(r)
    alias = r["alias"]
    # remove pseud: prefix
    alias = alias[6:]
    # link

    pub, key = create_key()
    print(f"https://facetime.apple.com/join#v=1&p={alias}&k={pub}")
    print(key)

   # print(await user.lookup(["mailto:jjtech@jjtech.dev"]))

    #print(await user.lookup([f"pseud:{alias}"], "com.apple.private.alloy.facetime.multi", KeyPair(user._auth_keypair.key, user._facetime_cert)))

def parse_key(key: str):
    # Add = padding
    key = key + "=" * (4 - len(key) % 4)
    # Urlsafe base64 decode
    key = base64.urlsafe_b64decode(key)
    print(key.hex())
    # Parse as a P256 key
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    # Parse compressed key... need to add 0x02 prefix
    k = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x02" + key)
    # Serialize as PEM
    k = k.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    print(k.decode())

def create_key() -> tuple[str, str]:
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

    # URL-safe base64 encode
    pub = base64.urlsafe_b64encode(pub).decode()
    # Remove padding
    pub = pub.replace("=", "")

    # Turn private key into PEM for convenience
    return pub, serialize_key(key)

