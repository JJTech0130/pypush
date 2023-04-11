import plistlib
import random
import zlib
from base64 import b64decode, b64encode
from datetime import datetime

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import apns

USER_AGENT = "com.apple.madrid-lookup [macOS,13.2.1,22D68,MacBookPro18,3]"
# NOTE: The push token MUST be registered with the account for self-uri!
# This is an actual valid one for my account, since you can look it up anyway.
PUSH_TOKEN = "5V7AY+ikHr4DiSfq1W2UBa71G3FLGkpUSKTrOLg81yk="
SELF_URI = "mailto:jjtech@jjtech.dev"


# Nonce Format:
# 01000001876bd0a2c0e571093967fce3d7
# 01                                 # version
#   000001876d008cc5                 # unix time
#                   r1r2r3r4r5r6r7r8 # random bytes
def generate_nonce() -> bytes:
    return (
        b"\x01"
        + int(datetime.now().timestamp() * 1000).to_bytes(8, "big")
        + random.randbytes(8)
    )


def load_keys() -> tuple[str, str]:
    # Load the private key and certificate from files
    with open("ids.key", "r") as f:
        ids_key = f.read()
    with open("ids.crt", "r") as f:
        ids_cert = f.read()

    return ids_key, ids_cert


def _create_payload(
    bag_key: str, query_string: str, push_token: str, payload: bytes
) -> tuple[str, bytes]:
    # Generate the nonce
    nonce = generate_nonce()
    push_token = b64decode(push_token)

    return (
        nonce
        + len(bag_key).to_bytes(4)
        + bag_key.encode()
        + len(query_string).to_bytes(4)
        + query_string.encode()
        + len(payload).to_bytes(4)
        + payload
        + len(push_token).to_bytes(4)
        + push_token,
        nonce,
    )


def sign_payload(
    private_key: str, bag_key: str, query_string: str, push_token: str, payload: bytes
) -> tuple[str, bytes]:
    # Load the private key
    key = serialization.load_pem_private_key(
        private_key.encode(), password=None, backend=default_backend()
    )

    payload, nonce = _create_payload(bag_key, query_string, push_token, payload)
    sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA1())

    sig = b"\x01\x01" + sig
    sig = b64encode(sig).decode()

    return sig, nonce


BAG_KEYS = {
    "id-query": "https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query"
}

global_key, global_cert = load_keys()


def _send_request(conn: apns.APNSConnection, type: str, body: bytes) -> bytes:
    body = zlib.compress(body, wbits=16 + zlib.MAX_WBITS)

    # Sign the request
    signature, nonce = sign_payload(global_key, type, "", PUSH_TOKEN, body)

    print(signature)

    headers = {
        "x-id-cert": global_cert.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", ""),
        "x-id-nonce": b64encode(nonce).decode(),
        "x-id-sig": signature,
        "x-push-token": PUSH_TOKEN,
        "x-id-self-uri": SELF_URI,
        "User-Agent": USER_AGENT,
        "x-protocol-version": "1630",
    }

    req = {
        "cT": "application/x-apple-plist",
        "U": b"\x16%D\xd5\xcd:D1\xa1\xa7z6\xa9\xe2\xbc\x8f",  # Just random bytes?
        "c": 96,
        "ua": USER_AGENT,
        "u": BAG_KEYS[type],
        "h": headers,
        "v": 2,
        "b": body,
    }

    conn.send_message("com.apple.madrid", plistlib.dumps(req, fmt=plistlib.FMT_BINARY))
    resp = conn.wait_for_packet(0x0A)

    resp2 = apns._get_field(resp[1], 3)

    if resp2 is None:
        print(f"Got invalid response: {resp}")

    return resp2


def lookup(conn: apns.APNSConnection, query: list[str]) -> any:
    query = {"uris": query}
    resp = _send_request(conn, "id-query", plistlib.dumps(query))
    resp = plistlib.loads(resp)
    resp = zlib.decompress(resp["b"], 16 + zlib.MAX_WBITS)
    resp = plistlib.loads(resp)
    return resp
