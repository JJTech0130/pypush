import requests
import plistlib
from base64 import b64encode, b64decode
from datetime import datetime
import random
from hashlib import sha1
import zlib

USER_AGENT = "com.apple.madrid-lookup [macOS,13.2.1,22D68,MacBookPro18,3]"
PUSH_TOKEN = "5V7AY+ikHr4DiSfq1W2UBa71G3FLGkpUSKTrOLg81yk="

# Nonce Format:
# 01000001876bd0a2c0e571093967fce3d7
# 01                                 # version
#   000001876d008cc5                 # unix time
#                   r1r2r3r4r5r6r7r8 # random bytes
def generate_nonce() -> bytes:
    return b"\x01" + int(datetime.now().timestamp() * 1000).to_bytes(8, "big") + random.randbytes(8)

def load_keys() -> tuple[str, str]:
    # Load the private key and certificate from files
    with open("ids.key", "r") as f:
        ids_key = f.read()
    with open("ids.crt", "r") as f:
        ids_cert = f.read()

    return ids_key, ids_cert

def _create_payload(bag_key: str, query_string: str, push_token: str, payload: bytes) -> tuple[str, bytes]:
    # Generate the nonce
    nonce = generate_nonce()
    push_token = b64decode(push_token)

    return nonce + len(bag_key).to_bytes(4) + bag_key.encode() + len(query_string).to_bytes(4) + query_string.encode() + len(payload).to_bytes(4) + payload + len(push_token).to_bytes(4) + push_token, nonce


def sign_payload(private_key: str, bag_key: str, query_string: str, push_token: str, payload: bytes) -> tuple[str, bytes]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import utils

    # Load the private key
    key = serialization.load_pem_private_key(private_key.encode(), password=None, backend=default_backend())

    payload, nonce = _create_payload(bag_key, query_string, push_token, payload)
    sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA1())

    sig = b"\x01\x01" + sig
    sig = b64encode(sig).decode()

    return sig, nonce

body = {'uris': ['mailto:jjtech@jjtech.dev']}
body = plistlib.dumps(body)
body = zlib.compress(body, wbits=16 + zlib.MAX_WBITS)

key, cert = load_keys()
signature, nonce = sign_payload(key, 'id-query', '', PUSH_TOKEN, body)

headers = {
    'x-id-cert': cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\n", ""),
    'x-id-nonce': b64encode(nonce).decode(),
    'x-id-sig': signature,
    'x-push-token': PUSH_TOKEN,
    'x-id-self-uri': 'mailto:jjtech@jjtech.dev',
    'User-Agent': USER_AGENT,
    'x-protocol-version': '1630',
}

# We have to send it over APNs
import apns

conn1 = apns.APNSConnection()
conn1.connect()
conn1.keep_alive()
conn1.set_state(0x01)
conn1.filter([])
conn1.connect(False)
conn1.filter(["com.apple.madrid"])
print(conn1.token)

to_send = {'cT': 'application/x-apple-plist',
 'U': b'\x16%D\xd5\xcd:D1\xa1\xa7z6\xa9\xe2\xbc\x8f', # Just random bytes?
 'c': 96,
 'ua': '[macOS,13.2.1,22D68,MacBookPro18,3]',
 'u': 'https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query',
 'h': headers,
 'v': 2, # breaks lookup
 'b': body
}

conn1.send_message("com.apple.madrid", plistlib.dumps(to_send, fmt=plistlib.FMT_BINARY))

response = conn1.wait_for_packet(0x0a)

response = apns._get_field(response[1], 3)

response = plistlib.loads(response)

print(f"Status code: {response['hs']}")

body = response['b']
body = zlib.decompress(body, 16 + zlib.MAX_WBITS)
body = plistlib.loads(body)

print(f"Body: {body}")