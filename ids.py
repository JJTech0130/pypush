import plistlib
import random
import uuid
import zlib
from base64 import b64decode, b64encode
from datetime import datetime

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import apns
import bags
import gsa

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
    bag_key: str,
    query_string: str,
    push_token: str,
    payload: bytes,
    nonce: bytes = None,
) -> tuple[str, bytes]:
    # Generate the nonce
    if nonce is None:
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


# global_key, global_cert = load_keys()


def _send_request(conn: apns.APNSConnection, bag_key: str, body: bytes) -> bytes:
    body = zlib.compress(body, wbits=16 + zlib.MAX_WBITS)

    # Sign the request
    signature, nonce = sign_payload(global_key, bag_key, "", PUSH_TOKEN, body)

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
        "u": bags.ids_bag()[bag_key],
        "h": headers,
        "v": 2,
        "b": body,
    }

    conn.send_message("com.apple.madrid", plistlib.dumps(req, fmt=plistlib.FMT_BINARY))
    resp = conn.wait_for_packet(0x0A)

    resp_body = apns._get_field(resp[1], 3)

    if resp_body is None:
        raise (Exception(f"Got invalid response: {resp}"))

    return resp_body


def lookup(conn: apns.APNSConnection, query: list[str]) -> any:
    query = {"uris": query}
    resp = _send_request(conn, "id-query", plistlib.dumps(query))
    resp = plistlib.loads(resp)
    resp = zlib.decompress(resp["b"], 16 + zlib.MAX_WBITS)
    resp = plistlib.loads(resp)
    return resp


def _auth_token_request(username: str, password: str) -> any:
    # Turn the PET into an auth token
    data = {
        "apple-id": username,
        "client-id": str(uuid.uuid4()),
        "delegates": {"com.apple.private.ids": {"protocol-version": "4"}},
        "password": password,
    }
    data = plistlib.dumps(data)

    r = requests.post(
        "https://setup.icloud.com/setup/prefpane/loginDelegates",
        auth=(username, password),
        data=data,
        verify=False,
    )
    r = plistlib.loads(r.content)
    return r

# Gets an IDS auth token for the given username and password
# If use_gsa is True, GSA authentication will be used, which requires anisette
# If use_gsa is False, it will use a old style 2FA code
# If factor_gen is not None, it will be called to get the 2FA code, otherwise it will be prompted
# Returns (realm user id, auth token)
def _get_auth_token(username: str, password: str, use_gsa: bool = False, factor_gen: callable = None) -> tuple[str, str]:
    if use_gsa:
        g = gsa.authenticate(username, password, gsa.Anisette())
        pet = g["t"]["com.apple.gs.idms.pet"]["token"]
    else:
        # Make the request without the 2FA code to make the prompt appear
        _auth_token_request(username, password)
        # Now make the request with the 2FA code
        if factor_gen is None:
            pet = password + input("Enter 2FA code: ")
        else:
            pet = password + factor_gen()
    r = _auth_token_request(username, pet)
    #print(r)
    if 'description' in r:
        raise Exception(f"Error: {r['description']}")
    service_data = r["delegates"]["com.apple.private.ids"]["service-data"]
    realm_user_id = service_data["realm-user-id"]
    auth_token = service_data["auth-token"]
    # print(f"Auth token for {realm_user_id}: {auth_token}")
    return realm_user_id, auth_token

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


def _generate_csr(private_key: rsa.RSAPrivateKey) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(
                        NameOID.COMMON_NAME, random.randbytes(20).hex()
                    ),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )

    csr = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return (
        csr.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
        .replace("-----END CERTIFICATE REQUEST-----", "")
        .replace("\n", "")
    )


def _get_auth_cert(user_id, token) -> str:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    body = {
        "authentication-data": {"auth-token": token},
        "csr": b64decode(_generate_csr(private_key)),
        "realm-user-id": user_id,
    }

    #print(body["csr"])

    body = plistlib.dumps(body)

    r = requests.post(
        "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS",
        data=body,
        headers={"x-protocol-version": "1630"},
        verify=False,
    )
    r = plistlib.loads(r.content)
    if r["status"] != 0:
        raise (Exception(f"Failed to get auth cert: {r}"))
    return b64encode(r["cert"]).decode()


def test():
    import getpass
    # Prompt for username
    username = input("Enter iCloud username: ")
    # Prompt for password
    password = getpass.getpass("Enter iCloud password: ")
    def factor_gen():
        return input("Enter iCloud 2FA code: ")
    user_id, token = _get_auth_token(username, password, use_gsa=False, factor_gen=factor_gen)
    cert = _get_auth_cert(user_id, token)
    print(cert)


if __name__ == "__main__":
    test()
