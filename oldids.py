import gzip
import plistlib
import random
import uuid
from base64 import b64decode, b64encode
from collections import namedtuple
from datetime import datetime

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import apns
import bags
import gsa

USER_AGENT = "com.apple.madrid-lookup [macOS,13.2.1,22D68,MacBookPro18,3]"
PROTOCOL_VERSION = "1640"

KeyPair = namedtuple("KeyPair", ["key", "cert"])

# global_key, global_cert = load_keys()


def _send_request(
    conn: apns.APNSConnection,
    bag_key: str,
    topic: str,
    body: bytes,
    keypair: KeyPair,
    username: str,
) -> bytes:
    #print(body)
    print(bag_key, topic, body, keypair, username)
    body = gzip.compress(body, mtime=0)

    push_token = b64encode(conn.token).decode()

    # Sign the request
    signature, nonce = _sign_payload(keypair.key, bag_key, "", push_token, body)

    headers = {
        "x-id-cert": keypair.cert.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", ""),
        "x-id-nonce": b64encode(nonce).decode(),
        "x-id-sig": signature,
        "x-push-token": push_token,
        "x-id-self-uri": "mailto:user_test2@icloud.com",
        "User-Agent": USER_AGENT,
        "x-protocol-version": "1640",
    }

    # print(headers)

    msg_id = random.randbytes(16)

    req = {
        "cT": "application/x-apple-plist",
        "U": msg_id,
        "c": 96,
        "ua": USER_AGENT,
        "u": bags.ids_bag()[bag_key],
        "h": headers,
        "v": 2,
        "b": body,
    }
    print(req)

    conn.send_message("com.apple.madrid", plistlib.dumps(req, fmt=plistlib.FMT_BINARY))
    # resp = conn.wait_for_packet(0x0A)

    def check_response(x):
        if x[0] != 0x0A:
            return False
        resp_body = apns._get_field(x[1], 3)
        if resp_body is None:
            return False
        resp_body = plistlib.loads(resp_body)
        return resp_body["U"] == msg_id

    # Lambda to check if the response is the one we want
    # conn.incoming_queue.find(check_response)
    payload = conn.incoming_queue.wait_pop_find(check_response)
    # conn._send_ack(apns._get_field(payload[1], 4))
    resp = apns._get_field(payload[1], 3)
    return plistlib.loads(resp)


# Performs an IDS lookup
# conn: an active APNs connection. must be connected and have a push token. will be filtered to the IDS topic
# self: the user's email address
# keypair: a KeyPair object containing the user's private key and certificate
# topic: the IDS topic to query
# query: a list of URIs to query
def lookup(
    conn: apns.APNSConnection, self: str, keypair: KeyPair, topic: str, query: list[str]
) -> any:
    conn.filter(["com.apple.madrid"])
    query = {"uris": query}
    resp = _send_request(conn, "id-query", topic, plistlib.dumps(query), keypair, self)
    # resp = plistlib.loads(resp)
    # print(resp)
    resp = gzip.decompress(resp["b"])
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
# Will use native Grand Slam on macOS
# If factor_gen is not None, it will be called to get the 2FA code, otherwise it will be prompted
# Returns (realm user id, auth token)
def _get_auth_token(
    username: str, password: str, factor_gen: callable = None
) -> tuple[str, str]:
    from sys import platform

    # if use_gsa:
    if platform == "darwin":
        g = gsa.authenticate(username, password, gsa.Anisette())
        pet = g["t"]["com.apple.gs.idms.pet"]["token"]
    else:
        # Make the request without the 2FA code to make the prompt appear
        _auth_token_request(username, password)
        # TODO: Make sure we actually need the second request, some rare accounts don't have 2FA
        # Now make the request with the 2FA code
        if factor_gen is None:
            pet = password + input("Enter 2FA code: ")
        else:
            pet = password + factor_gen()
    r = _auth_token_request(username, pet)
    # print(r)
    if "description" in r:
        raise Exception(f"Error: {r['description']}")
    service_data = r["delegates"]["com.apple.private.ids"]["service-data"]
    realm_user_id = service_data["realm-user-id"]
    auth_token = service_data["auth-token"]
    # print(f"Auth token for {realm_user_id}: {auth_token}")
    return realm_user_id, auth_token


def _generate_csr(private_key: rsa.RSAPrivateKey) -> str:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, random.randbytes(20).hex()),
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


# Gets an IDS auth cert for the given user id and auth token
# Returns [private key PEM, certificate PEM]
def _get_auth_cert(user_id, token) -> KeyPair:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    body = {
        "authentication-data": {"auth-token": token},
        "csr": b64decode(_generate_csr(private_key)),
        "realm-user-id": user_id,
    }

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
    cert = x509.load_der_x509_certificate(r["cert"])
    return KeyPair(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("utf-8")
        .strip(),
        cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip(),
    )


def _register_request(
    push_token, info, auth_key: KeyPair, push_key: KeyPair, validation_data
):
    body = {
        "hardware-version": "MacBookPro18,3",
        "language": "en-US",
        "os-version": "macOS,13.2.1,22D68",
        "software-version": "22D68",
        "services": [
            {
                "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
                "service": "com.apple.madrid",
                "users": [
                    {
                        # TODO: Pass ALL URIs from get handles
                        "uris": [{"uri": info["uri"]}],
                        "user-id": info["user_id"],
                    }
                ],
            }
        ],
        "validation-data": b64decode(validation_data),
    }

    body = plistlib.dumps(body)

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id-0": info["user_id"],
    }
    _add_auth_push_signatures(
        headers, body, "id-register", auth_key, push_key, push_token, 0
    )

    r = requests.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register",
        headers=headers,
        data=body,
        verify=False,
    )
    r = plistlib.loads(r.content)
    print(f'Response code: {r["status"]}')
    if "status" in r and r["status"] == 6004:
        raise Exception("Validation data expired!")
    # TODO: Do validation of nested statuses
    return r


def mini_cert(cert: str):
    return (
        cert.replace("\n", "")
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
    )


PROTOCOL_VERSION = "1640"


def _get_handles(push_token, user_id: str, auth_key: KeyPair, push_key: KeyPair):
    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id": user_id,
    }
    _add_auth_push_signatures(
        headers, None, "id-get-handles", auth_key, push_key, push_token
    )

    r = requests.get(
        "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/idsGetHandles",
        headers=headers,
        verify=False,
    )

    r = plistlib.loads(r.content)

    if not "handles" in r:
        raise Exception("No handles in response: " + str(r))

    return [handle["uri"] for handle in r["handles"]]


class IDSUser:
    def _authenticate_for_token(
        self, username: str, password: str, factor_callback: callable = None
    ):
        self.user_id, self._auth_token = _get_auth_token(
            username, password, factor_callback
        )

    def _authenticate_for_cert(self):
        self._auth_keypair = _get_auth_cert(self.user_id, self._auth_token)

    # Factor callback will be called if a 2FA code is necessary
    def __init__(
        self,
        push_connection: apns.APNSConnection,
        username: str,
        password: str,
        factor_callback: callable = None,
    ):
        self.push_connection = push_connection
        self._authenticate_for_token(username, password, factor_callback)
        self._authenticate_for_cert()
        self.handles = _get_handles(
            b64encode(self.push_connection.token),
            self.user_id,
            self._auth_keypair,
            KeyPair(self.push_connection.private_key, self.push_connection.cert),
        )

    def __str__(self):
        return f"IDSUser(user_id={self.user_id}, handles={self.handles}, push_token={b64encode(self.push_connection.token).decode()})"


def test():
    import getpass

    conn = apns.APNSConnection()
    conn.connect()
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
    user = IDSUser(conn, username, password)
    print(user)


# SIGNING STUFF

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


# Creates a payload from individual parts for signing
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
    print(push_token)
    push_token = b64decode(push_token)

    if payload is None:
        payload = b""

    return (
        nonce
        + len(bag_key).to_bytes(4, "big")
        + bag_key.encode()
        + len(query_string).to_bytes(4, "big")
        + query_string.encode()
        + len(payload).to_bytes(4, "big")
        + payload
        + len(push_token).to_bytes(4, "big")
        + push_token,
        nonce,
    )


# Returns signature, nonce
def _sign_payload(
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


# Add headers for x-push-sig and x-auth-sig stuff
def _add_auth_push_signatures(
    headers: dict,
    body: bytes,
    bag_key: str,
    auth_key: KeyPair,
    push_key: KeyPair,
    push_token: str,
    auth_number=None,
):
    push_sig, push_nonce = _sign_payload(push_key.key, bag_key, "", push_token, body)
    headers["x-push-sig"] = push_sig
    headers["x-push-nonce"] = b64encode(push_nonce)
    headers["x-push-cert"] = mini_cert(push_key.cert)
    headers["x-push-token"] = push_token

    auth_sig, auth_nonce = _sign_payload(auth_key.key, bag_key, "", push_token, body)
    auth_postfix = "-" + str(auth_number) if auth_number is not None else ""
    headers["x-auth-sig" + auth_postfix] = auth_sig
    headers["x-auth-nonce" + auth_postfix] = b64encode(auth_nonce)
    headers["x-auth-cert" + auth_postfix] = mini_cert(auth_key.cert)


if __name__ == "__main__":
    test()
