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
def _get_auth_token(
    username: str, password: str, use_gsa: bool = False, factor_gen: callable = None
) -> tuple[str, str]:
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
    # print(r)
    if "description" in r:
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
def _get_auth_cert(user_id, token) -> tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    body = {
        "authentication-data": {"auth-token": token},
        "csr": b64decode(_generate_csr(private_key)),
        "realm-user-id": user_id,
    }

    # print(body["csr"])

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
    # return b64encode(r["cert"]).decode()
    # cert = x509.load_pem_x509_certificate(b64encode(r["cert"]).decode())
    cert = x509.load_der_x509_certificate(r["cert"])
    # cert = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("utf-8")
        .strip(),
        cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip(),
    )


def _register_request(push_token, user_id, auth_cert, auth_key, push_cert, push_key):
    # body = {'device-name': 'Test'}
    body = {
        "device-name": "James’s Laptop",
        "hardware-version": "MacBookPro18,3",
        "language": "en-US",
        "os-version": "macOS,13.2.1,22D68",
        # "private-device-data": {
        #     "ap": "0",
        #     "d": "703987510.082306",
        #     "dt": 1,
        #     "gt": "0",
        #     "h": "1",
        #     "ktf": "0",
        #     "ktv": 54,
        #     "m": "0",
        #     "p": "0",
        #     "pb": "22D68",
        #     "pn": "macOS",
        #     "pv": "13.2.1",
        #     "s": "0",
        #     "t": "0",
        #     "u": "E451BD65-51B0-44F3-805A-A92BDD8A5000",
        #     "v": "1",
        # },
        "retry-count": 0,
        "services": [
            {
                "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
                "service": "com.apple.madrid",
                # "sub-services": [
                # "com.apple.private.alloy.gelato",
                # "com.apple.private.alloy.gamecenter.imessage",
                # "com.apple.private.alloy.sms",
                # "com.apple.private.alloy.biz",
                # ],
                "users": [
                    # {
                    #     "client-data": {
                    #         "ec-version": 1,
                    #         "kt-version": 5,
                    #         "nicknames-version": 1,
                    #         "optionally-receive-typing-indicators": True,
                    #         "prefers-sdr": False,
                    #         "public-message-identity-key": b"0\x81\xf6\x81C\x00A\x04\x87\x1e\xeb\xe4u\x0b\xa3\x9e\x9c\xbc\xf8rK\x1e\xfe44%f$\x1d\xe8\xbb\xc6\xbdCD\x9ckv K\xc1\x1e\xb1\xdf4\xc8S6\x0f\x92\xd0=\x1e\x84\x9c\xc5\xa5\xb6\xb7}\xdd\xec\x1e\x1e\xd8Q\xd8\xca\xdb\x07'\xc7\x82\x81\xae\x00\xac0\x81\xa9\x02\x81\xa1\x00\xa8 \xfc\x9f\xa6\xb0V2\xce\x1c\xa7\x13\x9e\x03\xd1\xd8\x97a\xbb\xdd\xac\x86\xb8\x10(\x89\x13QP\x8f\xf0+EP\xd1\xb06\xee\x94\xcd\xa8\x9e\xf1\xedp\xa4\x9726\x1e\xe9\xab\xd4\xcb\xac\x05\xd7\x8c?\xbb\xa2\xde,\xfe\r\x1a\xb9\x88W@\x99\xec\xa0]\r\x1a>dV\xb2@\xc5P\xf3m\x80y\xf5\xa0G\xae\xd8h\x92\xef\xca\x85\xcbB\xed\xa9W\x8c\x13\xd4O\xdbYI2\xdcM\x1f\xf6c\x17\x1c\xd1v\xdd\xbcc\xac,&V\xfd\x07\xa0\xc3\x9f\x00\x1f\xc6\xe4\x02u\x12p\x8f\xe2\xb0\x14\xfai\x12\xbb\xa6\x9a6Q\xa5\xde+\x9e{\xcf\xc8\x1b}\x02\x03\x01\x00\x01",
                    #         "public-message-identity-ngm-version": 12,
                    #         "public-message-identity-version": 2,
                    #         "public-message-ngm-device-prekey-data-key": b"\n v\xd6=#\xb7\xde\xe9~n\xdd\x94|xw\x1c#W\xa5\xe0\xf3\x15\xed\xd1\xa0\xab\xa8\xfd\xa9\x8c\xdd\x16\xb0\x12@x\xb4\xafE\xc4\x1b\xcd\xe9\xb1\x8f\x8aI\x03\xd2&F\x95\x9b\x99R\x92\x07/\x12\xaeM\x10\xf3\xa2u\x7f5]\xd9\x19\xc3\x91\xb5\xb4\xbdO\x9c\x1f\r\xae\xa9\xf3+\x9c\x00M2\x83\x147\xb3X\xa11\x00\xaeV\xbe_\x19\x10\xafg\x19\xbf\x10\xd9A",
                    #         "supports-ack-v1": True,
                    #         "supports-animoji-v2": True,
                    #         "supports-audio-messaging-v2": True,
                    #         "supports-autoloopvideo-v1": True,
                    #         "supports-be-v1": True,
                    #         "supports-ca-v1": True,
                    #         "supports-certified-delivery-v1": True,
                    #         "supports-cross-platform-sharing": True,
                    #         "supports-dq-nr": True,
                    #         "supports-fsm-v1": True,
                    #         "supports-fsm-v2": True,
                    #         "supports-fsm-v3": True,
                    #         "supports-hdr": True,
                    #         "supports-heif": True,
                    #         "supports-ii-v1": True,
                    #         "supports-impact-v1": True,
                    #         "supports-inline-attachments": True,
                    #         "supports-keep-receipts": True,
                    #         "supports-location-sharing": True,
                    #         "supports-media-v2": True,
                    #         "supports-original-timestamp-v1": True,
                    #         "supports-people-request-messages": True,
                    #         "supports-people-request-messages-v2": True,
                    #         "supports-photos-extension-v1": True,
                    #         "supports-photos-extension-v2": True,
                    #         "supports-protobuf-payload-data-v2": True,
                    #         "supports-rem": True,
                    #         "supports-sa-v1": True,
                    #         "supports-st-v1": True,
                    #         "supports-update-attachments-v1": True,
                    #     },
                    #     #"kt-loggable-data": b'\n"\n \rl\xbe\xca\xf7\xe8\xb2\x89k\x18\x1e\xb9,d\xf8\xe2\n\xbf\x8d\xe1E\xd6\xf3T\xcb\xd9\x99d\xd1mk\xeb\x10\x0c\x18\x05"E\x08\x01\x12A\x04\x99\x16\xc3\xd8\x85\x80qPr\xbf\x0c\xdb\x9f\x1bHK\xb2:)\x01\x88\x91\xb1\x08do\xf3\x16\xc7\xaa\xd3nb\xddQF\x8f\xb2a\xb1\xbbK\xdf\xd0\xfa\x95\xa29XZ\xcaRh\xbex\xc4f\xe6G`\x1f\xf2\xf3[',
                    #     "uris": [{"uri": "mailto:user_test2@icloud.com"}],
                    #     "user-id": "D:20994360971",
                    # }
                ],
            }
        ],
        "software-version": "22D68",
        # "validation-data": b"v\x02V`\xd8N\xf3V\xb0\xc4'=\x137+\x16-o\x1d\x00\x1c\xf53\xe0g\xd9\x83x\xe0\xderh\xa0\xc7\x00\x00\x01\xe0\x07\x00\x00\x00\x01\x00\x00\x01\x806\x81<\xb9G\xf0,(CQX\xc5\x1e\xbc\xfe}a\xf7y\xfcg\xa1j/B\xb6k\xf4\xeey\x7f=e\xe6\xea\xa3\xfd\xb2\x18\x8e.\x19\x9e'\x9eO]\xca\xe3{\x9f\x10I\x94\x1a\xe0\xef>\xce\x9dl\xb0\xb2u\x88KT\x0b\xcc\x915\x92\xd3\x86\x1b\xb3\xe5\x04\x9f\x8d\x8a\x82$\x11\xfb\xf2t\xda&\x96@U<lP\"/\xf6->\xec\x84\x13\xe7p\xffS\x02\xde\x8c\xdd\xfcqA\x14!\xa4\x07\x82\xd0\x9fm\xe9~\xc4\xcf\x96\xd6D\xa3\xf0\xb9\xa7\xa2}\xc5\x0e.\x0fvYz\x07\xc2\x9f$s:\xd4<\x13u]\x06f[\xcd\x95\xd1\xad\xe9\xb3\xb3\x9f|\nh-\xa2\xa6\xb9c\xa1\x8d\xf2gx\x84\xbe\x1d\xc4\x03}^\xbf\x9ck#\xa8\xad\xa5\x87\x04\x88D\xd0\xee>\x9f\x0f\xa63;\x7fE\x14\x89\x1c]\x8b\x13o\xbd\xf6\x84`R\xa2\xb7Z\xcc\xdf+\xc5\xe5>\xf73?\x84\xe2d\x97\xd3\x07\x10V\xb6\xb4\nB7\xfc\x8bReeA\x15t\x94\xcf\xa8\x957\x1f\x1d>\xe1\xa4\xc5X\xb0!\x81\xcah\x11.'$\xf6\x12\xb3`\xe9\xa93\x07\xe4}\x02\xee\x95hW\xb7\xfb '_\xafC.\xdd\x13\x8df\xcf(H\x06\x18\xe2\xe7\xce\x93+\xf9\xe0\xf5\x17r\xb5.g2M\x8a\xb7\x80j\xb3\x00*\xa6Z\x1f\x07\xf3\x82\xcfj\xd2R\xc1%\xcc\xbe\x10\x9c\xb4qp\x1f\xd7W\x8c\x1aL2\xfa\xeb\x01s\x01m\xa3$\x9cJ\xf8X?\x99r`pT\xa7\xa6\x80\xcc\xc0\x97\xb3|[%\xc8Usj\x1d\x00\x00\x00\x00\x00\x00\x00O\x01P\xdc\"\x98\xc3\xd9\xb5\xbaK\xdc.\xeb\x81\x87r\x8d\xa4q^\xcb\x00\x00\x006\t\x01\x92\x91\x8fI\xff\xff\xd5g\xf2\x1d\x04G\xf4_\xe4\x90dE\xc7\xb7\xcaO~V\x1e[\x7ff?e|d\xae\xb8\x92(F\xd1_\xe9\xb2\x9e\xb0\xf1\x99\x92\x07\xf8\xb2&I\xed",
        "validation-data": random.randbytes(10),
    }

    body = plistlib.dumps(body)
    body = zlib.compress(body, wbits=16 + zlib.MAX_WBITS)

    push_sig, push_nonce = sign_payload(push_key, "id-register", "", push_token, body)
    auth_sig, auth_nonce = sign_payload(auth_key, "id-register", "", push_token, body)

    headers = {
        "x-protocol-version": "1640",
        "content-type": "application/x-apple-plist",
        "content-encoding": "gzip",
        "x-auth-sig-0": auth_sig,
        "x-auth-cert-0": auth_cert.replace("\n", "")
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", ""),
        "x-auth-user-id-0": user_id,
        "x-auth-nonce-0": b64encode(auth_nonce),
        "x-pr-nonce": b64encode(auth_nonce),
        "x-push-token": push_token,
        "x-push-sig": push_sig,
        "x-push-cert": push_cert.replace("\n", "")
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", ""),
        "x-push-nonce": b64encode(push_nonce),
    }

    # headers.update(gsa.Anisette().generate_headers())

    r = requests.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register",
        headers=headers,
        data=body,
        verify=False,
    )
    print(r.text)


def test():
    import getpass
    import json

    # Open config as read and write

    try:
        with open("config.json", "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        config = {}

    # If no username is set, prompt for it
    if "username" not in config:
        config["username"] = input("Enter iCloud username: ")
    # If no password is set, prompt for it
    if "password" not in config:
        config["password"] = getpass.getpass("Enter iCloud password: ")
    # If grandslam authentication is not set, prompt for it
    if "use_gsa" not in config:
        config["use_gsa"] = input("Use grandslam authentication? [y/N] ").lower() == "y"

    def factor_gen():
        return input("Enter iCloud 2FA code: ")

    user_id, token = _get_auth_token(
        config["username"], config["password"], config["use_gsa"], factor_gen=factor_gen
    )

    config["user_id"] = user_id
    config["token"] = token

    key, cert = _get_auth_cert(user_id, token)

    config["key"] = key
    config["cert"] = cert
    # print(key, cert)

    conn1 = apns.APNSConnection()
    conn1.connect()

    conn1.filter(["com.apple.madrid"])

    _register_request(
        b64encode(conn1.token), user_id, cert, key, conn1.cert, conn1.private_key
    )

    # Save config
    with open("config.json", "w") as f:
        json.dump(config, f, indent=4)


if __name__ == "__main__":
    test()
