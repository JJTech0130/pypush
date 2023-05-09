import requests
import plistlib
import uuid
import gsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
import random
from base64 import b64decode
from ._helpers import KeyPair, PROTOCOL_VERSION, USER_AGENT
from . import signing


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

def _get_handles(push_token, user_id: str, auth_key: KeyPair, push_key: KeyPair):
    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id": user_id,
        #"user-agent": USER_AGENT,
    }
    import oldids
    #headers2 = headers.copy()
    #oldids._add_auth_push_sig(headers2, None, "id-get-handles", auth_key, push_key, push_token)
    #headers3 = headers.copy()
    signing.add_auth_signature(
        headers, None, "id-get-handles", auth_key, push_key, push_token
    )

    #for key, value in headers2.items():
    #    if headers3[key] != value:
    #        print(f"Key {key} mismatch: {headers3[key]} != {value}")

    r = requests.get(
        "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/idsGetHandles",
        headers=headers,
        verify=False,
    )

    r = plistlib.loads(r.content)

    if not "handles" in r:
        raise Exception("No handles in response: " + str(r))

    return [handle["uri"] for handle in r["handles"]]