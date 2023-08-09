import plistlib
import random
import uuid
from base64 import b64decode

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

import bags

from . import signing
from ._helpers import PROTOCOL_VERSION, USER_AGENT, KeyPair

import logging
logger = logging.getLogger("ids")


def _auth_token_request(username: str, password: str) -> any:
    # Turn the PET into an auth token
    data = {
        "username": username,
        #"client-id": str(uuid.uuid4()),
        #"delegates": {"com.apple.private.ids": {"protocol-version": "4"}},
        "password": password,
    }
    data = plistlib.dumps(data)

    r = requests.post(
        # TODO: Figure out which URL bag we can get this from
        "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser",
        #"https://setup.icloud.com/setup/prefpane/loginDelegates",
        #auth=(username, password),
        data=data,
        verify=False,
    )
    r = plistlib.loads(r.content)
    return r


# Gets an IDS auth token for the given username and password
# Will use native Grand Slam on macOS
# If factor_gen is not None, it will be called to get the 2FA code, otherwise it will be prompted
# Returns (realm user id, auth token)
def get_auth_token(
    username: str, password: str, factor_gen: callable = None
) -> tuple[str, str]:
    from sys import platform
    
    result = _auth_token_request(username, password)
    if result["status"] != 0:
        if result["status"] == 5000:
            if factor_gen is None:
                password = password + input("Enter 2FA code: ")
            else:
                password = password + factor_gen()
            result = _auth_token_request(username, password)
            if result["status"] != 0:
                raise Exception(f"Error: {result}")
    
    auth_token = result["auth-token"]
    realm_user_id = result["profile-id"]
    # else:
    #     logger.debug("Using old-style authentication")
    #     # Make the request without the 2FA code to make the prompt appear
    #     _auth_token_request(username, password)
    #     # TODO: Make sure we actually need the second request, some rare accounts don't have 2FA
    #     # Now make the request with the 2FA code
    #     if factor_gen is None:
    #         pet = password + input("Enter 2FA code: ")
    #     else:
    #         pet = password + factor_gen()
    # r = _auth_token_request(username, pet)
    # # print(r)
    # if "description" in r:
    #     raise Exception(f"Error: {r['description']}")
    # service_data = r["delegates"]["com.apple.private.ids"]["service-data"]
    # realm_user_id = service_data["realm-user-id"]
    # auth_token = service_data["auth-token"]
    # print(f"Auth token for {realm_user_id}: {auth_token}")
    logger.debug(f"Got auth token for IDS: {auth_token}")
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
def get_auth_cert(user_id, token) -> KeyPair:
    BAG_KEY = "id-authenticate-ds-id"

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
        bags.ids_bag()[BAG_KEY],
        #"https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS",
        data=body,
        headers={"x-protocol-version": "1630"},
        verify=False,
    )
    r = plistlib.loads(r.content)
    if r["status"] != 0:
        raise (Exception(f"Failed to get auth cert: {r}"))
    cert = x509.load_der_x509_certificate(r["cert"])
    logger.debug("Got auth cert from token")
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


def get_handles(push_token, user_id: str, auth_key: KeyPair, push_key: KeyPair):
    BAG_KEY = "id-get-handles"

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id": user_id,
    }
    signing.add_auth_signature(
        headers, None, BAG_KEY, auth_key, push_key, push_token
    )

    r = requests.get(
        bags.ids_bag()[BAG_KEY],
        headers=headers,
        verify=False,
    )

    r = plistlib.loads(r.content)

    if not "handles" in r:
        raise Exception("No handles in response: " + str(r))

    logger.debug(f"User {user_id} has handles {r['handles']}")
    return [handle["uri"] for handle in r["handles"]]
