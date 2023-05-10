import random
from base64 import b64decode, b64encode
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from ._helpers import KeyPair, dearmour


# TODO: Move this helper somewhere else
def armour_cert(cert: bytes) -> str:
    cert = x509.load_der_x509_certificate(cert)
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip()


"""
Generates a nonce in this format:
01000001876bd0a2c0e571093967fce3d7
01                                 # version
   000001876d008cc5                 # unix time
                   r1r2r3r4r5r6r7r8 # random bytes
"""


def generate_nonce() -> bytes:
    return (
        b"\x01"
        + int(datetime.now().timestamp() * 1000).to_bytes(8, "big")
        + random.randbytes(8)
    )


import typing


# Creates a payload from individual parts for signing
def _create_payload(
    bag_key: str,
    query_string: str,
    push_token: typing.Union[str, bytes],
    payload: bytes,
    nonce: typing.Union[bytes, None] = None,
) -> tuple[bytes, bytes]:
    # Generate the nonce
    if nonce is None:
        nonce = generate_nonce()

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
    private_key: str, bag_key: str, query_string: str, push_token: str, payload: bytes, nonce = None
) -> tuple[str, bytes]:
    # Load the private key
    key = serialization.load_pem_private_key(
        private_key.encode(), password=None, backend=default_backend()
    )

    payload, nonce = _create_payload(bag_key, query_string, push_token, payload, nonce)

    sig = key.sign(payload, padding.PKCS1v15(), hashes.SHA1())  # type: ignore

    sig = b"\x01\x01" + sig
    sig = b64encode(sig).decode()

    return sig, nonce


# Add headers for x-push-sig and x-auth-sig stuff
def add_auth_signature(
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
    headers["x-push-cert"] = dearmour(push_key.cert)
    headers["x-push-token"] = push_token

    auth_sig, auth_nonce = _sign_payload(auth_key.key, bag_key, "", push_token, body)
    auth_postfix = "-" + str(auth_number) if auth_number is not None else ""
    headers["x-auth-sig" + auth_postfix] = auth_sig
    headers["x-auth-nonce" + auth_postfix] = b64encode(auth_nonce)
    headers["x-auth-cert" + auth_postfix] = dearmour(auth_key.cert)


def add_id_signature(
    headers: dict,
    body: bytes,
    bag_key: str,
    id_key: KeyPair,
    push_token: str,
    nonce=None,
):
    id_sig, id_nonce = _sign_payload(id_key.key, bag_key, "", push_token, body, nonce)
    headers["x-id-sig"] = id_sig
    headers["x-id-nonce"] = b64encode(id_nonce).decode()
    headers["x-id-cert"] = dearmour(id_key.cert)
    headers["x-push-token"] = push_token
