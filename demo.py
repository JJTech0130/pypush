import gzip
import json
import logging
import plistlib
import threading
import time
from base64 import b64decode, b64encode
from getpass import getpass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from rich.logging import RichHandler

import apns
import ids

logging.basicConfig(
    level=logging.NOTSET, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

# Set sane log levels
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("jelly").setLevel(logging.INFO)
logging.getLogger("nac").setLevel(logging.INFO)
logging.getLogger("apns").setLevel(logging.INFO)
logging.getLogger("albert").setLevel(logging.INFO)
logging.getLogger("ids").setLevel(logging.DEBUG)
logging.getLogger("bags").setLevel(logging.DEBUG)

# Try and load config.json
try:
    with open("config.json", "r") as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {}

conn = apns.APNSConnection(
    CONFIG.get("push", {}).get("key"), CONFIG.get("push", {}).get("cert")
)


def safe_b64decode(s):
    try:
        return b64decode(s)
    except:
        return None


conn.connect(token=safe_b64decode(CONFIG.get("push", {}).get("token")))
conn.set_state(1)
conn.filter(["com.apple.madrid"])

user = ids.IDSUser(conn)

if CONFIG.get("auth", {}).get("cert") is not None:
    auth_keypair = ids._helpers.KeyPair(CONFIG["auth"]["key"], CONFIG["auth"]["cert"])
    user_id = CONFIG["auth"]["user_id"]
    handles = CONFIG["auth"]["handles"]
    user.restore_authentication(auth_keypair, user_id, handles)
else:
    username = input("Username: ")
    password = getpass("Password: ")

    user.authenticate(username, password)

user.encryption_identity = ids.identity.IDSIdentity(encryption_key=CONFIG.get("encryption", {}).get("rsa_key"), signing_key=CONFIG.get("encryption", {}).get("ec_key"))

if (
    CONFIG.get("id", {}).get("cert") is not None
    and user.encryption_identity is not None
):
    id_keypair = ids._helpers.KeyPair(CONFIG["id"]["key"], CONFIG["id"]["cert"])
    user.restore_identity(id_keypair)
else:
    logging.info("Registering new identity...")
    import emulated.nac

    vd = emulated.nac.generate_validation_data()
    vd = b64encode(vd).decode()

    user.register(vd)

logging.info("Waiting for incoming messages...")

# Create a thread to send keepalive messages


def keepalive():
    while True:
        time.sleep(5)
        conn.keep_alive()


threading.Thread(target=keepalive, daemon=True).start()

# Write config.json
CONFIG["encryption"] = {
    "rsa_key": user.encryption_identity.encryption_key,
    "ec_key": user.encryption_identity.signing_key,
}
CONFIG["id"] = {
    "key": user._id_keypair.key,
    "cert": user._id_keypair.cert,
}
CONFIG["auth"] = {
    "key": user._auth_keypair.key,
    "cert": user._auth_keypair.cert,
    "user_id": user.user_id,
    "handles": user.handles,
}
CONFIG["push"] = {
    "token": b64encode(user.push_connection.token).decode(),
    "key": user.push_connection.private_key,
    "cert": user.push_connection.cert,
}

with open("config.json", "w") as f:
    json.dump(CONFIG, f, indent=4)

import imessage
im = imessage.iMessageUser(conn, user)

while True:
    msg = im.receive()
    print(f"Got message {msg['t']}")
    
# user_rsa_key = ids._helpers.parse_key(user.encryption_identity.encryption_key)
# NORMAL_NONCE = b"\x00" * 15 + b"\x01"

# def decrypt(payload, sender_token, rsa_key: rsa.RSAPrivateKey = user_rsa_key):
#     """
#     iMessage payload format:
#     0x00 - ?
#     0x01-0x02 - length of payload
#     0x03-0xA0 - RSA encrypted payload portion
#         0x00-0x0F - AES key
#         0x0F-0x?? - AES encrypted payload portion
#     0xA1-0xlength of payload+3 - AES encrypted payload portion
#     0xlength of payload+3 - length of signature
#     0xLEN+4-0xLEN+4+length of signature - signature
#     """
#     from io import BytesIO


#     payload = BytesIO(payload)
#     tag = payload.read(1)
#     length = int.from_bytes(payload.read(2), "big")
#     body = payload.read(length)
#     body_io = BytesIO(body)
#     rsa_body = rsa_key.decrypt(
#         body_io.read(160),
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA1()),
#             algorithm=hashes.SHA1(),
#             label=None,
#         ),
#     )

#     cipher = Cipher(algorithms.AES(rsa_body[:16]), modes.CTR(NORMAL_NONCE))
#     decrypted = cipher.decryptor().update(rsa_body[16:] + body_io.read())

#     # Try to gzip decompress the payload
#     try:
#         decrypted = gzip.decompress(decrypted)
#     except:
#         logging.debug("Failed to decompress payload")
#         pass

#     decrypted = plistlib.loads(decrypted)

#     signature_len = payload.read(1)[0]
#     signature = payload.read(signature_len)
#     #logging.info(f"Signature: {signature}")
#     #logging.info(f"Decrypted: {decrypted}")

#     # Verify the signature
#     sender = decrypted["p"][-1]
#     # Lookup the public key for the sender
#     lookup = user.lookup([sender])[sender]
#     #logging.debug(f"Lookup: {lookup}")
#     sender = None
#     for identity in lookup['identities']:
#         if identity['push-token'] == sender_token:
#             sender = identity
#             break
    
#     if sender is None:
#         logging.error(f"Failed to find identity for {sender_token}")

#     identity_keys = sender['client-data']['public-message-identity-key']
#     identity_keys = ids.identity.IDSIdentity.decode(identity_keys)

#     sender_ec_key = ids._helpers.parse_key(identity_keys.signing_public_key)

#     from cryptography.hazmat.primitives.asymmetric import ec
#     #logging.debug(f"Verifying signature {signature} with key {sender_ec_key.public_numbers()} and data {body}")
#     # Verify the signature (will throw an exception if it fails)
#     sender_ec_key.verify(
#         signature,
#         body,
#         ec.ECDSA(hashes.SHA1()),
#     )

#     return decrypted


# while True:

#     def check_response(x):
#         if x[0] != 0x0A:
#             return False
#         resp_body = apns._get_field(x[1], 3)
#         if resp_body is None:
#             return False
#         resp_body = plistlib.loads(resp_body)
#         if "P" not in resp_body:
#             return False
#         return True

#     payload = conn.incoming_queue.wait_pop_find(check_response)
#     resp_body = apns._get_field(payload[1], 3)
#     id = apns._get_field(payload[1], 4)
#     conn._send_ack(id)
#     resp_body = plistlib.loads(resp_body)
#     # logging.info(f"Got response: {resp_body}")
#     logging.debug(f"Got message: {resp_body}")
#     token = resp_body['t']
#     payload = resp_body["P"]
#     payload = decrypt(payload, token)
#     logging.info(f"Got message: {payload['t']} from {payload['p'][1]}")
