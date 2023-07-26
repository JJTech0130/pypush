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
from ids.keydec import IdentityKeys

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

user.ec_key = CONFIG.get("encryption", {}).get("ec_key")
user.rsa_key = CONFIG.get("encryption", {}).get("rsa_key")

if CONFIG.get("id", {}).get("cert") is not None and user.ec_key is not None and user.rsa_key is not None:
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
    "ec_key": user.ec_key,
    "rsa_key": user.rsa_key,
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

user_rsa_key = load_pem_private_key(user.rsa_key.encode(), password=None)

def decrypt(payload):
    # print(payload[1:3])
    length = int.from_bytes(payload[1:3], "big")
    # print("Length", length)
    payload = payload[3 : length + 3]
    # print("Decrypting payload", payload)

    decrypted1 = user_rsa_key.decrypt(
        payload[:160],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        ),
    )

    cipher = Cipher(algorithms.AES(decrypted1[:16]), modes.CTR(b"\x00" * 15 + b"\x01"))
    decryptor = cipher.decryptor()
    pt = decryptor.update(decrypted1[16:] + payload[160:])
    # print(pt)
    pt = gzip.decompress(pt)
    payload = plistlib.loads(pt)
    # logging.debug(f"Got payload: {payload}")
    return payload


while True:

    def check_response(x):
        if x[0] != 0x0A:
            return False
        resp_body = apns._get_field(x[1], 3)
        if resp_body is None:
            return False
        resp_body = plistlib.loads(resp_body)
        if "P" not in resp_body:
            return False
        return True

    payload = conn.incoming_queue.wait_pop_find(check_response)
    resp_body = apns._get_field(payload[1], 3)
    id = apns._get_field(payload[1], 4)
    conn._send_ack(id)
    resp_body = plistlib.loads(resp_body)
    # logging.info(f"Got response: {resp_body}")
    payload = resp_body["P"]
    payload = decrypt(payload)
    logging.info(f"Got message: {payload['t']} from {payload['p'][1]}")
