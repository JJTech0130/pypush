import json
from base64 import b64encode
from getpass import getpass
from base64 import b64decode
import apns
import ids

import logging
from rich.logging import RichHandler

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)

# Set sane log levels
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("jelly").setLevel(logging.INFO)
logging.getLogger("nac").setLevel(logging.INFO)
logging.getLogger("apns").setLevel(logging.DEBUG)
logging.getLogger("albert").setLevel(logging.INFO)
logging.getLogger("ids").setLevel(logging.DEBUG)
logging.getLogger("bags").setLevel(logging.DEBUG)

def input_multiline(prompt):
    print(prompt)
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)


# Try and load config.json
try:
    with open("config.json", "r") as f:

        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {}

def convert_config(old):
    new = {}
    new["id"] = {
        "key": old["key"],
        "cert": old["ids_cert"],
    }
    new["auth"] = {
        "key": old["key"],
        "cert": old["auth_cert"],
        "user_id": old["user_id"],
        "handles": [
            "mailto:user_test2@icloud.com",
        ]
        #"handles": old["handles"],
    }
    new["push"] = {
        "token": old["push"]["token"],
        "key": old["push"]["key"],
        "cert": old["push"]["cert"],
    }
    return new

# Uncomment this to change from an old config.json to a new one
#CONFIG = convert_config(CONFIG)


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
#print(b64encode(conn.token).decode())
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

# Generate a new RSA keypair for the identity
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
# Load the old keypair if it exists
if CONFIG.get("encrypt") is not None:
    priv_enc = load_pem_private_key(CONFIG["encrypt"].encode(), password=None)
else:
    priv_enc = rsa.generate_private_key(public_exponent=65537, key_size=1280)
pub_enc = priv_enc.public_key()

if CONFIG.get("id", {}).get("cert") is not None:
    id_keypair = ids._helpers.KeyPair(CONFIG["id"]["key"], CONFIG["id"]["cert"])
    user.restore_identity(id_keypair)
else:
    #vd = input_multiline("Enter validation data: ")
    import emulated.nac
    vd = emulated.nac.generate_validation_data()
    vd = b64encode(vd).decode()

    from ids.keydec import IdentityKeys
    
    published_keys = IdentityKeys(None, pub_enc)
    user.register(vd, published_keys)

#logging.info(f"Looked up textgpt@icloud.com, got response: {user.lookup(['mailto:textgpt@icloud.com'])}")

# logging.info("Enter a username to look up, for example: mailto:textgpt@icloud.com")
# while True:
#     # Read a line from stdin
#     line = input("> ")
#     if line == "":
#         break
#     # Look up the username
#     resp = user.lookup([line])
#     #logging.info(f"Looked up {line}, got response: {user.lookup([line])}")
#     info = resp[line]
#     identities = info["identities"]
#     logging.info(f"Identities: {len(identities)}")
#     for identity in identities:
#         logging.info(f"Identity: [yellow]{b64encode(identity['push-token']).decode()}[/] ({len(identity)} properties)", extra={"markup": True})
#         if len(identity) > 5:
#             logging.warning(identity)

logging.debug(user.lookup(["mailto:usert4@icloud.com", "mailto:jjtech@jjtech.dev"]))
# resp = user.lookup(["mailto:jjtech@jjtech.dev"])
# info = resp["mailto:jjtech@jjtech.dev"]
# identities = info["identities"]
# for identity in identities:
#     logging.info(f"Identity: [yellow]{b64encode(identity['push-token']).decode()}[/] ({len(identity)} properties)", extra={"markup": True})
#     if "client-data" in identity:
#         logging.warning(identity["client-data"])
logging.info("Waiting for incomming messages...")

# Create a thread to send keepalive messages
import threading
import time
def keepalive():
    while True:
        time.sleep(5)
        conn.keep_alive()
threading.Thread(target=keepalive, daemon=True).start()

# while True:
# #     # Wait for a message
# #     # def check_response(x):
# #     #     if x[0] != 0x0A:
# #     #         return False
# #     #     resp_body = apns._get_field(x[1], 3)
# #     #     if resp_body is None:
# #     #         return False
# #     #     resp_body = apns._get_field(x[1], 3)
# #     #     if resp_body is None:
# #     #         return False
# #     #     resp_body = plistlib.loads(resp_body)
# #     #     return resp_body.get('U') == msg_id
#     pass

# Write config.json
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
from cryptography.hazmat.primitives import serialization
CONFIG["encrypt"] = priv_enc.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()).decode("utf-8").strip()

with open("config.json", "w") as f:
    json.dump(CONFIG, f, indent=4)

def decrypt(payload):
    import gzip
    #print(payload[1:3])
    length = int.from_bytes(payload[1:3], "big")
    #print("Length", length)
    payload = payload[3:length+3]
    #print("Decrypting payload", payload)
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    decrypted1 = priv_enc.decrypt(payload[:160], padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None
    ))

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(decrypted1[:16]), modes.CTR(b'\x00'*15 + b'\x01'))
    decryptor = cipher.decryptor()
    pt = decryptor.update(decrypted1[16:] + payload[160:])
    #print(pt)
    pt = gzip.decompress(pt)
    payload = plistlib.loads(pt)
    logging.info(f"Got payload: {payload}")


import plistlib
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
    resp_body = plistlib.loads(resp_body)
    #logging.info(f"Got response: {resp_body}")
    payload = resp_body["P"]
    decrypt(payload)

        