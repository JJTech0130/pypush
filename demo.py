import json
import logging
import threading
import time
from base64 import b64decode, b64encode
from getpass import getpass

from rich.logging import RichHandler

import apns
import ids
import imessage

logging.basicConfig(
    level=logging.NOTSET, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

# Set sane log levels
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("jelly").setLevel(logging.INFO)
logging.getLogger("nac").setLevel(logging.INFO)
logging.getLogger("apns").setLevel(logging.DEBUG)
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

user.encryption_identity = ids.identity.IDSIdentity(
    encryption_key=CONFIG.get("encryption", {}).get("rsa_key"),
    signing_key=CONFIG.get("encryption", {}).get("ec_key"),
)

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

im = imessage.iMessageUser(conn, user)

# while True:
#     i = im.receive()
#     if i is not None:
#         print(f"Got message {i}")
imsg = imessage.iMessage()
imsg.sender = user.handles[0]
imsg.participants = ["mailto:jjtech@jjtech.dev"]
imsg.text = "Hello world!"

time.sleep(1)
im.send(imsg)

for i in range(10):
    z = im.receive()
    if z is not None:
        print(f"Got message {z}")
    time.sleep(1)
# # Create a thread to take user input
# INPUT_QUEUE = apns.IncomingQueue()

# def input_thread():
#     while True:
#         from prompt_toolkit import prompt

#         try:
#             msg = prompt('>> ')
#         except:
#             msg = 'quit'
#         INPUT_QUEUE.append(msg)

# threading.Thread(target=input_thread, daemon=True).start()
        
        
# while True:
#     msg = im.receive()
#     if msg is not None:
#         print(f"Got message {msg}")
    
#     if len(INPUT_QUEUE) > 0:
#         msg = INPUT_QUEUE.pop()
#         if msg == 'help' or msg == 'h':
#             print('help (h): show this message')
#             print('quit (q): quit')
#             print('send (s) [recipiant] [message]: send a message')
#         elif msg == 'quit' or msg == 'q':
#             break
#         elif msg.startswith('send') or msg.startswith('s'):
#             msg = msg.split(' ')
#             if len(msg) < 3:
#                 print('send [recipiant] [message]')
#             else:
#                 imsg = imessage.iMessage()
#                 imsg.text = ' '.join(msg[2:])
#                 imsg.participants = [msg[1], user.handles[0]]
#                 imsg.sender = user.handles[0]

#                 im.send(imsg)
        
