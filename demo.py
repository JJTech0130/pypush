import json
import logging
import os
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
logging.getLogger("py.warnings").setLevel(logging.ERROR) # Ignore warnings from urllib3
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("jelly").setLevel(logging.INFO)
logging.getLogger("nac").setLevel(logging.INFO)
logging.getLogger("apns").setLevel(logging.INFO)
logging.getLogger("albert").setLevel(logging.INFO)
logging.getLogger("ids").setLevel(logging.DEBUG)
logging.getLogger("bags").setLevel(logging.INFO)
logging.getLogger("imessage").setLevel(logging.DEBUG)

logging.captureWarnings(True)

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

INPUT_QUEUE = apns.IncomingQueue()

def input_thread():
    from prompt_toolkit import prompt
    while True:

        try:
            msg = prompt('>> ')
        except:
            msg = 'quit'
        INPUT_QUEUE.append(msg)

threading.Thread(target=input_thread, daemon=True).start()

print("Type 'help' for help")  

def fixup_handle(handle):
    if handle.startswith('tel:+'):
        return handle
    elif handle.startswith('mailto:'):
        return handle
    elif handle.startswith('tel:'):
        return 'tel:+' + handle[4:]
    elif handle.startswith('+'):
        return 'tel:' + handle
    # If the handle starts with a number
    elif handle[0].isdigit():
        # If the handle is 10 digits, assume it's a US number
        if len(handle) == 10:
            return 'tel:+1' + handle
        # If the handle is 11 digits, assume it's a US number with country code
        elif len(handle) == 11:
            return 'tel:+' + handle
    else: # Assume it's an email
        return 'mailto:' + handle

current_participants = []
current_effect = None
while True:
    msg = im.receive()
    if msg is not None:
        # print(f'[{msg.sender}] {msg.text}')
        print(msg.to_string())

        attachments = msg.attachments()
        if len(attachments) > 0:
            attachments_path = f"attachments/{msg.id}/"
            os.makedirs(attachments_path, exist_ok=True)

            for attachment in attachments:
                with open(attachments_path + attachment.name, "wb") as attachment_file:
                    attachment_file.write(attachment.versions[0].data())

            print(f"({len(attachments)} attachment{'s have' if len(attachments) != 1 else ' has'} been downloaded and put "
                  f"in {attachments_path})")
    
    if len(INPUT_QUEUE) > 0:
        msg = INPUT_QUEUE.pop()
        if msg == '': continue
        if msg == 'help' or msg == 'h':
            print('help (h): show this message')
            print('quit (q): quit')
            #print('send (s) [recipient] [message]: send a message')
            print('filter (f) [recipient]: set the current chat')
            print('effect (e): adds an iMessage effect to the next sent message')
            print('note: recipient must start with tel: or mailto: and include the country code')
            print('handle <handle>: set the current handle (for sending messages)')
            print('\\: escape commands (will be removed from message)')
        elif msg == 'quit' or msg == 'q':
            break
        elif msg == 'effect' or msg == 'e' or msg.startswith("effect ") or msg.startswith("e "):
            msg = msg.split(" ")
            if len(msg) < 2 or msg[1] == "":
                print("effect [effect namespace]")
            else:
                print(f"next message will be sent with [{msg[1]}]")
                current_effect = msg[1]
        elif msg == 'filter' or msg == 'f' or msg.startswith('filter ') or msg.startswith('f '):
            # Set the curernt chat
            msg = msg.split(' ')
            if len(msg) < 2 or msg[1] == '':
                print('filter [recipients]')
            else:
                print(f'Filtering to {[fixup_handle(h) for h in msg[1:]]}')
                current_participants = [fixup_handle(h) for h in msg[1:]]
        elif msg == 'handle' or msg.startswith('handle '):
            msg = msg.split(' ')
            if len(msg) < 2 or msg[1] == '':
                print('handle [handle]')
                print('Available handles:')
                for h in user.handles:
                    if h == user.current_handle:
                        print(f'\t{h} (current)')
                    else:
                        print(f'\t{h}')
            else:
                h = msg[1]
                h = fixup_handle(h)
                if h in user.handles:
                    print(f'Using {h} as handle')
                    user.current_handle = h
                else:
                    print(f'Handle {h} not found')

        elif current_participants != []:
            if msg.startswith('\\'):
                msg = msg[1:]
            im.send(imessage.iMessage(
                text=msg,
                participants=current_participants,
                sender=user.current_handle,
                effect=current_effect
            ))
            current_effect = None
        else:
            print('No chat selected, use help for help')

    time.sleep(0.1)
        
        # elif msg.startswith('send') or msg.startswith('s'):
        #     msg = msg.split(' ')
        #     if len(msg) < 3:
        #         print('send [recipient] [message]')
        #     else:
        #         im.send(imessage.iMessage(
        #             text=' '.join(msg[2:]),
        #             participants=[msg[1], user.handles[0]],
        #             #sender=user.handles[0]
        #         ))
        
