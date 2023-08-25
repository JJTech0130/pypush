import json
import logging
import os
import threading
import time
from base64 import b64decode, b64encode
from getpass import getpass
from subprocess import PIPE, Popen

from rich.logging import RichHandler

import apns
import ids
import imessage

import trio

logging.basicConfig(
    level=logging.NOTSET, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

# Set sane log levels
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("py.warnings").setLevel(logging.ERROR)  # Ignore warnings from urllib3
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("jelly").setLevel(logging.INFO)
logging.getLogger("nac").setLevel(logging.INFO)
logging.getLogger("apns").setLevel(logging.INFO)
logging.getLogger("albert").setLevel(logging.INFO)
logging.getLogger("ids").setLevel(logging.DEBUG)
logging.getLogger("bags").setLevel(logging.INFO)
logging.getLogger("imessage").setLevel(logging.INFO)

logging.captureWarnings(True)

process = Popen(["git", "rev-parse", "HEAD"], stdout=PIPE) # type: ignore
(commit_hash, err) = process.communicate()
exit_code = process.wait()
commit_hash = commit_hash.decode().strip()

# Try and load config.json
try:
    with open("config.json", "r") as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {}

# Re-register if the commit hash has changed
FORCE_REREGISTER = True
if CONFIG.get("commit_hash") != commit_hash or FORCE_REREGISTER:
    logging.warning("pypush commit is different, forcing re-registration...")
    CONFIG["commit_hash"] = commit_hash
    if "id" in CONFIG:
        del CONFIG["id"]


def safe_b64decode(s):
    try:
        return b64decode(s)
    except:
        return None

async def main():
    token = CONFIG.get("push", {}).get("token")
    if token is not None:
        token = b64decode(token)
    else:
        token = b""

    push_creds = apns.PushCredentials(
        CONFIG.get("push", {}).get("key", ""), CONFIG.get("push", {}).get("cert", ""), token)

    async with apns.APNSConnection.start(push_creds) as conn:
        await conn.set_state(1)
        await conn.filter(["com.apple.madrid"])

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

        import sms_registration
        phone_sig = safe_b64decode(CONFIG.get("phone", {}).get("sig"))
        phone_number = CONFIG.get("phone", {}).get("number")

        if phone_sig is None or phone_number is None:
            print("Registering phone number...")
            phone_number, phone_sig = sms_registration.register(user.push_connection.credentials.token)
            CONFIG["phone"] = {
                "number": phone_number,
                "sig": b64encode(phone_sig).decode(),
            }
        if CONFIG.get("phone", {}).get("auth_key") is not None and CONFIG.get("phone", {}).get("auth_cert") is not None:
            phone_auth_keypair = ids._helpers.KeyPair(CONFIG["phone"]["auth_key"], CONFIG["phone"]["auth_cert"])
        else:
            phone_auth_keypair = ids.profile.get_phone_cert(phone_number, user.push_connection.credentials.token, [phone_sig])
            CONFIG["phone"]["auth_key"] = phone_auth_keypair.key
            CONFIG["phone"]["auth_cert"] = phone_auth_keypair.cert


        user.encryption_identity = ids.identity.IDSIdentity(
            encryption_key=CONFIG.get("encryption", {}).get("rsa_key"),
            signing_key=CONFIG.get("encryption", {}).get("ec_key"),
        )

        #user._auth_keypair = phone_auth_keypair
        user.handles = [f"tel:{phone_number}"]
        print(user.user_id)
       # user.user_id = f"P:{phone_number}"


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

            user.register(vd, [("P:" + phone_number, phone_auth_keypair)])
            #user.register(vd)

        print("Handles: ", user.handles)

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
            "token": b64encode(user.push_connection.credentials.token).decode(),
            "key": user.push_connection.credentials.private_key,
            "cert": user.push_connection.credentials.cert,
        }

        with open("config.json", "w") as f:
            json.dump(CONFIG, f, indent=4)

        im = imessage.iMessageUser(conn, user)

        # Send a message to myself
        async with trio.open_nursery() as nursery:
            nursery.start_soon(input_task, im)
            nursery.start_soon(output_task, im)

async def input_task(im: imessage.iMessageUser):
    while True:
        cmd = await trio.to_thread.run_sync(input, "> ", cancellable=True)
        if cmd != "":
            await im.send(imessage.iMessage.create(im, cmd, ["tel:+16106632676"]))

async def output_task(im: imessage.iMessageUser):
    while True:
        msg = await im.receive()
        print(str(msg))


if __name__ == "__main__":
    trio.run(main)