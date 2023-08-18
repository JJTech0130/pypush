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

logging.basicConfig(
    level=logging.NOTSET, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

# Set sane log levels
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("py.warnings").setLevel(logging.ERROR)  # Ignore warnings from urllib3
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("jelly").setLevel(logging.INFO)
logging.getLogger("nac").setLevel(logging.INFO)
logging.getLogger("apns").setLevel(logging.DEBUG)
logging.getLogger("albert").setLevel(logging.INFO)
logging.getLogger("ids").setLevel(logging.DEBUG)
logging.getLogger("bags").setLevel(logging.INFO)
logging.getLogger("imessage").setLevel(logging.DEBUG)

logging.captureWarnings(True)

process = Popen(["git", "rev-parse", "HEAD"], stdout=PIPE)
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
if CONFIG.get("commit_hash") != commit_hash:
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
    # Try and load config.json
    try:
        with open("config.json", "r") as f:
            CONFIG = json.load(f)
    except FileNotFoundError:
        CONFIG = {}

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
        await im.send(imessage.iMessage.create(im, "Hello, world!", [user.current_handle]))

if __name__ == "__main__":
    import trio
    trio.run(main)