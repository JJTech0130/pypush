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

import trio
import argparse

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

# Try and load config.json
try:
    with open("config.json", "r") as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    CONFIG = {}

def safe_b64decode(s):
    try:
        return b64decode(s)
    except:
        return None
    
def safe_config():
    with open("config.json", "w") as f:
        json.dump(CONFIG, f, indent=4)

async def main(args: argparse.Namespace):
    # Load any existing push credentials
    token = CONFIG.get("push", {}).get("token")
    token = b64decode(token) if token is not None else b""

    push_creds = apns.PushCredentials(
        CONFIG.get("push", {}).get("key", ""), CONFIG.get("push", {}).get("cert", ""), token)
    
    def register(conn, users):
        import emulated.nac
        vd = emulated.nac.generate_validation_data()
        vd = b64encode(vd).decode()
        users = ids.register(conn, users, vd, args.client_data)
        return users

    async with apns.APNSConnection.start(push_creds) as conn:
        # Save the push credentials to the config
        CONFIG["push"] = {
            "token": b64encode(conn.credentials.token).decode(),
            "key": conn.credentials.private_key,
            "cert": conn.credentials.cert,
        }
        safe_config()

        # Activate the connection
        await conn.set_state(1)
        await conn.filter(["com.apple.madrid"])

        # If the user wants a phone number, we need to register it WITH an Apple ID, then register the Apple ID again
        # otherwise we encounter issues for some reason
        
        users = []
        if "id" in CONFIG:
            logging.debug("Restoring old-style identity...")

            users.append(ids.IDSAppleUser(conn, CONFIG["auth"]["user_id"], ids._helpers.KeyPair(CONFIG["auth"]["key"], CONFIG["auth"]["cert"]),
                                    ids.identity.IDSIdentity(CONFIG["encryption"]["ec_key"], CONFIG["encryption"]["rsa_key"]), CONFIG["id"]["cert"],
                                    CONFIG["auth"]["handles"]))
        if "users" in CONFIG:
            logging.debug("Restoring new-style identity...")
            for user in CONFIG["users"]:
                users.append(ids.IDSUser(conn, user["id"], ids._helpers.KeyPair(user["auth_key"], user["auth_cert"]),
                                    ids.identity.IDSIdentity(user["signing_key"], user["encryption_key"]), user["id_cert"],
                                    user["handles"]))
        
        else:
            print("Would you like to register a phone number? (y/n)")
            if input("> ").lower() == "y":
                import sms_registration
                if args.gateway is not None:
                    sms_registration.GATEWAY = args.gateway
                if args.phone is not None:
                    sms_registration.PHONE_IP = args.phone

                if "phone" in CONFIG:
                    phone_sig = b64decode(CONFIG["phone"].get("sig"))
                    phone_number = CONFIG["phone"].get("number")
                elif args.pdu is not None:
                    sms_registration.parse_pdu(args.pdu, None)
                else:
                    import sms_registration
                    phone_number, phone_sig = sms_registration.register(conn.credentials.token, args.trigger_pdu)
                    CONFIG["phone"] = {
                        "number": phone_number,
                        "sig": b64encode(phone_sig).decode(),
                    }
                    safe_config()

                users.append(ids.IDSPhoneUser.authenticate(conn, phone_number, phone_sig))

            print("Would you like sign in to your Apple ID (recommended)? (y/n)")
            if input("> ").lower() == "y":
                username = input("Username: ")
                password = input("Password: ")

                users.append(ids.IDSAppleUser.authenticate(conn, username, password))

            users = register(conn, users)

            CONFIG["users"] = []
            for user in users:
                CONFIG["users"].append({
                    "id": user.user_id,
                    "auth_key": user.auth_keypair.key,
                    "auth_cert": user.auth_keypair.cert,
                    "encryption_key": user.encryption_identity.encryption_key if user.encryption_identity is not None else None,
                    "signing_key": user.encryption_identity.signing_key if user.encryption_identity is not None else None,
                    "id_cert": user.id_cert,
                    "handles": user.handles,
                })
            safe_config()

        if args.reregister:
            print("Re-registering...")
            users = register(conn, users)

        print(f"Done?")

        if args.alive:
            logging.getLogger("apns").setLevel(logging.DEBUG)
            while True:
                await trio.sleep(20)

        






            

            

    #     user = ids.IDSUser(conn)

    #     if CONFIG.get("auth", {}).get("cert") is not None:
    #         auth_keypair = ids._helpers.KeyPair(CONFIG["auth"]["key"], CONFIG["auth"]["cert"])
    #         user_id = CONFIG["auth"]["user_id"]
    #         handles = CONFIG["auth"]["handles"]
    #         user.restore_authentication(auth_keypair, user_id, handles)
    #     else:
    #         username = input("Username: ")
    #         password = getpass("Password: ")

    #         user.authenticate(username, password)

    #     import sms_registration
    #     phone_sig = safe_b64decode(CONFIG.get("phone", {}).get("sig"))
    #     phone_number = CONFIG.get("phone", {}).get("number")

    #     if phone_sig is None or phone_number is None:
    #         print("Registering phone number...")
    #         phone_number, phone_sig = sms_registration.register(user.push_connection.credentials.token)
    #         CONFIG["phone"] = {
    #             "number": phone_number,
    #             "sig": b64encode(phone_sig).decode(),
    #         }
    #     if CONFIG.get("phone", {}).get("auth_key") is not None and CONFIG.get("phone", {}).get("auth_cert") is not None:
    #         phone_auth_keypair = ids._helpers.KeyPair(CONFIG["phone"]["auth_key"], CONFIG["phone"]["auth_cert"])
    #     else:
    #         phone_auth_keypair = ids.profile.get_phone_cert(phone_number, user.push_connection.credentials.token, [phone_sig])
    #         CONFIG["phone"]["auth_key"] = phone_auth_keypair.key
    #         CONFIG["phone"]["auth_cert"] = phone_auth_keypair.cert


    #     user.encryption_identity = ids.identity.IDSIdentity(
    #         encryption_key=CONFIG.get("encryption", {}).get("rsa_key"),
    #         signing_key=CONFIG.get("encryption", {}).get("ec_key"),
    #     )

    #     #user._auth_keypair = phone_auth_keypair
    #     user.handles = [f"tel:{phone_number}"]
    #     print(user.user_id)
    #    # user.user_id = f"P:{phone_number}"


    #     if (
    #         CONFIG.get("id", {}).get("cert") is not None
    #         and user.encryption_identity is not None
    #     ):
    #         id_keypair = ids._helpers.KeyPair(CONFIG["id"]["key"], CONFIG["id"]["cert"])
    #         user.restore_identity(id_keypair)
    #     else:
    #         logging.info("Registering new identity...")
    #         import emulated.nac

    #         vd = emulated.nac.generate_validation_data()
    #         vd = b64encode(vd).decode()

    #         ids.register
    #         user.register(vd, [("P:" + phone_number, phone_auth_keypair)])
    #         #user.register(vd)

    #     print("Handles: ", user.handles)

    #     # Write config.json
    #     CONFIG["encryption"] = {
    #         "rsa_key": user.encryption_identity.encryption_key,
    #         "ec_key": user.encryption_identity.signing_key,
    #     }
    #     CONFIG["id"] = {
    #         "key": user._id_keypair.key,
    #         "cert": user._id_keypair.cert,
    #     }
    #     CONFIG["auth"] = {
    #         "key": user._auth_keypair.key,
    #         "cert": user._auth_keypair.cert,
    #         "user_id": user.user_id,
    #         "handles": user.handles,
    #     }
    #     CONFIG["push"] = {
    #         "token": b64encode(user.push_connection.credentials.token).decode(),
    #         "key": user.push_connection.credentials.private_key,
    #         "cert": user.push_connection.credentials.cert,
    #     }

    #     with open("config.json", "w") as f:
    #         json.dump(CONFIG, f, indent=4)

    #     im = imessage.iMessageUser(conn, user)

        # Send a message to myself
        # async with trio.open_nursery() as nursery:
        #     nursery.start_soon(input_task, im)
        #     nursery.start_soon(output_task, im)

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--reregister", action="store_true", help="Force re-registration")
    parser.add_argument("--alive", action="store_true", help="Keep the connection alive")
    parser.add_argument("--client-data", action="store_true", help="Publish client data (only necessary for actually sending/receiving messages)")
    parser.add_argument("--trigger-pdu", action="store_true", help="Trigger a REG-REQ")
    # String arg to override pdu
    parser.add_argument("--pdu", type=str, help="Override the PDU REG-RESP")
    parser.add_argument("--phone", type=str, help="Override the phone IP")
    parser.add_argument("--gateway", type=str, help="Override the gateway phone number")

    args = parser.parse_args()
    
    if not args.pdu.startswith("REG-RESP"):
        print("Invalid REG-RESP PDU")
        exit(1)

    trio.run(main, args)