import json
import logging
import os
import threading
import platform
import time
import traceback
from base64 import b64decode, b64encode
from getpass import getpass
from cryptography import x509
import datetime

from rich.logging import RichHandler

minor_version = int(platform.python_version().split('.')[1]) 
  
 if minor_version < 10 or minor_version > 11: 
     raise Exception(f"Incompatible Python version '{platform.python_version()}'")

import apns
import ids
import imessage

import trio
import argparse

from exceptions import *

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
logging.getLogger("ids").setLevel(logging.INFO)
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

def get_not_valid_after_timestamp(cert_data):
    try:
        cert = x509.load_pem_x509_certificate(cert_data.encode('utf-8'))
        return cert.not_valid_after
    except Exception as e:
        return None  # Return None in case of an error

expiration = None

async def main(args: argparse.Namespace):

    global expiration

    # Load any existing push credentials
    token = CONFIG.get("push", {}).get("token")
    token = b64decode(token) if token is not None else b""

    push_creds = apns.PushCredentials(
        CONFIG.get("push", {}).get("key", ""), CONFIG.get("push", {}).get("cert", ""), token)
    
    def register(conn, users):
        import emulated.nac
        vd = emulated.nac.generate_validation_data()
        vd = b64encode(vd).decode()
        users = ids.register(conn, users, vd, args.client_data or args.reg_notify)
        return users
    
    def expiration_identifier(users: list[ids.IDSUser]) -> datetime.datetime | None:
            expiration = None
            # Format time as HH:MM:SS PM/AM EST/EDT (X minutes from now)
            expire_msg = lambda expiration: f"Number registration is valid until {str(expiration.astimezone().strftime('%x %I:%M:%S %p %Z'))} ({str(int((expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds()/60))} minutes from now)"
            for user in users:
                # If this is a phone number user, then it's got to be the one we just linked
                # so pull out the expiration date from the certificate
                if "P:" in str(user.user_id):
                    # There is not really a good reason to try/catch here: If we couldn't reregister, just crash (very unlikely we can recover)
                    cert = x509.load_pem_x509_certificate(user.id_cert.encode('utf-8'))
                    expiration = cert.not_valid_after 
                    # Make it a UTC aware timezone, for reasons
                    expiration = expiration.replace(tzinfo=datetime.timezone.utc)
                    logging.info(expire_msg(expiration))
            return expiration

    
    async def reregister(conn: apns.APNSConnection, users: list[ids.IDSUser]) -> datetime.datetime:
        register(conn, users)

        CONFIG["users"] = []

        expiration = None
        # Format time as HH:MM:SS PM/AM EST/EDT (X minutes from now)
        expire_msg = lambda expiration: f"Number registration is valid until {str(expiration.astimezone().strftime('%x %I:%M:%S %p %Z'))} ({str(int((expiration - datetime.datetime.now(datetime.timezone.utc)).total_seconds()/60))} minutes from now)"
        
        email_user = None
        email_addr = None # For HACK below

        for user in users:
            # Clear the config and re-save everything to match the new registration
            CONFIG["users"].append({
                "id": user.user_id,
                "auth_key": user.auth_keypair.key,
                "auth_cert": user.auth_keypair.cert,
                "encryption_key": user.encryption_identity.encryption_key if user.encryption_identity is not None else None,
                "signing_key": user.encryption_identity.signing_key if user.encryption_identity is not None else None,
                "id_cert": user.id_cert,
                "handles": user.handles,
            })

            if not "P:" in str(user.user_id):
                email_user = user
                for n in range(len(user.handles)):
                    # HACK: Just pick the first email address they have to avoid picking the linked phone number
                    # TODO: Properly fix this, so that the linked phone number is not in the Apple ID user's list of handles
                    if "mailto:" in str(user.handles[n]):
                        email_addr = user.handles[n]

        # Set up a temporary iMessage user to send notifications
        im = imessage.iMessageUser(conn, email_user)
        im.current_handle = email_addr # HACK: See above
        
        # Notify other devices on the account that new handles are available
        await im._send_raw(130, [im.current_handle], "com.apple.madrid")

        expiration = expiration_identifier(users)

        # Save the config to disk
        safe_config()

        # Send the notification iMessage (if enabled)
        if args.reg_notify:
            await im.send(imessage.iMessage.create(im, expire_msg(expiration), [email_addr]))

        return expiration

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

                if "phone" in CONFIG:
                    phone_sig = b64decode(CONFIG["phone"].get("sig"))
                    phone_number = CONFIG["phone"].get("number")
                elif args.pdu is not None:
                    phone_number, phone_sig = sms_registration.parse_pdu(args.pdu, None)
                else:
                    if args.phone is None:
                        #raise GatewayConnectionError("You did not supply an IP address.")
                        # Prompt for IP address
                        print("Please enter the IP address of your phone.")
                        print("This should be displayed in the SMS registration helper app")
                        print("You must be on the same network as your phone.")
                        phone = input("> ")
                    else:
                        phone = args.phone
                    import sms_registration
                    phone_number, phone_sig = sms_registration.register(push_token=conn.credentials.token,
                                                                        no_parse=args.trigger_pdu, gateway=args.gateway,
                                                                        phone_ip=phone)
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

            await reregister(conn, users)

        if args.daemon:
            wait_time_minutes = 5  # this is in minutes. 5 recommended
            
            if args.reregister:
                expiration = await reregister(conn, users)
            else:
                expiration = expiration_identifier(users)
            
            if expiration is None:
                expiration = await reregister(conn, users)

            while True:
                reregister_time = expiration - datetime.timedelta(minutes=wait_time_minutes)  # wait_time_minutes before expiration
                reregister_delta = (reregister_time - datetime.datetime.now(datetime.timezone.utc)).total_seconds()

                logging.info(f"Reregistering in {int(reregister_delta / 60)} minutes...")
                if (reregister_delta > 0):
                    await trio.sleep(reregister_delta)

                logging.info("Reregistering...")
                expiration = await reregister(conn, users)

                logging.info("Reregistered!")

        if args.cronreg:
            reregister_within = 60 # Minutes, time where if expiration time is less than, rereg.
            for user in users:
                if "P:" in str(user.user_id):
                    # logging.info(f'The user is: {user}')
                    cert = x509.load_pem_x509_certificate(user.id_cert.encode('utf-8'))
                    expiration = cert.not_valid_after
                    logging.info(f'Certificate expires on: {expiration}')
                    reregister_time = expiration - datetime.timedelta(minutes=reregister_within)
                    reregister_time = reregister_time.astimezone(datetime.timezone.utc)
                    logging.info(f'Reregistration will occur at: {reregister_time}')
                    reregister_delta = (reregister_time - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
                    logging.info(f'The time between now and reregistration time is: {(reregister_delta / 3600):.2f} hours or {(reregister_delta / 86400):.2f} days')
                    if reregister_delta > 3600:
                        logging.info('Certificates expiration is greater than 60 minutes, quiting')
                    else:
                        logging.info('Certificate expires soon, reregistering now')
                        expiration = await reregister(conn, users)
                        logging.info('Reregistered')

        elif args.reregister:
            await reregister(conn, users)

        print("Done!")

        if args.alive:
            logging.getLogger("apns").setLevel(logging.DEBUG)
            while True:
                await trio.sleep(20)

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
    parser.add_argument("--reg-notify", action="store_true", help="Get iMessage after each registration")
    parser.add_argument("--alive", action="store_true", help="Keep the connection alive")
    parser.add_argument("--client-data", action="store_true", help="Publish client data (only necessary for actually sending/receiving messages)")
    parser.add_argument("--trigger-pdu", action="store_true", help="Trigger a REG-REQ")
    # String arg to override pdu
    parser.add_argument("--pdu", type=str, help="Override the PDU REG-RESP")
    parser.add_argument("--phone", type=str, help="Override the phone IP")
    parser.add_argument("--gateway", type=str, help="Override the gateway phone number")
    parser.add_argument("--daemon", action="store_true", help="Continuously reregister 5 minutes before the certificate expires")
    parser.add_argument("--cronreg", action="store_true", help="Reregister if less than 60 minutes from expiration")

    args = parser.parse_args()
    
    if args.pdu is not None and not args.pdu.startswith("REG-RESP"):
        raise InvalidResponseError("Received invalid REG-RESP PDU from Gateway Client.")

    trio.run(main, args)
