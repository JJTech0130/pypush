from ids import *
import ids
import getpass
import json

# Open config
try:
    with open("config.json", "r") as f:
        config = json.load(f)
except FileNotFoundError:
    config = {}

# If no username is set, prompt for it
if "username" not in config:
    config["username"] = input("Enter iCloud username: ")
# If no password is set, prompt for it
if "password" not in config:
    config["password"] = getpass.getpass("Enter iCloud password: ")
# If grandslam authentication is not set, prompt for it
if "use_gsa" not in config:
    config["use_gsa"] = input("Use grandslam authentication? [y/N] ").lower() == "y"

def factor_gen():
    return input("Enter iCloud 2FA code: ")

user_id, token = ids._get_auth_token(
    config["username"], config["password"], config["use_gsa"], factor_gen=factor_gen
)

config["user_id"] = user_id
config["token"] = token

key, cert = ids._get_auth_cert(user_id, token)

config["key"] = key
config["cert"] = cert

conn1 = apns.APNSConnection()
conn1.connect()

conn1.filter(["com.apple.madrid"])

info = {
    "uri": "mailto:" + config["username"],
    "user_id": user_id,
}

resp = None
try:
    if "validation_data" in config:
        resp = ids._register_request(
            b64encode(conn1.token),
            info,
            cert,
            key,
            conn1.cert,
            conn1.private_key,
            config["validation_data"],
        )
except Exception as e:
    print(e)
    resp = None

if resp is None:
    print(
        "Note: Validation data can be obtained from @JJTech, or intercepted using a HTTP proxy."
    )
    validation_data = (
        input_multiline("Enter validation data: ")
        .replace("\n", "")
        .replace(" ", "")
    )
    resp = ids._register_request(
        b64encode(conn1.token),
        info,
        cert,
        key,
        conn1.cert,
        conn1.private_key,
        validation_data,
    )
    config["validation_data"] = validation_data

madrid_cert = x509.load_der_x509_certificate(
    resp["services"][0]["users"][0]["cert"]
)
madrid_cert = (
    madrid_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8").strip()
)

config["madrid_cert"] = madrid_cert

# Save config
with open("config.json", "w") as f:
    json.dump(config, f, indent=4)