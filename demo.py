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

if CONFIG.get("id", {}).get("cert") is not None:
    id_keypair = ids._helpers.KeyPair(CONFIG["id"]["key"], CONFIG["id"]["cert"])
    user.restore_identity(id_keypair)
else:
    #vd = input_multiline("Enter validation data: ")
    import emulated.nac
    vd = emulated.nac.generate_validation_data()
    vd = b64encode(vd).decode()
    raise Exception("No")
    user.register(vd)

print(user.lookup(["mailto:textgpt@icloud.com"]))

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

with open("config.json", "w") as f:
    json.dump(CONFIG, f, indent=4)
