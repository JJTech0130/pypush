import ids
import apns
from getpass import getpass
import json
from base64 import b64encode

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


conn = apns.APNSConnection(CONFIG.get("push", {}).get("key"), CONFIG.get("push", {}).get("cert"))
conn.connect(CONFIG.get("push", {}).get("token"))

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

vd = input_multiline("Enter validation data: ")
user.register(vd)

# Write config.json
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