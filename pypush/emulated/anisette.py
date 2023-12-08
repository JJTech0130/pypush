# Add parent directory to path
import sys
sys.path.append(".")
from websockets.sync.client import connect
import json
from base64 import b64encode
import random
from pypush import bags
import requests
import plistlib
import icloud.gsa as gsa

ANISETTE_SERVER = "wss://ani.sidestore.io/v3/provisioning_session"

START_PROVISIONING_URL = bags.grandslam_bag()["urls"]["midStartProvisioning"]
FINISH_PROVISIONING_URL = bags.grandslam_bag()["urls"]["midFinishProvisioning"]


def start_provisioning() -> str: # returns spim
    body = {
        "Header": {},
        "Request": {}
    }
    body = plistlib.dumps(body)
    r = requests.post(START_PROVISIONING_URL, verify=False, data=body, headers= {
        "X-Mme-Client-Info": gsa.build_client(),
        "User-Agent": gsa.USER_AGENT,
    })
    b = plistlib.loads(r.content)
    return b['Response']['spim']

identifier = b64encode(random.randbytes(16)).decode()

spim = ""
cpim = ""

with connect(ANISETTE_SERVER) as websocket:
    # Handle messages as the server sends them
    while True:
        message = json.loads(websocket.recv())
        print(f"Received: {message}")

        if message["result"] == "GiveIdentifier":
            websocket.send(json.dumps({
                "identifier": identifier,
            }))
        elif message["result"] == "GiveStartProvisioningData":
            spim = start_provisioning()
            websocket.send(json.dumps({
                "spim": spim,
            }))
        elif message["result"] == "GiveEndProvisioningData":

            if 'cpim' in message:
                cpim = message['cpim']

        elif message["result"] == "Timeout":
            break