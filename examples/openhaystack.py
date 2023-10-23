# Add parent directory to path
import sys
sys.path.append(".")

import icloud.gsa as gsa
import requests
import uuid
import plistlib
from base64 import b64encode, b64decode
import json
import icloud

from rich.logging import RichHandler
import logging
logging.basicConfig(
    level=logging.INFO, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

CONFIG_PATH = "config/openhaystack.json"
# See if we have a search party token saved
import os
if os.path.exists(CONFIG_PATH):
    print("Using saved config...")
    #print("Found search party token!")
    with open(CONFIG_PATH, "r") as f:
        j = json.load(f)
        search_party_token = j["search_party_token"]
        ds_prs_id = j["ds_prs_id"]
    
else:
    # Prompt for username and password
    USERNAME = input("Username: ")
    PASSWORD = input("Password: ")

    r = icloud.login(USERNAME, PASSWORD, delegates=["com.apple.mobileme"])

    search_party_token = r['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']
    #ds_prs_id = r['delegates']['com.apple.mobileme']['service-data']['appleAccountInfo']['dsPrsID'] # This can also be obtained from the grandslam response
    ds_prs_id = r['dsid']

    print("Logged in!")

    with open(CONFIG_PATH, "w") as f:
        json.dump({
            "search_party_token": search_party_token,
            "ds_prs_id": ds_prs_id,
            }, f, indent=4)

import time 

r = requests.post(
    "https://gateway.icloud.com/acsnservice/fetch",
    auth=(ds_prs_id, search_party_token),
    headers=gsa.generate_anisette_headers(),
    json={
        "search": [
            {
                "startDate": 1697662550688,
                "endDate": 1697673599999,
                "ids": [
                    "/a8rQOW7Ucg2OOBo0D3i/7IZAbvRXcO+5y/1w0QVE4s="
                ]
            }
        ]
    },
    verify=False,
)

#print(r.headers)
if r.status_code != 200 or len(r.content) == 0:
    print("Error fetching locations (ratelimit?): ", r.status_code, r.headers)
    exit(1)
r = r.content.decode()
print(json.dumps(json.loads(r), indent=4))