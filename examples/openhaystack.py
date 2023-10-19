# Add parent directory to path
import sys
sys.path.append("..")
sys.path.append(".")

import gsa
import requests
import uuid
import plistlib
from base64 import b64encode, b64decode
import json

CONFIG_PATH = "examples/openhaystack.json"
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

    print("Authenticating with Grand Slam...")
    g = gsa.authenticate(USERNAME, PASSWORD)
    #print(g)
    pet = g["t"]["com.apple.gs.idms.pet"]["token"]
    print("Authenticated!")
    #print(g)

    data = {
        "apple-id": USERNAME,
        #"delegates": {"com.apple.private.ids": {"protocol-version": "4"}},
        "delegates": {"com.apple.mobileme": {}},
        "password": pet,
        "client-id": str(uuid.uuid4()),

    }
    data = plistlib.dumps(data)
    from emulated import nac

    print("Generating validation data...")
    v = nac.generate_validation_data()
    print("Generated validation data!")

    headers = {
        "X-Apple-ADSID": g["adsid"],
        "X-Mme-Nas-Qualify": b64encode(v).decode(),
        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
        "X-Mme-Client-Info": gsa.build_client(emulated_app="accountsd") # Otherwise we get MOBILEME_TERMS_OF_SERVICE_UPDATE on some accounts
    }
    headers.update(gsa.generate_anisette_headers())

    print(headers)

    print("Logging in to iCloud...")
    r = requests.post(
        "https://setup.icloud.com/setup/prefpane/login",
        auth=(USERNAME, pet),
        data=data,
        headers=headers,
        verify=False,
    )

    print(r)
    print(r.headers)
    r = plistlib.loads(r.content)
    print(r)

    search_party_token = r['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']
    ds_prs_id = r['delegates']['com.apple.mobileme']['service-data']['appleAccountInfo']['dsPrsID'] # This can also be obtained from the grandslam response

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
}
    
)

#print(r.headers)
if r.status_code != 200 or len(r.content) == 0:
    print("Error fetching locations (ratelimit?): ", r.status_code, r.headers)
    exit(1)
r = r.content.decode()
print(json.dumps(json.loads(r), indent=4))