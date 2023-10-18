# Add parent directory to path
import sys
sys.path.append("..")
sys.path.append(".")

import gsa
import requests
import uuid
import plistlib
from base64 import b64encode, b64decode

# Prompt for username and password
USERNAME = input("Username: ")
PASSWORD = input("Password: ")

anisette = gsa.Anisette()

print("Anisette headers:", anisette.generate_headers())


print("Authenticating with Grand Slam...")
g = gsa.authenticate(USERNAME, PASSWORD, anisette)
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
    "X-Mme-Nas-Qualify": b64encode(v),
    "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"
}
headers.update(anisette.generate_headers())
# Otherwise we get MOBILEME_TERMS_OF_SERVICE_UPDATE on some accounts
# Really should just change it in gsa.py
headers["X-Mme-Client-Info"]= "<MacBookPro18,3> <Mac OS X;13.4.1;22F82> <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
#print(headers)

print("Logging in to iCloud...")
r = requests.post(
    "https://setup.icloud.com/setup/prefpane/login",
    auth=(USERNAME, pet),
    data=data,
    headers=headers,
    verify=False,

)
#print(r.headers)
r = plistlib.loads(r.content)
#import json

#print(json.dumps(r, indent=4))

print("Logged in!")

print("Search Party Token: ", r['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken'])