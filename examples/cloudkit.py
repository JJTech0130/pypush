import sys 
sys.path.append(".")

import requests
import uuid
import plistlib
from base64 import b64encode, b64decode
import json
import random
import icloud.gsa as gsa
import icloud.cloudkit as cloudkit

from rich.logging import RichHandler
import logging
logging.basicConfig(
    level=logging.INFO, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
)

def main():
    CONFIG_PATH = "config/cloudkit.json"
    # See if we have a search party token saved
    import os
    if os.path.exists(CONFIG_PATH):
        print("Using saved config...")
        #print("Found search party token!")
        with open(CONFIG_PATH, "r") as f:
            j = json.load(f)
            cloudkit_token = j["cloudkit_token"]
            ds_prs_id = j["ds_prs_id"]
        
    else:
        # Prompt for username and password
        USERNAME = input("Username: ")
        PASSWORD = input("Password: ")

        r = icloud.login(USERNAME, PASSWORD, delegates=["com.apple.mobileme"])

        cloudkit_token = r['delegates']['com.apple.mobileme']['service-data']['tokens']['cloudKitToken']
        ds_prs_id = r['delegates']['com.apple.mobileme']['service-data']['appleAccountInfo']['dsPrsID'] # This can also be obtained from the grandslam response

        print("Logged in!")

        with open(CONFIG_PATH, "w") as f:
            json.dump({
                "cloudkit_token": cloudkit_token,
                "ds_prs_id": ds_prs_id,
                }, f, indent=4)
            
    print("CloudKit token: ", cloudkit_token)

    headers = {
        "x-cloudkit-authtoken": cloudkit_token,
        "x-cloudkit-userid": "_ec5fa262446ad56fb4bda84d00e981ff", # Hash of bundle id and icloud id
        "x-cloudkit-containerid": "iCloud.dev.jjtech.experiments.cktest",
        "x-cloudkit-bundleid": "dev.jjtech.experiments.cktest",
        "x-cloudkit-bundleversion": "1",
        "x-cloudkit-databasescope": "Public",
        "x-cloudkit-environment": "Sandbox",

        "accept": "application/x-protobuf",
        "content-type": 'application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true',

        "x-apple-operation-id": random.randbytes(8).hex(),
        "x-apple-request-uuid": str(uuid.uuid4()).upper()
    }

    headers.update(gsa.generate_anisette_headers())

    body = cloudkit.build_record_save_request(cloudkit.Record(uuid.uuid4(), "ToDoItem", {"title": "Test"}), "iCloud.dev.jjtech.experiments.cktest", sandbox=True)
    r = requests.post(
        "https://gateway.icloud.com/ckdatabase/api/client/record/save",
        headers=headers,
        data=body,
        verify=False
    )

    print(r.content)

if __name__ == "__main__":
    main()