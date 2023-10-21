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
import random

CONFIG_PATH = "examples/cloudkit.json"
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

import cloudkit_pb2

# header {
#   applicationContainer: "iCloud.dev.jjtech.experiments.cktest"
#   applicationBundle: "dev.jjtech.experiments.cktest"
#   applicationVersion: "1"
#   deviceIdentifier {
#     name: "776D147D-DAF3-495F-A834-12526DAECA5C"
#     type: DEVICE
#   }
#   deviceSoftwareVersion: "13.4.1"
#   deviceHardwareVersion: "MacBookPro18,3"
#   deviceLibraryName: "com.apple.cloudkit.CloudKitDaemon"
#   deviceLibraryVersion: "2060.11"
#   locale {
#     languageCode: "en-US"
#     regionCode: "US"
#   }
#   mmcsProtocolVersion: "5.0"
#   applicationContainerEnvironment: SANDBOX
#   deviceAssignedName: "James\342\200\231s Laptop"
#   deviceHardwareID: "776D147D-DAF3-495F-A834-12526DAECA5C"
#   targetDatabase: PUBLIC_DB
#   isolationLevel: ZONE
#   unk1: 0
#   unk2: "7B40B37D-2503-5161-9B4E-84D20478694C"
#   deviceSerial: "X5T0QFNHXP"
#   unk3: 0
#   unk4: 1
# }
# request {
#   operationUUID: "B1FC75B3-D69E-4368-BD0A-93170C7A3017"
#   type: RECORD_SAVE_TYPE
#   last: true
# }
# recordSaveRequest {
#   record {
#     recordIdentifier {
#       value {
#         name: "699F278B-1381-4480-8297-7751B88B8F06"
#         type: RECORD
#       }
#       zoneIdentifier {
#         value {
#           name: "_defaultZone"
#           type: RECORD_ZONE
#         }
#         ownerIdentifier {
#           name: "_defaultOwner"
#           type: USER
#         }
#       }
#     }
#     type {
#       name: "ToDoItem"
#     }
#     recordField {
#       identifier {
#         name: "name"
#       }
#       value {
#         type: STRING_TYPE
#         stringValue: "Test item"
#       }
#     }
#   }
#   unk1: 1
#   unk2: 2
# }

from typing import Literal

#def build_cloudkit_record_save_request(container: str, sandbox: bool, database: Literal["PUBLIC"] | Literal["PRIVATE"] | Literal["SHARED"], zone: str, ):

request = cloudkit_pb2.RequestOperation()
request.header.applicationContainer = "iCloud.dev.jjtech.experiments.cktest"
#request.header.applicationBundle = "dev.jjtech.experiments.cktest"
#request.header.applicationVersion = "1"
#request.header.deviceIdentifier.name = "776D147D-DAF3-495F-A834-12526DAECA5C"
#request.header.deviceIdentifier.type = cloudkit_pb2.Identifier.Type.DEVICE
#request.header.deviceSoftwareVersion = "13.4.1"
#request.header.deviceHardwareVersion = "MacBookPro18,3"
#request.header.deviceLibraryName = "com.apple.cloudkit.CloudKitDaemon"
#request.header.deviceLibraryVersion = "2060.11"
#request.header.locale.languageCode = "en-US"
#request.header.locale.regionCode = "US"
#request.header.mmcsProtocolVersion = "5.0"
request.header.applicationContainerEnvironment = cloudkit_pb2.RequestOperation.Header.ContainerEnvironment.SANDBOX
#request.header.deviceAssignedName = "James’s Laptop"
request.header.deviceHardwareID = str(uuid.uuid4()).upper()
request.header.targetDatabase = cloudkit_pb2.RequestOperation.Header.Database.PUBLIC_DB
request.header.isolationLevel = cloudkit_pb2.RequestOperation.Header.IsolationLevel.ZONE
#request.header.unk1 = 0
#request.header.unk2 = "7B40B37D-2503-5161-9B4E-84D20478694C"
#request.header.deviceSerial = "X5T0QFNHXP"
#request.header.unk3 = 0
#request.header.unk4 = 1
request.request.operationUUID = str(uuid.uuid4()).upper()
request.request.type = cloudkit_pb2.Operation.Type.RECORD_SAVE_TYPE
request.request.last = True
request.recordSaveRequest.record.recordIdentifier.value.name = str(uuid.uuid4()).upper()
request.recordSaveRequest.record.recordIdentifier.value.type = cloudkit_pb2.Identifier.Type.RECORD
request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.value.name = "_defaultZone"
request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.value.type = cloudkit_pb2.Identifier.Type.RECORD_ZONE
request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.ownerIdentifier.name = "_defaultOwner"
request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.ownerIdentifier.type = cloudkit_pb2.Identifier.Type.USER
request.recordSaveRequest.record.type.name = "ToDoItem"
# RecordField is a repeated field, so we have to append to it
request.recordSaveRequest.record.recordField.append(cloudkit_pb2.Record.Field())
request.recordSaveRequest.record.recordField[0].identifier.name = "name"
request.recordSaveRequest.record.recordField[0].value.type = cloudkit_pb2.Record.Field.Value.Type.STRING_TYPE
request.recordSaveRequest.record.recordField[0].value.stringValue = "Test pypush 5"
#request.recordSaveRequest.record.recordField.identifier.name = "name"
#request.recordSaveRequest.record.recordField.value.type = cloudkit_pb2.Record.Field.Value.Type.STRING_TYPE
#request.recordSaveRequest.record.recordField.value.stringValue = "Test item"
#request.recordSaveRequest.unk1 = 1
#request.recordSaveRequest.unk2 = 2



# WHAT ARE THESE BYTES???
body = b"\xfe\x03" + request.SerializeToString()
r =requests.post(
    "https://gateway.icloud.com/ckdatabase/api/client/record/save",
    headers=headers,
    data=body,
    verify=False
)

print(r.content)
# import time 

# r = requests.post(
#     "https://gateway.icloud.com/acsnservice/fetch",
#     auth=(ds_prs_id, search_party_token),
#     headers=gsa.generate_anisette_headers(),
#     json={
#     "search": [
#         {
#             "startDate": 1697662550688,
#             "endDate": 1697673599999,
#             "ids": [
#                 "/a8rQOW7Ucg2OOBo0D3i/7IZAbvRXcO+5y/1w0QVE4s="
#             ]
#         }
#     ]
# }
    
# )

# #print(r.headers)
# if r.status_code != 200 or len(r.content) == 0:
#     print("Error fetching locations (ratelimit?): ", r.status_code, r.headers)
#     exit(1)
# r = r.content.decode()
# print(json.dumps(json.loads(r), indent=4))