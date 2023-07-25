import plistlib
from base64 import b64decode

import requests

from ._helpers import PROTOCOL_VERSION, USER_AGENT, KeyPair
from .signing import add_auth_signature, armour_cert
from .keydec import IdentityKeys

import logging
logger = logging.getLogger("ids")


def register(
    push_token, handles, user_id, auth_key: KeyPair, push_key: KeyPair, published_keys: IdentityKeys, validation_data
):
    logger.debug(f"Registering IDS identity for {handles}")
    uris = [{"uri": handle} for handle in handles]

    body = {
        "hardware-version": "MacBookPro18,3",
        "language": "en-US",
        "os-version": "macOS,13.2.1,22D68",
        "software-version": "22D68",
        "services": [
            {
                "capabilities": [{"flags": 17, "name": "Messenger", "version": 1}],
                "service": "com.apple.madrid",
                "users": [
                    {
                        "client-data": {
                            'is-c2k-equipment': True,
						    'optionally-receive-typing-indicators': True,
						    'public-message-identity-key': published_keys.encode(),
                            # 'public-message-identity-key': b64decode("""MIH2gUMAQQSYmvE+hYOWVGotZUCd
						    #     M6zoW/2clK8RIzUtE6JAmWSCwj7d
                            #     B213vxEBNAPHefEtlxkVKlQH6bsw
                            #     ja5qYyl3Fh28goGuAKwwgakCgaEA
                            #     4lw3MrXOFIWWIi3TTUGksXVCIz92
                            #     R3AG3ghBa1ZBoZ6rIJHeuxhD2vTV
                            #     hicpW7kvZ/+AFgE4vFFef/9TjG6C
                            #     rsBtWUUfPtYHqc7+uaghVW13qfYC
                            #     tdGsW8Apvf6MJqsRmITJjoYZ5kwl
                            #     scp5Xw/1KVQzKMfZrwZeLC/UZ6O1
                            #     41u4Xvm+u40e+Ky/wMCOwLGBG0Ag
                            #     ZBH91Xrq+S8izgSLmQIDAQAB""".replace("\n", "").replace(" ", "").replace("\t", "")),
						    'public-message-identity-version':2,
                            'show-peer-errors': True,
                            'supports-ack-v1': True,
                            'supports-activity-sharing-v1': True,
                            'supports-audio-messaging-v2': True,
                            "supports-autoloopvideo-v1": True,
                            'supports-be-v1': True,
                            'supports-ca-v1': True,
                            'supports-fsm-v1': True,
                            'supports-fsm-v2': True,
                            'supports-fsm-v3': True,
                            'supports-ii-v1': True,
                            'supports-impact-v1': True,
                            'supports-inline-attachments': True,
                            'supports-keep-receipts': True,
                            "supports-location-sharing": True,
                            'supports-media-v2': True,
                            'supports-photos-extension-v1': True,
                            'supports-st-v1': True,
                            'supports-update-attachments-v1': True,
                        },
                        "uris": uris,
                        "user-id": user_id,
                    }
                ],
            }
        ],
        "validation-data": b64decode(validation_data),
    }

    body = plistlib.dumps(body)

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id-0": user_id,
    }
    add_auth_signature(headers, body, "id-register", auth_key, push_key, push_token, 0)

    r = requests.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register",
        headers=headers,
        data=body,
        verify=False,
    )
    r = plistlib.loads(r.content)
    #print(f'Response code: {r["status"]}')
    logger.debug(f"Recieved response to IDS registration: {r}")
    if "status" in r and r["status"] == 6004:
        raise Exception("Validation data expired!")
    # TODO: Do validation of nested statuses
    if "status" in r and r["status"] != 0:
        raise Exception(f"Failed to register: {r}")
    if not "services" in r:
        raise Exception(f"No services in response: {r}")
    if not "users" in r["services"][0]:
        raise Exception(f"No users in response: {r}")
    if not "cert" in r["services"][0]["users"][0]:
        raise Exception(f"No cert in response: {r}")

    return armour_cert(r["services"][0]["users"][0]["cert"])
