import plistlib
from base64 import b64decode

import requests

from ._helpers import PROTOCOL_VERSION, USER_AGENT, KeyPair
from .signing import add_auth_signature, armour_cert


def register(
    push_token, handles, user_id, auth_key: KeyPair, push_key: KeyPair, validation_data
):
    uris = [{"uri": handle} for handle in handles]

    body = {
        "hardware-version": "MacBookPro18,3",
        "language": "en-US",
        "os-version": "macOS,13.2.1,22D68",
        "software-version": "22D68",
        "services": [
            {
                "capabilities": [{"flags": 1, "name": "Messenger", "version": 1}],
                "service": "com.apple.madrid",
                "users": [
                    {
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
    print(f'Response code: {r["status"]}')
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
