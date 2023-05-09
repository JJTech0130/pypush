from ._helpers import KeyPair, PROTOCOL_VERSION, USER_AGENT
from base64 import b64decode
import plistlib
import requests
from .signing import add_auth_signature

def register_request(
    push_token, handles, uid, auth_key: KeyPair, push_key: KeyPair, validation_data
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
                        # TODO: Pass ALL URIs from get handles
                        "uris": uris,
                        "user-id": uid,
                    }
                ],
            }
        ],
        "validation-data": b64decode(validation_data),
    }

    body = plistlib.dumps(body)

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
        "x-auth-user-id-0": uid,
    }
    add_auth_signature(
        headers, body, "id-register", auth_key, push_key, push_token, 0
    )

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
    return r