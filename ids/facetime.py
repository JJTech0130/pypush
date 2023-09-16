from ids import IDSUser
import logging
logger = logging.getLogger("ids")
import plistlib
from ids._helpers import PROTOCOL_VERSION, KeyPair, parse_key, serialize_key
from ids.signing import add_auth_signature, armour_cert, add_id_signature, add_push_signature
import requests
from base64 import b64decode, b64encode

async def provision_alias(user: IDSUser):
#     <?xml version="1.0" encoding="UTF-8"?>
# <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
# <plist version="1.0">
#   <dict>
#     <key>attributes</key>
#     <dict>
#       <key>allowedServices</key>
#       <dict>
#         <key>com.apple.private.alloy.facetime.multi</key>
#         <array/>
#       </dict>
#       <key>expiry-epoch-seconds</key>
#       <real>1726418686.6028981</real>
#       <key>featureId</key>
#       <string>Gondola</string>
#     </dict>
#     <key>operation</key>
#     <string>create</string>
#   </dict>
    import time
    logger.debug(f"Adding new temp alias")
    body = {
        "attributes": {
            "allowedServices": {
                "com.apple.private.alloy.facetime.multi": []
            },
            # Unix timestamp in seconds, with decimal places, for 1 year from now
            "expiry-epoch-seconds": time.time() + 31536000,
            "featureId": "Gondola"
        },
        "operation": "create"
    }
    body = plistlib.dumps(body)

    headers = {
        "x-protocol-version": PROTOCOL_VERSION,
       # "x-auth-user-id-0": user.user_id,
        "x-id-self-uri": "mailto:testu3@icloud.com"
    }
    #add_auth_signature(headers, body, "id-register", user._auth_keypair, user._push_keypair, b64encode(user.push_connection.credentials.token), 0)
    add_push_signature(headers, body, "id-provision-alias", user._push_keypair, b64encode(user.push_connection.credentials.token))
    add_id_signature(headers, body, "id-provision-alias", user._id_keypair, b64encode(user.push_connection.credentials.token))

    r = requests.post(
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/provisionAlias",
        headers=headers,
        data=body,
        verify=False,
    )
    r = plistlib.loads(r.content)

    print(r)
