from collections import namedtuple

USER_AGENT = "com.apple.madrid-lookup [macOS,13.2.1,22D68,MacBookPro18,3]"
PROTOCOL_VERSION = "1640"

# KeyPair is a named tuple that holds a key and a certificate in PEM form
KeyPair = namedtuple("KeyPair", ["key", "cert"])

def dearmour(armoured: str) -> str:
    import re
    # Use a regex to remove the header and footer (generic so it work on more than just certificates)
    return re.sub(r"-----BEGIN .*-----|-----END .*-----", "", armoured).replace("\n", "")