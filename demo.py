import plistlib
import zlib
from base64 import b64decode, b64encode
from hashlib import sha1

import apns
import ids

conn1 = apns.APNSConnection()
conn1.connect()
conn1.keep_alive()
conn1.set_state(0x01)
conn1.filter([])
conn1.connect(False)
conn1.filter(["com.apple.madrid"])

print(ids.lookup(conn1, ["mailto:jjtech@jjtech.dev"]))
