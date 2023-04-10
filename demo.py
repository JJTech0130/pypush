import apns
from base64 import b64decode, b64encode
from hashlib import sha1
import plistlib, zlib

conn1 = apns.APNSConnection()
conn1.connect()
conn1.keep_alive()
conn1.set_state(0x01)
conn1.filter([])
conn1.connect(False)
conn1.filter(["com.apple.madrid"])

# See ids.py for something useful