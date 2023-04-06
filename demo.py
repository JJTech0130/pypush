import apns
from base64 import b64decode, b64encode

c = apns.APNSConnection()
print(f"Push Token: {b64encode(c.token).decode()}")