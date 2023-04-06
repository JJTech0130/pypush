import apns
from base64 import b64decode, b64encode

conn1 = apns.APNSConnection()
print(f"Push Token 1: {b64encode(conn1.token).decode()}")

conn2 = apns.APNSConnection(cert=conn1.cert, private_key=conn1.private_key, token=conn1.token)
print(f"Push Token 2: {b64encode(conn2.token).decode()}")