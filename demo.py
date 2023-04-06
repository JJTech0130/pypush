import apns
from base64 import b64decode, b64encode
from hashlib import sha1

conn1 = apns.APNSConnection()
conn1.connect()
print(f"Push Token 1: {b64encode(conn1.token).decode()}")

conn2 = apns.APNSConnection()
conn2.connect()
print(f"Push Token 2: {b64encode(conn2.token).decode()}")

conn1.filter(["com.apple.madrid"])
conn2.filter(["com.apple.madrid"])

# #print(sha1(b"com.apple.madrid").digest())
# # Send a notification
# # expiry timestamp in UNIX epoch
# expiry = 1680761868
# expiry = expiry.to_bytes(4, "big")

# # Current time in UNIX nano epoch
# import time
# now = int(time.time() * 1000).to_bytes(8, "big")

# payload = apns.Payload(0x0a, apns.Fields({1: sha1(b"com.apple.madrid").digest(), 2: conn2.token, 3: b"Hello World!", 4: 0x00.to_bytes(), 5: expiry, 6: now, 7: 0x00.to_bytes()}))
# conn1.sock.write(payload.to_bytes())

# print("Waiting for response...")

# # Check if the notification was sent
# resp = apns.Payload.from_stream(conn1.sock)
# print(resp)

# # Read the message from the other connection
# resp = apns.Payload.from_stream(conn2.sock)
# print(resp)