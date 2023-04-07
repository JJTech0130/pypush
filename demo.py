import apns
from base64 import b64decode, b64encode
from hashlib import sha1

conn1 = apns.APNSConnection()
conn1.connect()
conn1.keep_alive()
conn1.set_state(0x01)
print(f"Push Token 1: {b64encode(conn1.token).decode()}")

#while True:
#    pass
conn1.filter([])
conn1.connect(False)
print(f"User Token 1: {b64encode(conn1.token).decode()}")

# conn2 = apns.APNSConnection()
# conn2.connect()
# conn2.filter([])
# print(f"Push Token 2: {b64encode(conn2.token).decode()}")
# conn2.connect(False)
# print(f"User Token 2: {b64encode(conn2.token).decode()}")

conn1.filter(["com.apple.madrid"])
# conn2.filter(["com.apple.madrid"])

conn1.send_message(b"\xe5^\xc0c\xe8\xa4\x1e\xbe\x03\x89'\xea\xd5m\x94\x05\xae\xf5\x1bqK\x1aJTH\xa4\xeb8\xb8<\xd7)", "com.apple.madrid", b'bplist00\xdd\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x13\x17\x18\x19ScdrRtPRgdQiRsPRnrQcQUQtScdvRuaRqHQvM\x08\xd6\xf3\xe6\x8d\x04\x18\x95\xfd\xea\xe9\xf50_\x10\x10tel:+16106632676\t\x12=\x12c&_\x10\x1amailto:jjgill07@icloud.com\x10\x01\x10mO\x10\x10UC>\x9f\xce\xa4N\xe0\xba\xe9\xad\x8e_h\xd7hO\x10 \xe5^\xc0c\xe8\xa4\x1e\xbe\x03\x89\'\xea\xd5m\x94\x05\xae\xf5\x1bqK\x1aJTH\xa4\xeb8\xb8<\xd7)_\x10#[macOS,13.2.1,22D68,MacBookPro18,3]O\x10!\x01\x97\xca\\"\xcaI\x82\x0c\xb66C\xa7\x89h\x91\xcd\x18Ozj"\x06u;9\x96\xebrQs|=\x10\x08\x00\x08\x00#\x00\'\x00*\x00-\x00/\x002\x005\x007\x009\x00;\x00?\x00B\x00E\x00G\x00U\x00h\x00i\x00n\x00\x8b\x00\x8d\x00\x8f\x00\xa2\x00\xc5\x00\xeb\x01\x0f\x00\x00\x00\x00\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x11')


# while True:
#     print(conn1.expect_message())
    #print(conn2.expect_message())
#print(conn1.expect_message())
#print(conn2.expect_message())
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