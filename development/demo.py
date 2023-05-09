import apns
import ids

conn1 = apns.APNSConnection()
conn1.connect()

# Uncomment these for greater parity with apsd
# conn1.keep_alive()
# conn1.set_state(0x01)
# conn1.filter([])
# conn1.connect(False)

conn1.filter(["com.apple.madrid"])

# print(ids.lookup(conn1, ["mailto:jjtech@jjtech.dev"]))

#print(ids.register(conn1, "user_test2@icloud.com", "wowSecure1"))
