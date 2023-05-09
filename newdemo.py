import ids
import apns
from getpass import getpass


conn = apns.APNSConnection()
conn.connect()

username = input("Username: ")
password = getpass("Password: ")
user = ids.IDSUser(conn, username, password)

print(user.handles)