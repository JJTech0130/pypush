
# LOW LEVEL imessage function, decryption etc
# Don't handle APNS etc, accept it already setup

## HAVE ANOTHER FILE TO SETUP EVERYTHING AUTOMATICALLY, etc
# JSON parsing of keys, don't pass around strs??

import apns
import ids

class iMessageUser:
    def __init__(self, apns: apns.APNSConnection, ids: ids.IDSUser, encryption_key: str, signing_key: str):
        self.apns = apns
        self.ids = ids
        self.encryption_key = encryption_key
        self.signing_key = signing_key

    def _get_raw_messages(self) -> list[dict]:
        pass

    def _send_raw_message(self, message: dict):
        pass

    def _decrypt_message(self, message: dict) -> dict:
        pass

    def _encrypt_message(self, message: dict) -> dict:
        pass

    def _sign_message(self, message: dict) -> dict:
        pass

    def _verify_message(self, message: dict) -> dict:
        pass

    def get_messages(self) -> list[dict]:
        pass
