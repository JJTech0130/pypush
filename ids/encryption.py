from . import ids_pb2, _helpers

import struct,time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import logging
logger = logging.getLogger("ids")

class NGMIdentity:
    def __init__(self, device_key: str | None, pre_key: str | None):
        if device_key is None:
            device_key = _helpers.create_compactable_key()
        if pre_key is None:
            pre_key = _helpers.create_compactable_key()
        self.device_key = device_key
        self.pre_key = pre_key

    def sign_prekey(self):
        timestamp = time.time()
        # Set decimal to 0
        timestamp = float(int(timestamp))
        to_sign = b"NGMPrekeySignature" + _helpers.compact_key(_helpers.parse_key(self.pre_key)) + struct.pack("<d", timestamp)
        # Extend to the next multiple of 8
        #to_sign += b"\x00" * (8 - (len(to_sign) % 8))
        #print(to_sign)
        signed = _helpers.parse_key(self.device_key).sign(to_sign, ec.ECDSA(hashes.SHA256()))
        a,b = decode_dss_signature(signed)
        signed = a.to_bytes(32, "big") + b.to_bytes(32, "big")
    
   # print("SIGNED: " + a.to_bytes(32, "big").hex() + b.to_bytes(32, "big").hex())
        # print(signed)

        # print("device")
        # print(_helpers.compact_key(_helpers.parse_key(self.device_key)))
        # print("pre")
        # print(_helpers.compact_key(_helpers.parse_key(self.pre_key)))

        prekey_signed = ids_pb2.PublicDevicePrekey()
        prekey_signed.prekeySignature = signed
        prekey_signed.prekey = _helpers.compact_key(_helpers.parse_key(self.pre_key))
        prekey_signed.timestamp = timestamp

        return prekey_signed.SerializeToString()


    def generate_loggable_data(self):
        identity = ids_pb2.NgmPublicIdentity()
        identity.publicKey = _helpers.compact_key(_helpers.parse_key(self.device_key))

        loggable_data = ids_pb2.KeyTransparencyLoggableData()
        loggable_data.ngmPublicIdentity = identity.SerializeToString()
        loggable_data.ngmVersion = 12                                                                                                                                                            
        loggable_data.ktVersion = 0

        return loggable_data.SerializeToString()
        



def parse_loggable_data(data: bytes):
    # Parse as a LoggableData
    loggable_data = ids_pb2.KeyTransparencyLoggableData()
    loggable_data.ParseFromString(data)
    #print(loggable_data)

    logger.debug(f"LoggableData: {loggable_data}")
    
    identity = ids_pb2.NgmPublicIdentity()
    identity.ParseFromString(loggable_data.ngmPublicIdentity)

    key = _helpers.parse_compact_key(identity.publicKey)

    return key

def create_loggable_data():
    """
    This function must create the key so we know it fits in the compact format
    """

    pub, key = _helpers.create_compact_key()

    identity = ids_pb2.NgmPublicIdentity()
    identity.publicKey = pub

    loggable_data = ids_pb2.KeyTransparencyLoggableData()
    loggable_data.ngmPublicIdentity = identity.SerializeToString()
    loggable_data.ngmVersion = 12                                                                                                                                                            
    loggable_data.ktVersion = 5 



    return loggable_data.SerializeToString(), key

    