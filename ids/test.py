import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import _helpers
import struct
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def sign_prekey():
    pre_key = _helpers.create_compactable_key()
    device_key = _helpers.create_compactable_key()
    print("DEV PRIV KEY: " + _helpers.parse_key(device_key).private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()).hex())
    timestamp = time.time()
    # Set decimal to 0
    timestamp = float(int(timestamp))
    to_sign = b"NGMPrekeySignature" + _helpers.compact_key(_helpers.parse_key(pre_key)) + struct.pack("<d", timestamp)
    print("EXPECTED: " + to_sign.hex())
    # Extend to the next multiple of 8
    #to_sign += b"\x00" * (8 - (len(to_sign) % 8))
    #print(to_sign)
    signed = _helpers.parse_key(device_key).sign(to_sign, ec.ECDSA(hashes.SHA256()))
    # Decode the signature into the tuple
    a,b = decode_dss_signature(signed)
    
    print("SIGNED: " + a.to_bytes(32, "big").hex() + b.to_bytes(32, "big").hex())


    #print("SIGNED: " + signed.hex())

    print("DEVICE KEY: " + _helpers.parse_key(device_key).public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex())

sign_prekey()