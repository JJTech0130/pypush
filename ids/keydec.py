from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from base64 import b64decode, b64encode

from io import BytesIO

class IdentityKeys():
    def __init__(self, ecdsa_key: ec.EllipticCurvePublicKey, rsa_key: rsa.RSAPublicKey):
        self.ecdsa_key = ecdsa_key
        self.rsa_key = rsa_key
    
    def decode(input: bytes) -> 'IdentityKeys':
        input = BytesIO(input)

        assert input.read(5) == b'\x30\x81\xF6\x81\x43' # DER header
        raw_ecdsa = input.read(67)
        assert input.read(3) == b'\x82\x81\xAE' # DER header
        raw_rsa = input.read(174)

        # Parse the RSA key
        raw_rsa = BytesIO(raw_rsa)
        assert raw_rsa.read(2) == b'\x00\xAC' # Not sure what this is
        assert raw_rsa.read(3) == b'\x30\x81\xA9' # Inner DER header
        assert raw_rsa.read(3) == b'\x02\x81\xA1'
        rsa_modulus = raw_rsa.read(161)
        rsa_modulus = int.from_bytes(rsa_modulus, "big")
        assert raw_rsa.read(5) == b'\x02\x03\x01\x00\x01' # Exponent, should always be 65537

        # Parse the EC key
        assert raw_ecdsa[:3] == b'\x00\x41\x04'
        raw_ecdsa = raw_ecdsa[3:]
        ec_x = int.from_bytes(raw_ecdsa[:32], "big")
        ec_y = int.from_bytes(raw_ecdsa[32:], "big")

        ec_key = ec.EllipticCurvePublicNumbers(ec_x, ec_y, ec.SECP256R1())
        ec_key = ec_key.public_key()

        rsa_key = rsa.RSAPublicNumbers(e=65537, n=rsa_modulus)
        rsa_key = rsa_key.public_key()

        return IdentityKeys(ec_key, rsa_key)
    
    def encode(self) -> bytes:
        output = BytesIO()

        raw_rsa = BytesIO()
        raw_rsa.write(b'\x00\xAC')
        raw_rsa.write(b'\x30\x81\xA9')
        raw_rsa.write(b'\x02\x81\xA1')
        raw_rsa.write(self.rsa_key.public_numbers().n.to_bytes(161, "big"))
        raw_rsa.write(b'\x02\x03\x01\x00\x01') # Hardcode the exponent

        output.write(b'\x30\x81\xF6\x81\x43')
        output.write(b'\x00\x41\x04')
        output.write(self.ecdsa_key.public_numbers().x.to_bytes(32, "big"))
        output.write(self.ecdsa_key.public_numbers().y.to_bytes(32, "big"))

        output.write(b'\x82\x81\xAE')
        output.write(raw_rsa.getvalue())

        return output.getvalue()
        
if __name__ == "__main__":
    input_key = """MIH2gUMAQQSYmvE+hYOWVGotZUCd
						        M6zoW/2clK8RIzUtE6JAmWSCwj7d
                                B213vxEBNAPHefEtlxkVKlQH6bsw
                                ja5qYyl3Fh28goGuAKwwgakCgaEA
                                4lw3MrXOFIWWIi3TTUGksXVCIz92
                                R3AG3ghBa1ZBoZ6rIJHeuxhD2vTV
                                hicpW7kvZ/+AFgE4vFFef/9TjG6C
                                rsBtWUUfPtYHqc7+uaghVW13qfYC
                                tdGsW8Apvf6MJqsRmITJjoYZ5kwl
                                scp5Xw/1KVQzKMfZrwZeLC/UZ6O1
                                41u4Xvm+u40e+Ky/wMCOwLGBG0Ag
                                ZBH91Xrq+S8izgSLmQIDAQAB""".replace("\n", "").replace(" ", "").replace("\t", "")
    keys = IdentityKeys.decode(b64decode(input_key))
    print(b64encode(keys.encode()).decode())
    print(len(keys.encode()))
    print(len(b64decode(input_key)))
    print(keys.encode() == b64decode(input_key))
    print(keys.rsa_key.key_size)