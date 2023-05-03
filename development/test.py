import hashlib
import plistlib
import zlib
from base64 import b64decode

import ids

with open("body.txt", "r") as f:
    BODY = f.read()

CERT = "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"
SIG = "AQEZs/u9Ptb8AmFpCv5XgzUsskvcleZDBxYTe5JOoshFCxpnByTwFA0mxplklHqT2rTEeF+Bu0Bo0vEPlh9KslmIoQLo6ej25bbtFN07dnHNwd84xzQzWBa4VHLQE1gNjSpcorppxpAUon/eFRu5yRxmwQVmqo+XmmxSuFCzxUaAZAPFPDna+8tvRwd0q3kuK9b0w/kuT16X1SL166fFNzmsQGcBqob9C9xX0VlYGqSd4K975gWdYsPo/kiY0ni4Q130oc6oAANr8ATN0bEeAO6/AfVM2aqHJTGlYlekBFWf8Tp8AJLUc4cm676346IEBST+l4rYGxYYStV2PEmp9cZ+"
TOKEN = "5V7AY+ikHr4DiSfq1W2UBa71G3FLGkpUSKTrOLg81yk="
NONCE = "AQAAAYeBb0XwKDMBW5PfAPM="


def extract_hash(sig: bytes, cert: str) -> str:
    # sig = b64decode(SIG)[2:]
    sig = int.from_bytes(sig)

    # Get the correct hash
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate

    # key, cert = load_keys()
    cert = "-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----"
    cert = load_pem_x509_certificate(cert.encode(), default_backend())
    modulus = cert.public_key().public_numbers().n
    power = cert.public_key().public_numbers().e
    # print(hex(pow(sig, power, modulus)))

    return pow(sig, power, modulus)
    # from cryptography import x509

    # cert = "-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----"
    # cert = x509.load_pem_x509_certificate(cert.encode())
    # pub = cert.public_key()
    # modulus = pub.public_numbers().n
    # # Get the power
    # power = pub.public_numbers().e
    # # Get the hash from the sig
    # sig = b64decode(sig)
    # sig = sig[2:]
    # sig = int.from_bytes(sig)
    # hash = pow(sig, power, modulus)

    # print(hex(hash))

    # return hash


body = plistlib.dumps(plistlib.loads(BODY.encode()))
body = zlib.compress(BODY.encode(), wbits=16 + zlib.MAX_WBITS)

p = ids._create_payload("id-register", "", TOKEN, body, b64decode(NONCE))[0]
s = hashlib.sha1(p).digest()
print(s.hex())
# extract_hash(SIG, CERT)

# Loop through all POSSIBLE ranges
# sig = b64decode(SIG)
# print(sig[:2])
# for i in range(len(sig)):
#     for j in range(i, len(sig)):
#         h = extract_hash(sig[i:j], CERT)
#         t = hex(h)
#         if 'ffffff' in t:
#             print(i, j, t)
# sig = b64decode(SIG)[2:]
# for i in range(len(sig)):
#     h = extract_hash(sig[:i], CERT)
#     t = hex(h)
#     if 'ffff' in t:
#         print(i, t)

# #print(hex(extract_hash(SIG, CERT)))

# CERT2 = "MIICnjCCAgegAwIBAgIKBAr40/DyW42YxjANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEVMBMGA1UECxMMQXBwbGUgaVBob25lMR8wHQYDVQQDExZBcHBsZSBpUGhvbmUgRGV2aWNlIENBMB4XDTIzMDQwNzE0MTUwNVoXDTI0MDQwNzE0MjAwNVowLzEtMCsGA1UEAxYkOUNCOTkzMTYtNkJERi00REYzLUFCRjUtNzcxNDU5MjFFQkY1MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwsLiv8cifPdQZJQZtWvoD0WoTekSGwRj7KhxOi+AC1EUTdByWna8l7DDnixqww01FyA9pCBwottv0Xk9lOsrJrK05RXS+A7IieycejnUMdmRkgS7AsHIXOUSjtlkg2sfz5eYV9cqemTJnhdOvKtbqb9lYVN/8EehXD5JuogN+vwIDAQABo4GVMIGSMB8GA1UdIwQYMBaAFLL+ISNEhpVqedWBJo5zENinTI50MB0GA1UdDgQWBBQCl798/NQ3s5KywbJjoCjfjvWvmDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEAYKKoZIhvdjZAYKBAQCBQAwDQYJKoZIhvcNAQEFBQADgYEAfBwkujrswCn+wtu0eKCa39Cv58YC3AhK24Aj2iwXbddHaj9B9ye6HDy1BHPG21LKNGqm4X/XEtJQ3ZY/hGr4eenmtYjOI4a/oi127mrSt7uZmoib9x5S6w68eCCKkO+DD2JqDbMr2ATUhVNUxMegrzYdju8LofYqXBKzkoZ0/nk="
# SIG2 = "AQGOTyyRBWMxoGWqEUl5bZJXssL6bkK4acxIDOCJTUy0MMavNEwtFThZkqVpQFqjB7eXNBM6PxwPtmwHmf/5IWgIkBUthIwhGJV3pLUkhDHTVX5YjbUSF7Z4y+Y39BQ2hhYjfcz1bw2KH40MByt+bnk28Xv2XaKWYuBinH9PVajp3g=="


SIG3 = "AQEZs/u9Ptb8AmFpCv5XgzUsskvcleZDBxYTe5JOoshFCxpnByTwFA0mxplklHqT2rTEeF+Bu0Bo0vEPlh9KslmIoQLo6ej25bbtFN07dnHNwd84xzQzWBa4VHLQE1gNjSpcorppxpAUon/eFRu5yRxmwQVmqo+XmmxSuFCzxUaAZAPFPDna+8tvRwd0q3kuK9b0w/kuT16X1SL166fFNzmsQGcBqob9C9xX0VlYGqSd4K975gWdYsPo/kiY0ni4Q130oc6oAANr8ATN0bEeAO6/AfVM2aqHJTGlYlekBFWf8Tp8AJLUc4cm676346IEBST+l4rYGxYYStV2PEmp9cZ+"
CERT3 = "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"

print(hex(extract_hash(b64decode(SIG)[2:], CERT)))
