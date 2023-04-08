import tlslite
import socket

COURIER_HOST = "windows.courier.push.apple.com" # TODO: Get this from config
COURIER_PORT = 5223
ALPN = [b"apns-security-v2"]

# Connect to the courier server
def connect(private_key: str, cert: str) -> tlslite.TLSConnection:
    # Connect to the courier server
    sock = socket.create_connection((COURIER_HOST, COURIER_PORT))
    # Wrap the socket in TLS
    sock = tlslite.TLSConnection(sock)
    # Parse the certificate and private key
    cert = tlslite.X509CertChain([tlslite.X509().parse(cert)])
    private_key = tlslite.parsePEMKey(private_key, private=True)
    # Handshake with the server
    sock.handshakeClientCert(cert, private_key, alpn=ALPN)

    return sock

if __name__ == "__main__":
    sock = connect()
    sock.write(b"Hello World!")
    print(sock.read())
    sock.close()

