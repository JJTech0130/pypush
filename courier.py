import albert
import tlslite
import socket

COURIER_HOST = "10-courier.push.apple.com"
COURIER_PORT = 5223
#ALPN = [b"apns-security-v2"]
ALPN = None

# Check if we have already generated a push certificate
# If not, generate one
def _setup_push_cert():
    try:
        with open("push.key", "r") as f:
            private_key = f.read()
        with open("push.crt", "r") as f:
            cert = f.read()
    except FileNotFoundError:
        private_key, cert = albert.generate_push_cert()
        with open("push.key", "w") as f:
            f.write(private_key)
        with open("push.crt", "w") as f:
            f.write(cert)
    
    return private_key, cert

def connect():
    private_key, cert = _setup_push_cert()

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

