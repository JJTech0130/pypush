import albert
import tlslite
import socket

COURIER_HOST = "10-courier.push.apple.com"
COURIER_PORT = 5223
ALPN = [b"apns-security-v2"]
#ALPN = None

def connect(private_key=None, cert=None):
    # If we don't have a private key or certificate, generate one
    if private_key is None or cert is None:
        private_key, cert = albert.generate_push_cert()

    # Connect to the courier server
    sock = socket.create_connection((COURIER_HOST, COURIER_PORT))
    # Wrap the socket in TLS
    sock = tlslite.TLSConnection(sock)
    # Parse the certificate and private key
    cert_parsed = tlslite.X509CertChain([tlslite.X509().parse(cert)])
    private_key_parsed = tlslite.parsePEMKey(private_key, private=True)
    # Handshake with the server
    sock.handshakeClientCert(cert_parsed, private_key_parsed, alpn=ALPN)

    return sock, private_key, cert

if __name__ == "__main__":
    sock = connect()
    sock.write(b"Hello World!")
    print(sock.read())
    sock.close()

