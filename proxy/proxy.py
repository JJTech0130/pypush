# TLS server to proxy APNs traffic

import socket
import tlslite
import threading

import sys
 
# setting path
sys.path.append('../')

# APNs server to proxy traffic to
APNS_HOST = "windows.courier.push.apple.com"
APNS_PORT = 5223
#ALPN = b"apns-security-v3"
ALPN = b"apns-security-v2"
#ALPN = b"apns-pack-v1"

global_cnt = 0

# Connect to the APNs server
def connect() -> tlslite.TLSConnection:
    # Connect to the APNs server
    sock = socket.create_connection((APNS_HOST, APNS_PORT))
    # Wrap the socket in TLS
    ssock = tlslite.TLSConnection(sock)
    #print("Handshaking with APNs")
    # Handshake with the server
    if ALPN == b"apns-security-v3":
        ssock.handshakeClientCert(alpn=[ALPN])
    else:
        import albert
        private_key, cert = albert.generate_push_cert()
        cert = tlslite.X509CertChain([tlslite.X509().parse(cert)])
        private_key = tlslite.parsePEMKey(private_key, private=True)
        # Handshake with the server
        ssock.handshakeClientCert(cert, private_key, alpn=[ALPN])
    
    return ssock

cert:str = None
key:str = None


import apns
import printer


def proxy(conn1: tlslite.TLSConnection, conn2: tlslite.TLSConnection, prefix: str = ""):
    try:
        while True:
            # Read data from the first connection
            data = conn1.read()
            # If there is no data, the connection has closed
            if not data:
                break

            override = printer.pretty_print_payload(prefix, apns._deserialize_payload_from_buffer(data))
            if override is not None:
                data = override
                print("OVERRIDE: ", end="")
                printer.pretty_print_payload(prefix, apns._deserialize_payload_from_buffer(data))

            #print(prefix, data)
            # Write the data to the second connection
            conn2.write(data)
    except OSError as e:
        if e.errno == 9:
            pass # Probably a connection closed error
    except tlslite.TLSAbruptCloseError:
        pass
    print("Connection closed")
    # Close the connections
    conn1.close()
    conn2.close()

def handle(conn: socket.socket):
    # Wrap the socket in TLS
    s_conn = tlslite.TLSConnection(conn)
    global cert, key
    chain = tlslite.X509CertChain()
    chain.parsePemList(cert)
    #print(chain)
    #cert = tlslite.X509CertChain([tlslite.X509().parse(cert)])
    key_parsed  = tlslite.parsePEMKey(key, private=True)
    #print(key_parsed)
    s_conn.handshakeServer(certChain=chain, privateKey=key_parsed, reqCert=False, alpn=[ALPN])

    print("Handling connection")
    # Connect to the APNs server
    apns = connect()
    print("Connected to APNs")

    global global_cnt
    global_cnt += 1
    # Proxy data between the connections
    # Create a thread to proxy data from the APNs server to the client
    threading.Thread(target=proxy, args=(s_conn, apns, f"{global_cnt} apsd -> APNs")).start()
    # Just proxy data from the client to the APNs server in this thread
    proxy(apns, s_conn, f"{global_cnt} APNs -> apsd")

def serve():

    # Create a socket to listen for connections
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("localhost", 5223))
    sock.listen()

    print("Listening for connections...")

    # Handshake with the client
    # Read the certificate and private key from the config
    with open("push_certificate_chain.pem", "r") as f:
        global cert
        cert = f.read()
        

    # NEED TO USE OPENSSL, SEE CORETRUST CMD, MIMIC ENTRUST? OR AT LEAST SEE PUSHPROXY FOR EXTRACTION & REPLACEMENT
    with open("push_key.pem", "r") as f:
        global key
        key = f.read()

    # Accept connections
    while True:
        # Accept a connection
        conn, addr = sock.accept()
        # Create a thread to handle the connection
        #handle(conn)
        thread = threading.Thread(target=handle, args=(conn,))
        thread.start()

if __name__ == "__main__":
    serve()
