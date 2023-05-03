# TLS server to proxy APNs traffic

import socket
import sys
import threading

import tlslite

# setting path
sys.path.append("../")
sys.path.append("../../")

# APNs server to proxy traffic to
APNS_HOST = "windows.courier.push.apple.com"
APNS_PORT = 5223
ALPN = b"apns-security-v3"
# ALPN = b"apns-security-v2"
# ALPN = b"apns-pack-v1"

global_cnt = 0


# Connect to the APNs server
def connect() -> tlslite.TLSConnection:
    # Connect to the APNs server
    sock = socket.create_connection((APNS_HOST, APNS_PORT))
    # Wrap the socket in TLS
    ssock = tlslite.TLSConnection(sock)
    # print("Handshaking with APNs")
    # Handshake with the server
    if ALPN == b"apns-security-v3":
        print("Using v3")
        ssock.handshakeClientCert(alpn=[ALPN])
    else:
        import albert

        private_key, cert = albert.generate_push_cert()
        cert = tlslite.X509CertChain([tlslite.X509().parse(cert)])
        private_key = tlslite.parsePEMKey(private_key, private=True)
        # Handshake with the server
        ssock.handshakeClientCert(cert, private_key, alpn=[ALPN])

    return ssock


cert: str = None
key: str = None


import printer

import apns

outgoing_list = []
incoming_list = []
# last_outgoing = b""


def proxy(conn1: tlslite.TLSConnection, conn2: tlslite.TLSConnection, prefix: str = ""):
    try:
        while True:
            # Read data from the first connection
            data = conn1.read()
            # print(prefix, "data: ", data)
            # If there is no data, the connection has closed
            if not data:
                print(prefix, "Connection closed due to no data")
                break

            try:
                override = printer.pretty_print_payload(
                    prefix, apns._deserialize_payload_from_buffer(data)
                )
            except Exception as e:
                print(e)  # Can't crash the proxy over parsing errors
            if override is not None:
                data = override
                print("OVERRIDE: ", end="")
                printer.pretty_print_payload(
                    prefix, apns._deserialize_payload_from_buffer(data)
                )

            if "apsd -> APNs" in prefix:
                global outgoing_list
                outgoing_list.insert(0, data)
                if len(outgoing_list) > 100:
                    outgoing_list.pop()
            elif "APNs -> apsd" in prefix:
                global incoming_list
                incoming_list.insert(0, data)
                if len(incoming_list) > 100:
                    incoming_list.pop()

            # print(prefix, data)
            # Write the data to the second connection
            conn2.write(data)
    except OSError as e:
        if e.errno == 9:
            print(prefix, "Connection closed due to OSError 9")
            pass  # Probably a connection closed error
        else:
            raise e
    except tlslite.TLSAbruptCloseError as e:
        print(prefix, "Connection closed abruptly: ", e)
    print("Connection closed")
    # Close the connections
    conn1.close()
    conn2.close()


repl_lock = False


def repl(conn1: tlslite.TLSConnection, conn2: tlslite.TLSConnection):
    global repl_lock
    if repl_lock:
        print("REPL already running")
        return
    repl_lock = True
    import IPython

    IPython.embed()


def handle(conn: socket.socket):
    # Wrap the socket in TLS
    s_conn = tlslite.TLSConnection(conn)
    global cert, key
    chain = tlslite.X509CertChain()
    chain.parsePemList(cert)
    # print(chain)
    # cert = tlslite.X509CertChain([tlslite.X509().parse(cert)])
    key_parsed = tlslite.parsePEMKey(key, private=True)
    # print(key_parsed)
    s_conn.handshakeServer(
        certChain=chain, privateKey=key_parsed, reqCert=False, alpn=[ALPN]
    )

    print("Handling connection")
    # Connect to the APNs server
    apns = connect()
    print("Connected to APNs")

    threading.Thread(target=repl, args=(s_conn, apns)).start()

    global global_cnt
    global_cnt += 1
    # Proxy data between the connections
    # Create a thread to proxy data from the APNs server to the client
    threading.Thread(
        target=proxy, args=(s_conn, apns, f"{global_cnt} apsd -> APNs")
    ).start()
    # Just proxy data from the client to the APNs server in this thread
    proxy(apns, s_conn, f"{global_cnt} APNs -> apsd")


def serve():
    # Create a socket to listen for connections
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow the socket to be reused
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

    conns = []
    # Accept connections
    try:
        while True:
            # Accept a connection
            conn, addr = sock.accept()
            conns.append(conn)
            # Create a thread to handle the connection
            # handle(conn)
            thread = threading.Thread(target=handle, args=(conn,))
            thread.start()
    except KeyboardInterrupt:
        print("Keyboard interrupt, closing sockets")
        for conn in conns:
            conn.close()
        sock.close()


if __name__ == "__main__":
    serve()
