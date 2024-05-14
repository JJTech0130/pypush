import anyio
import anyio.to_thread
from anyio.streams.tls import TLSListener, TLSStream
import anyio.abc
import ssl
# Check if we can import Frida
try:
    import frida
except ImportError:
    print("Please install the 'proxy' extra to use this feature.")
    exit(1)

from pypush import apns

async def forward_packets(source: anyio.abc.ByteStream, dest: anyio.abc.ByteStream):
    while True:
        print("waiting for packet")
        packet = await apns.protocol.Packet.from_stream(source)
        print("forwarding")
        await dest.send(packet.to_bytes())

async def handle(client: TLSStream):
    async with client:
        print("Connected")
        # Make a new APNs connection to forward to
        async with apns.connection.Connection(None, None) as conn:
            async with anyio.create_task_group() as tg:
                #tg.start_soon()
                assert conn._socket
                #print(await client.receive(1))
                tg.start_soon(forward_packets, client, conn._socket)
                tg.start_soon(forward_packets, conn._socket, client)
                print("Started forwarding")
        print("Disconnecting")

def redirect_courier(session: frida.core.Session):
    session.create_script(
        """
        var getaddrinfo_handle = Module.findExportByName(null, 'getaddrinfo');
        if (getaddrinfo_handle) {
            Interceptor.attach(getaddrinfo_handle, {
                onEnter: function(args) {
                    var node = Memory.readUtf8String(args[0]);
                    var service = Memory.readUtf8String(args[1]);
                    //this.res_ptr = args[3]
                    //console.log('[*] getaddrinfo("' + node + '", "' + service + '", ...)');
                    // Check for "courier.push.apple.com" in name
                    if (node.indexOf("courier.push.apple.com") !== -1) {
                        // Write "localhost" to the first argument
                        Memory.writeUtf8String(args[0], "localhost");
                        console.log('[*] getaddrinfo("' + node + '", ...) => getaddrinfo("localhost", ...)');
                    } else {
                        //console.log('[*] getaddrinfo("' + node + '", ...)');
                    }
                }
            });
            console.log('[+] getaddrinfo() hook installed.');
        }
        """
    ).load()

def trust_all_hosts(session: frida.core.Session):
    session.create_script(
        """
        // Hook -[APSTCPStream isTrust:validWithPolicy:forPeer:] to always return true
        var isTrust_handle = ObjC.classes.APSTCPStream['- isTrust:validWithPolicy:forPeer:'];
        if (isTrust_handle) {
            Interceptor.attach(isTrust_handle.implementation, {
                onEnter: function(args) {
                    console.log('[*] -[APSTCPStream isTrust:validWithPolicy:forPeer:]');
                    console.log('    - isTrust: ' + args[2]);
                    console.log('    - validWithPolicy: ' + args[3]);
                    console.log('    - forPeer: ' + args[4]);
                    //args[2] = true;
                    console.log('    => isTrust: ' + args[2]);
                },
                onLeave: function(retval) {
                    console.log('    <= ' + retval);
                    retval.replace(1);
                }
            });
            console.log('[+] -[APSTCPStream isTrust:validWithPolicy:forPeer:] hook installed.');
        }
        """
    ).load()


def temp_certs():
    # Create a self-signed certificate for the server and write it to temporary files
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.primitives.serialization import PublicFormat
    import datetime
    import tempfile

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"localhost")]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"localhost")]))
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
    certificate = builder.sign(key, SHA256())

    cert_path, key_path = tempfile.mktemp(), tempfile.mktemp()

    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    return cert_path, key_path

async def courier_proxy():
    # Start listening on localhost:COURIER_PORT
    listener = await anyio.create_tcp_listener(local_port=apns.connection.COURIER_PORT)
    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.set_alpn_protocols(["apns-security-v3"])
    context.load_cert_chain(*temp_certs())
    listener = TLSListener(listener, ssl_context=context)
    print("Listening on port", apns.connection.COURIER_PORT)
    await listener.serve(handle)

async def ainput(prompt: str = "") -> str:
    print(prompt, end="")
    return await anyio.to_thread.run_sync(input)
async def start():
    # Attach to the target app
    print("Killing apsd")
    frida.kill("apsd")
    print("Waiting for apsd to start...")
    while True:
        try:
            session = frida.attach("apsd")
            break
        except frida.ProcessNotFoundError:
            pass
    print(session)

    async with anyio.create_task_group() as tg:
        tg.start_soon(courier_proxy)
        trust_all_hosts(session)
        redirect_courier(session)
        await ainput("Press Enter to exit...\n")
        tg.cancel_scope.cancel()
    

def main():
    anyio.run(start)
