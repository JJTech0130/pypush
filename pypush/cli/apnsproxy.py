import datetime
import logging
import ssl
import tempfile

import anyio
import anyio.abc
import anyio.to_thread
from anyio.streams.tls import TLSListener, TLSStream
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from rich.logging import RichHandler

from pypush import apns
from pypush.apns.new import transport, protocol

from . import _frida

logging.basicConfig(level=logging.DEBUG, handlers=[RichHandler()], format="%(message)s")


async def forward_packets(
    source: transport.PacketStream, dest: transport.PacketStream, name: str = ""
):
    while True:
        packet = await source.receive()
        command = protocol.command_from_packet(packet)
        logging.info(f"{name} -> {command}")
        await dest.send(packet)


async def handle(client: TLSStream):
    async with client:
        client_pkt = transport.PacketStream(client)
        print("Connected")
        async with await transport.create_courier_connection() as conn:
            print("Connected to courier")
            async with anyio.create_task_group() as tg:
                tg.start_soon(forward_packets, client_pkt, conn, "client")
                tg.start_soon(forward_packets, conn, client_pkt, "server")
                print("Started forwarding")

        print("Disconnecting")


def temp_certs():
    # Create a self-signed certificate for the server and write it to temporary files
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")])
    )
    builder = builder.issuer_name(
        x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "localhost")])
    )
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    )
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(key.public_key())
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
    )
    certificate = builder.sign(key, SHA256())

    cert_path, key_path = tempfile.mktemp(), tempfile.mktemp()

    with open(cert_path, "wb") as f:
        f.write(certificate.public_bytes(Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

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
    apsd = _frida.attach_to_apsd()

    async with anyio.create_task_group() as tg:
        tg.start_soon(courier_proxy)
        _frida.redirect_courier(apsd)
        _frida.trust_all_hosts(apsd)

        await ainput("Press Enter to exit...\n")
        tg.cancel_scope.cancel()


def main():
    anyio.run(start)


if __name__ == "__main__":
    main()
