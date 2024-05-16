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

# from pypush import apns
from pypush.apns.new import transport, protocol

from . import _frida


async def forward_packets(
    source: transport.PacketStream, dest: transport.PacketStream, name: str = ""
):
    async for packet in source:
        try:
            command = protocol.command_from_packet(packet)
            if not isinstance(command, protocol.UnknownCommand):
                logging.info(f"{name} -> {command}")
            else:
                logging.warning(f"{name} -> {command}")
        except Exception as e:
            logging.error(f"Error parsing packet: {e}")
            logging.error(f"{name} => {packet}")
            await dest.send(packet)
            continue
        await dest.send(command.to_packet())


connection_cnt = 0


async def handle(client: TLSStream):
    global connection_cnt
    connection_cnt += 1

    sni = client._ssl_object.server_name  # type: ignore
    logging.debug(f"Got SNI: {sni}")
    sandbox = "sandbox" in sni

    # TODO: Check what SNI the client is connecting to, use that instead of guessing based on local IP
    async with client:
        client_pkt = transport.PacketStream(client)
        logging.debug("Client connected")

        forward = (
            "1-courier.push.apple.com"
            if not sandbox
            else "1-courier.sandbox.push.apple.com"
        )
        name = f"prod-{connection_cnt}" if not sandbox else f"sandbox-{connection_cnt}"

        async with await transport.create_courier_connection(forward) as conn:
            logging.debug("Connected to courier")
            async with anyio.create_task_group() as tg:
                tg.start_soon(forward_packets, client_pkt, conn, f"client-{name}")
                tg.start_soon(forward_packets, conn, client_pkt, f"server-{name}")
                logging.debug("Started forwarding")
        logging.debug("Courier disconnected")


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


def sni_callback(conn, server_name, ssl_context):
    # Set the server name in the conn so we can use it later
    conn.server_name = server_name  # type: ignore


async def courier_proxy(host):
    # Start listening on localhost:COURIER_PORT
    listener = await anyio.create_tcp_listener(
        local_port=transport.COURIER_PORT, local_host=host
    )
    # Create an SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.set_alpn_protocols(["apns-security-v3"])
    context.load_cert_chain(*temp_certs())
    context.set_servername_callback(sni_callback)
    listener = TLSListener(listener, ssl_context=context, standard_compatible=False)
    logging.info(f"Listening on {host}:{transport.COURIER_PORT}")

    await listener.serve(handle)


async def ainput(prompt: str = "") -> str:
    print(prompt, end="")
    return await anyio.to_thread.run_sync(input)


async def start(attach):
    async with anyio.create_task_group() as tg:
        tg.start_soon(courier_proxy, "localhost")
        if attach:
            apsd = _frida.attach_to_apsd()
            _frida.redirect_courier(apsd, "courier.push.apple.com", "localhost")
            _frida.redirect_courier(apsd, "courier.sandbox.push.apple.com", "localhost")
            _frida.trust_all_hosts(apsd)
        logging.info("Press Enter to exit...")
        await ainput()
        tg.cancel_scope.cancel()

    # # Attach to the target app
    # if attach:
    #     apsd = _frida.attach_to_apsd()

    #     async with anyio.create_task_group() as tg:
    #         if double_courier:
    #             logging.info("Double courier mode enabled")
    #             logging.info(
    #                 "Make sure to run `sudo ifconfig lo0 alias 127.0.0.2` and `sudo ifconfig lo0 alias 127.0.0.3` to add the extra IPs"
    #             )
    #             tg.start_soon(courier_proxy, "127.0.0.2", "2-courier.push.apple.com")
    #             tg.start_soon(
    #                 courier_proxy, "127.0.0.3", "7-courier.sandbox.push.apple.com"
    #             )
    #             _frida.redirect_courier(apsd, "courier.push.apple.com", "127.0.0.2")
    #             _frida.redirect_courier(
    #                 apsd, "courier.sandbox.push.apple.com", "127.0.0.3"
    #             )
    #         else:
    #             tg.start_soon(courier_proxy, "localhost", "1-courier.push.apple.com")

    #             _frida.redirect_courier(apsd, "courier.push.apple.com", "localhost")
    #         _frida.trust_all_hosts(apsd)

    #         logging.info("Press Enter to exit...")
    #         await ainput()
    #         tg.cancel_scope.cancel()
    # else:
    #     async with anyio.create_task_group() as tg:
    #         tg.start_soon(courier_proxy, "localhost", "1-courier.push.apple.com")
    #         logging.info("Press Enter to exit...")
    #         await ainput()
    #         tg.cancel_scope.cancel()


def main(attach):
    anyio.run(start, attach)
