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
from cryptography.hazmat.primitives.serialization import Encoding

# from pypush import apns
from pypush.apns import protocol, transport

from . import _frida


async def forward_packets(
    source: transport.PacketStream,
    dest: transport.PacketStream,
    name: str = "",
):
    try:
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
        logging.info(f"{name} -> EOF")
    except anyio.EndOfStream:
        logging.info(f"{name} -> EOS")
    except anyio.ClosedResourceError:
        logging.info(f"{name} -> Closed")
    except Exception as e:
        logging.error(f"Error forwarding packets: {e}")
    await dest.aclose()  # close the other stream so that the other task exits cleanly


connection_cnt = 0


async def handle(client: TLSStream):
    global connection_cnt
    connection_cnt += 1

    sni = client._ssl_object.server_name  # type: ignore
    logging.debug(f"Got SNI: {sni}")
    sandbox = "sandbox" in sni

    async with client:
        client_pkt = transport.PacketStream(client)
        logging.debug("Client connected")

        forward = (
            "1-courier.push.apple.com"
            if not sandbox
            else "1-courier.sandbox.push.apple.com"
        )
        name = f"prod-{connection_cnt}" if not sandbox else f"sandbox-{connection_cnt}"
        async with await transport.create_courier_connection(sandbox, forward) as conn:
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
            try:
                apsd = _frida.attach_to_apsd()
                _frida.redirect_courier(apsd, "courier.push.apple.com", "localhost")
                _frida.redirect_courier(
                    apsd, "courier.sandbox.push.apple.com", "localhost"
                )
                _frida.trust_all_hosts(apsd)
            except Exception as e:
                logging.error(f"Error attaching to apsd (did you run as root?): {e}")
        logging.info("Press Enter to exit...")
        await ainput()
        tg.cancel_scope.cancel()


def main(attach):
    anyio.run(start, attach)
