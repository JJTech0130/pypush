import sys
sys.path.append("../")
sys.path.append("../../")

import apns
import trio
import ssl

import logging
from rich.logging import RichHandler

logging.basicConfig(
    level=logging.NOTSET,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler()],
)

async def main():
    apns.COURIER_HOST = "windows.courier.push.apple.com"

    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.set_alpn_protocols(["apns-security-v3"])
    # Set the certificate and private key
    context.load_cert_chain("push_certificate_chain.pem", "push_key.pem")
    
    await trio.serve_ssl_over_tcp(handle_proxy, 5223, context)

async def handle_proxy(stream: trio.SocketStream):
    # Create an APNS connection
    # Create 2 tasks, one to read from the client and write to the server, and one to read from the server and write to the client
    try:
        async with trio.open_nursery() as nursery:
            apns_server = apns.APNSConnection(nursery)
            await apns_server._connect_socket()
            server = apns_server.sock

            nursery.start_soon(read_from_client, stream, server)
            nursery.start_soon(read_from_server, stream, server)
    except Exception as e:
        logging.error(e)

async def read_from_client(client: trio.SocketStream, server: trio.SocketStream):
    while True:
        payload = await apns.APNSPayload.read_from_stream(client)
        logging.debug(payload)
        await payload.write_to_stream(server)


async def read_from_server(client: trio.SocketStream, server: trio.SocketStream):
    while True:
        payload = await apns.APNSPayload.read_from_stream(server)
        logging.debug(payload)
        await payload.write_to_stream(client)

if __name__ == "__main__":
    trio.run(main)