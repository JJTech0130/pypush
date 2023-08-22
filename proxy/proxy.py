import os
import sys
import traceback

# setting path so we can import the needed packages
sys.path.append(os.path.join(sys.path[0], "../"))
sys.path.append(os.path.join(sys.path[0], "../../"))

import gzip
import logging
import plistlib
import ssl
from hashlib import sha1

import trio
from rich.logging import RichHandler

import printer
import apns

logging.basicConfig(
    level=logging.NOTSET,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler()],
)

async def main():
    apns.COURIER_HOST = "windows.courier.push.apple.com" # Use windows courier so that /etc/hosts override doesn't affect it

    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.set_alpn_protocols(["apns-security-v3"])
    # Set the certificate and private key
    parent_dir: str = os.path.dirname(os.path.realpath(__file__))
    context.load_cert_chain(os.path.join(parent_dir, "push_certificate_chain.pem"), os.path.join(parent_dir, "push_key.pem"))

    await trio.serve_ssl_over_tcp(handle_proxy, 5223, context)

async def handle_proxy(stream: trio.SocketStream):
    try:
        p = APNSProxy(stream)
        await p.start()
    except Exception:
        logging.error(f"APNSProxy instance encountered exception:")
        traceback.print_exc()

        #raise e

class APNSProxy:
    def __init__(self, client: trio.SocketStream):
        self.client = client

    async def start(self):
        logging.info("Starting proxy...")
        async with trio.open_nursery() as nursery:
            while True:
                try:
                    apns_server = apns.APNSConnection(nursery)
                    await apns_server._connect_socket()
                    self.connection = apns_server

                    nursery.start_soon(self.proxy, True)
                    nursery.start_soon(self.proxy, False)

                    break # Will only happen if there is no exception
                except Exception:
                    logging.error("Unable to start proxy, trying again...")
                    await trio.sleep(1)



    async def proxy(self, to_server: bool):
        if to_server:
            from_stream = self.client
            to_stream = self.connection.sock
        else:
            from_stream = self.connection.sock
            to_stream = self.client

        while True:
            payload = await apns.APNSPayload.read_from_stream(from_stream)
            payload = self.tamper(payload, to_server)
            self.log(payload, to_server)
            await payload.write_to_stream(to_stream)

    def log(self, payload: apns.APNSPayload, to_server: bool):
        printer.print_payload(payload, to_server)
        # if to_server:
        #     logging.info(f"-> {payload}")
        # else:
        #     logging.info(f"<- {payload}")

    def tamper(self, payload: apns.APNSPayload, to_server) -> apns.APNSPayload:
        #if not to_server:
        #    payload = self.tamper_lookup_keys(payload)

        return payload

    def tamper_lookup_keys(self, payload: apns.APNSPayload) -> apns.APNSPayload:
        if payload.id == 0xA: # Notification
            if payload.fields_with_id(2)[0].value == sha1(b"com.apple.madrid").digest(): # Topic
                if (body := payload.fields_with_id(3)[0].value) is not None:
                    body = plistlib.loads(body)
                    if body['c'] == 97: # Lookup response
                        resp = gzip.decompress(body["b"]) # HTTP body
                        resp = plistlib.loads(resp)

                        # Replace public keys
                        for result in resp["results"].values():
                            for identity in result["identities"]:
                                if "client-data" in identity:
                                    identity["client-data"]["public-message-identity-key"] = b"REDACTED"

                        resp = gzip.compress(plistlib.dumps(resp, fmt=plistlib.FMT_BINARY), mtime=0)
                        body["b"] = resp
                    body = plistlib.dumps(body, fmt=plistlib.FMT_BINARY)
                    for field in payload.fields:
                        if field.id == 3:
                            field.value = body
                            break
        return payload

if __name__ == "__main__":
    trio.run(main)
