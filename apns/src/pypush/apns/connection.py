import asyncio
import typing
import random
import plistlib
import httpx
import ssl
import time
import logging
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from . import payload

log = logging.getLogger(__name__)

APNS_CONFIG = plistlib.loads(
    plistlib.loads(httpx.get("http://init-p01st.push.apple.com/bag").content)["bag"]
)

# Pick a random courier server from 01 to APNSCourierHostcount
COURIER_HOST = f"{random.randint(1, APNS_CONFIG['APNSCourierHostcount'])}-{APNS_CONFIG['APNSCourierHostname']}"
COURIER_PORT = 5223
ALPN = ["apns-security-v3"]


class Connection:
    def __init__(
        self,
        certificate: x509.Certificate,
        private_key: rsa.RSAPrivateKey,
        token: typing.Union[bytes, None] = None,
    ):
        self._incoming_queue: typing.List[payload.Payload] = []
        self._queue_event = asyncio.Event()

        self._tasks: typing.List[asyncio.Task] = []

        self.connected = False
        self.certificate = certificate
        self.private_key = private_key
        self.token = token

    async def _send(self, payload: payload.Payload):
        await payload.write_to_stream(self._writer)

    async def _receive(
        self, id: int, filter: typing.Callable[[payload.Payload], bool] = lambda x: True
    ):
        while True:
            # TODO: Come up with a more efficient way to search for messages
            for message in self._incoming_queue:
                if message.id == id and filter(message):
                    # remove the message from the queue and return it
                    self._incoming_queue.remove(message)
                    return message

            # If no messages were found, wait for the queue to be updated
            await self._queue_event.wait()

    async def _queue_messages(self):
        while True:
            self._incoming_queue.append(
                await payload.Payload.read_from_stream(self._reader)
            )
            self._queue_event.set()
            self._queue_event.clear()

    async def connect(self, reconnect: bool = True):
        # TODO: Implement auto reconnection
        self._event_loop = asyncio.get_event_loop()

        context = ssl.create_default_context()
        context.set_alpn_protocols(ALPN)

        # TODO: Verify courier certificate
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self._reader, self._writer = await asyncio.open_connection(
            COURIER_HOST, COURIER_PORT, ssl=context
        )
        self.connected = True

        self._tasks.append(self._event_loop.create_task(self._queue_messages()))

        await self._connect_pkt(self.certificate, self.private_key, self.token)
        await self._state_pkt(0x01)

    async def aclose(self):
        self.connected = False
        for task in self._tasks:
            task.cancel()
        self._writer.close()
        await self._writer.wait_closed()

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()

    async def _state_pkt(self, state: int):
        log.debug(f"Sending state message with state {state}")
        await self._send(
            payload.Payload(
                0x14,
                [
                    payload.Field(1, state.to_bytes(1, "big")),
                    payload.Field(2, 0x7FFFFFFF.to_bytes(4, "big")),
                ],
            )
        )

    async def _connect_pkt(
        self,
        certificate: x509.Certificate,
        private_key: rsa.RSAPrivateKey,
        token: typing.Union[bytes, None],
    ):
        flags = 0b01000001  # TODO: Root/sub-connection flags

        cert = certificate.public_bytes(serialization.Encoding.DER)
        nonce = (
            b"\x00" + int(time.time() * 1000).to_bytes(8, "big") + random.randbytes(8)
        )
        signature = b"\x01\x01" + private_key.sign(
            nonce, padding.PKCS1v15(), hashes.SHA1()
        )

        p = payload.Payload(
            7,
            [
                payload.Field(0x2, b"\x01"),
                payload.Field(0x5, flags.to_bytes(4, "big")),
                payload.Field(0xC, cert),
                payload.Field(0xD, nonce),
                payload.Field(0xE, signature),
                # TODO: Metrics/optional device info fields
            ],
        )

        if token:
            p.fields.insert(0, payload.Field(0x1, token))

        await self._send(p)

        resp = await self._receive(8)

        if resp.fields_with_id(1)[0].value != b"\x00":
            raise Exception("Failed to connect")

        if len(resp.fields_with_id(3)) > 0:
            new_token = resp.fields_with_id(3)[0].value
        else:
            if token is None:
                raise Exception("No token received")
            new_token = token

        log.debug(
            f"Received connect response with token {base64.b64encode(new_token).decode()}"
        )

        return new_token


# TODO: Implement sub-connections
