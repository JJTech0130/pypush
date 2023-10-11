from __future__ import annotations

import logging
import random
import ssl
import time
from base64 import b64encode
from contextlib import asynccontextmanager
from dataclasses import dataclass
from hashlib import sha1
from typing import Callable

import trio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import albert
import bags

logger = logging.getLogger("apns")

# Pick a random courier server from 01 to APNSCourierHostcount
try:
    COURIER_HOST = f"{random.randint(1, bags.apns_init_bag()['APNSCourierHostcount'])}-{bags.apns_init_bag()['APNSCourierHostname']}"
except:
    COURIER_HOST = "01-courier.push.apple.com"
COURIER_PORT = 5223
ALPN = [b"apns-security-v3"]


async def apns_test():
    async with APNSConnection.start() as connection:
        print(b64encode(connection.credentials.token).decode())
        while True:
            await trio.sleep(1)
            print(".")
            # await connection.set_state(1)

    print("Finished")


def main():
    from rich.logging import RichHandler

    logging.basicConfig(
        level=logging.NOTSET,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler()],
    )

    # Set sane log levels
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("py.warnings").setLevel(
        logging.ERROR
    )  # Ignore warnings from urllib3
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("jelly").setLevel(logging.INFO)
    logging.getLogger("nac").setLevel(logging.INFO)
    logging.getLogger("apns").setLevel(logging.DEBUG)
    logging.getLogger("albert").setLevel(logging.INFO)
    logging.getLogger("ids").setLevel(logging.DEBUG)
    logging.getLogger("bags").setLevel(logging.INFO)
    logging.getLogger("imessage").setLevel(logging.DEBUG)

    logging.captureWarnings(True)

    print("APNs Test:")

    trio.run(apns_test)


@dataclass
class PushCredentials:
    private_key: str = ""
    cert: str = ""
    token: bytes = b""


class APNSConnection:
    """A connection to the APNs server"""

    _incoming_queue: list[APNSPayload] = []
    """A queue of payloads that have been received from the APNs server"""
    _queue_park: trio.Event = trio.Event()
    """An event that is set when a new payload is added to the queue"""

    async def _send(self, payload: APNSPayload):
        """Sends a payload to the APNs server"""
        while True:
            try:
                await payload.write_to_stream(self.sock)
                return
            except trio.BusyResourceError:
                print("Can't send payload, stream is busy; trying again in 0.2")
                await trio.sleep(0.2)
                continue
            except Exception as e:
                print(f"Can't send payload: {e}")
                return

    async def _receive(self, id: int, filter: Callable[[APNSPayload], bool] | None = None):
        """
        Waits for a payload with the given id to be added to the queue, then returns it.
        If filter is not None, it will be called with the payload as an argument, and if it returns False,
        the payload will be ignored and another will be waited for.

        NOTE: It is not defined what happens if receive is called twice with the same id and filter,
        as the first payload will be removed from the queue, so the second call might never return
        """

        # Check if anything currently in the queue matches the id
        for payload in self._incoming_queue:
            if payload.id == id:
                if filter is not None:
                    if filter(payload):
                        return self._incoming_queue.pop()
                else:
                    return self._incoming_queue.pop()
        while True:
            await self._queue_park.wait()  # Wait for a new payload to be added to the queue
            logger.debug(f"Woken by event, checking for {id}")
            # Check if the new payload matches the id
            if len(self._incoming_queue) == 0:
                continue # all payloads have been removed by someone else
            if self._incoming_queue[-1].id != id:
                continue
            if filter is not None:
                if not filter(self._incoming_queue[-1]):
                    continue
            return self._incoming_queue.pop()
            # Otherwise, wait for another payload to be added to the queue

    async def _queue_filler(self):
        """Fills the queue with payloads from the APNs socket"""
        while True:
            payload = await APNSPayload.read_from_stream(self.sock)

            logger.debug(f"Received payload: {payload}")

            self._incoming_queue.append(payload)

            # TODO: Hack: Send an ACK if this is a notification
            # We do this because as of now pypush does not handle all incoming notifications
            # and if you do not ACK a notification, APNs will keep resending it and eventually kill the connection
            if payload.id == 0xA:
                await self._send_ack(payload.fields_with_id(4)[0].value)

            # Signal to any waiting tasks that we have a new payload
            self._queue_park.set()
            self._queue_park = trio.Event()  # Reset the event

            logger.debug(f"Queue length: {len(self._incoming_queue)}")

    async def _keep_alive(self):
        """Sends keep alive messages to the APNs server every 5 minutes"""
        while True:
            await trio.sleep(300)
            logger.debug("Sending keep alive message")
            await self._send(APNSPayload(0x0C, []))
            await self._receive(0x0D)
            logger.debug("Got keep alive response")

    @asynccontextmanager
    @staticmethod
    async def start(credentials: PushCredentials = PushCredentials()):
        """Sets up a nursery and connection and yields the connection"""
        async with trio.open_nursery() as nursery:
            connection = APNSConnection(nursery, credentials)
            await connection.connect()
            yield connection
            nursery.cancel_scope.cancel()  # Cancel heartbeat and queue filler tasks
            await connection.sock.aclose()  # Close the socket

    def __init__(
        self, nursery: trio.Nursery, credentials: PushCredentials = PushCredentials()
    ):
        """Creates a raw APNSConnection. Make sure to call aclose() on the socket and cancel the nursery when you're done with it"""
        self._nursery = nursery
        self.credentials = credentials

    async def _connect_socket(self):
        sock = await trio.open_tcp_stream(COURIER_HOST, COURIER_PORT)

        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.set_alpn_protocols(["apns-security-v3"])

        # Turn off certificate verification, for the proxy
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self.sock = trio.SSLStream(sock, context, server_hostname=COURIER_HOST)

        await self.sock.do_handshake()

    async def connect(self):
        """Connects to the APNs server and starts the keep alive and queue filler tasks"""
        await self._connect_socket()

        logger.info(f"Connected to APNs ({COURIER_HOST})")

        if self.credentials.cert == "" or self.credentials.private_key == "":
            (
                self.credentials.private_key,
                self.credentials.cert,
            ) = albert.generate_push_cert()

        # Start the queue filler and keep alive tasks
        self._nursery.start_soon(self._queue_filler)
        self._nursery.start_soon(self._keep_alive)

        self.credentials.token = await self._connect(self.credentials.token)

    async def _connect(self, token: bytes | None = None, root: bool = False) -> bytes:
        """Sends the APNs connect message"""

        cert = x509.load_pem_x509_certificate(self.credentials.cert.encode())
        private_key = serialization.load_pem_private_key(
            self.credentials.private_key.encode(), password=None
        )

        if token is None:
            logger.debug(f"Sending connect message without token (root={root})")
        else:
            logger.debug(
                f"Sending connect message with token {b64encode(token).decode()} (root={root})"
            )
        flags = 0b01000001
        if root:
            flags |= 0b0100

        cert = cert.public_bytes(serialization.Encoding.DER)
        nonce = (
            b"\x00" + int(time.time() * 1000).to_bytes(8, "big") + random.randbytes(8)
        )
        signature = b"\x01\x01" + private_key.sign(nonce, padding.PKCS1v15(), hashes.SHA1())  # type: ignore

        payload = APNSPayload(
            7,
            [
                APNSField(0x2, b"\x01"),
                APNSField(0x5, flags.to_bytes(4, "big")),
                APNSField(0xC, cert),
                APNSField(0xD, nonce),
                APNSField(0xE, signature),
            ],
        )

        if token:
            payload.fields.insert(0, APNSField(0x1, token))

        await self._send(payload)

        payload = await self._receive(8)

        if payload.fields_with_id(1)[0].value != b"\x00":
            raise Exception("Failed to connect")

        if len(payload.fields_with_id(3)) > 0:
            new_token = payload.fields_with_id(3)[0].value
        else:
            if token is None:
                raise Exception("No token received")
            new_token = token

        logger.debug(
            f"Received connect response with token {b64encode(new_token).decode()}"
        )

        return new_token

    old_topics = []
    async def filter(self, topics: list[str]):
        """Sends the APNs filter message"""
        if topics == self.old_topics:
            return
        topics = list(set(topics + self.old_topics))
        self.old_topics = topics
        logger.debug(f"Sending filter message with topics {topics}")

        payload = APNSPayload(9, [APNSField(1, self.credentials.token)])

        for topic in topics:
            payload.fields.append(APNSField(2, sha1(topic.encode()).digest()))

        await payload.write_to_stream(self.sock)

    async def send_notification(self, topic: str, payload: bytes, id=None):
        """Sends a notification to the APNs server"""
        logger.debug(f"Sending notification to topic {topic}")
        if id is None:
            id = random.randbytes(4)

        p = APNSPayload(
            0xA,
            [
                APNSField(4, id),
                APNSField(1, sha1(topic.encode()).digest()),
                APNSField(2, self.credentials.token),
                APNSField(3, payload),
            ],
        )

        await self._send(p)

        # Wait for ACK
        r = await self._receive(0xB)

        # TODO: Check ACK code

    async def expect_notification(self, topics: str | list[str], filter: Callable | None = None):
        """Waits for a notification to be received, and acks it"""

        if isinstance(topics, list):
            topic_hashes = [sha1(topic.encode()).digest() for topic in topics]
        else:
            topic_hashes = [sha1(topics.encode()).digest()]

        def f(payload: APNSPayload):
            if payload.fields_with_id(2)[0].value not in topic_hashes:
                return False
            if filter is not None:
                return filter(payload)
            return True

        r = await self._receive(0xA, f)
        # await self._send_ack(r.fields_with_id(4)[0].value)
        return r

    async def set_state(self, state: int):
        """Sends the APNs state message"""
        logger.debug(f"Sending state message with state {state}")
        await self._send(
            APNSPayload(
                0x14,
                [
                    APNSField(1, state.to_bytes(1, "big")),
                    APNSField(2, 0x7FFFFFFF.to_bytes(4, "big")),
                ],
            )
        )

    async def _send_ack(self, id: bytes):
        """Sends an ACK for a notification with the given id"""
        logger.debug(f"Sending ACK for message {id}")
        payload = APNSPayload(
            0xB,
            [
                APNSField(1, self.credentials.token),
                APNSField(4, id),
                APNSField(8, b"\x00"),
            ],
        )
        await self._send(payload)


@dataclass
class APNSField:
    """A field in an APNS payload"""

    id: int
    value: bytes

    @staticmethod
    def from_buffer(stream: bytes) -> APNSField:
        id = int.from_bytes(stream[:1], "big")
        length = int.from_bytes(stream[1:3], "big")
        value = stream[3 : 3 + length]
        return APNSField(id, value)

    def to_buffer(self) -> bytes:
        return (
            self.id.to_bytes(1, "big") + len(self.value).to_bytes(2, "big") + self.value
        )


async def receive_exact(stream: trio.abc.Stream, amount: int):
        """Reads exactly the given amount of bytes from the given stream"""
        buffer = b""
        while len(buffer) < amount:
            # Check for EOF
            if (b := await stream.receive_some(1)) == b"":
                return None # None is how EOF's were represented in the old code, so we'll keep it that way
            buffer += b
        return buffer

@dataclass
class APNSPayload:
    """An APNS payload"""

    id: int
    fields: list[APNSField]

    @staticmethod
    async def read_from_stream(stream: trio.abc.Stream) -> APNSPayload:
        """Reads a payload from the given stream"""
        if not (id_bytes := await receive_exact(stream, 1)):
            raise Exception("Unable to read payload id from stream")
        id: int = int.from_bytes(id_bytes, "big")

        if (length := await receive_exact(stream, 4)) is None:
            raise Exception("Unable to read payload length from stream")
        length = int.from_bytes(length, "big")

        if length == 0:
            return APNSPayload(id, [])

        buffer = await receive_exact(stream, length)
        if buffer is None:
            raise Exception("Unable to read payload from stream")
        fields = []

        while len(buffer) > 0:
            field = APNSField.from_buffer(buffer)
            fields.append(field)
            buffer = buffer[3 + len(field.value) :]

        return APNSPayload(id, fields)

    async def write_to_stream(self, stream: trio.abc.Stream):
        """Writes the payload to the given stream"""
        payload = b""

        for field in self.fields:
            payload += field.to_buffer()

        buffer = self.id.to_bytes(1, "big") + len(payload).to_bytes(4, "big") + payload

        await stream.send_all(buffer)

    def fields_with_id(self, id: int):
        """Returns all fields with the given id"""
        return [field for field in self.fields if field.id == id]


if __name__ == "__main__":
    main()
