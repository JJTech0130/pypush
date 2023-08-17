from __future__ import annotations

import random
import socket
import threading
import time
from hashlib import sha1
from base64 import b64encode, b64decode
import logging
logger = logging.getLogger("apns")
import ssl

import trio

import albert
import bags

#COURIER_HOST = "windows.courier.push.apple.com"  # TODO: Get this from config
# Pick a random courier server from 01 to APNSCourierHostcount
COURIER_HOST = f"{random.randint(1, bags.apns_init_bag()['APNSCourierHostcount'])}-{bags.apns_init_bag()['APNSCourierHostname']}"
COURIER_PORT = 5223
ALPN = [b"apns-security-v3"]

async def apns_test():
    async with APNSConnection.start() as connection:
        print(b64encode(connection.credentials.token).decode())
        while True:
            await trio.sleep(1)
            print(".")
            #await connection.set_state(1)


    print("Finished")
def main():
    from rich.logging import RichHandler


    logging.basicConfig(
        level=logging.NOTSET, format="%(message)s", datefmt="[%X]", handlers=[RichHandler()]
    )

    # Set sane log levels
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("py.warnings").setLevel(logging.ERROR) # Ignore warnings from urllib3
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

from contextlib import asynccontextmanager
from dataclasses import dataclass

@dataclass
class PushCredentials:
    private_key: str
    cert: str
    token: bytes

class APNSConnection:
    _incoming_queue: list = [] # We don't need a lock because this is trio and we only have one thread
    _queue_park: trio.Event = trio.Event()

    async def _send(self, id: int, fields: list[tuple[int, bytes]]):
        payload = _serialize_payload(id, fields)
        await self.sock.send_all(payload)
    
    async def _receive(self, id: int):
        # Check if anything currently in the queue matches the id
        for payload in self._incoming_queue:
            if payload[0] == id:
                return payload
        while True:
            await self._queue_park.wait() # Wait for a new payload to be added to the queue
            logger.debug(f"Woken by event, checking for {id}")
            # Check if the new payload matches the id
            if self._incoming_queue[-1][0] == id:
                return self._incoming_queue.pop()
            # Otherwise, wait for another payload to be added to the queue

    async def _queue_filler(self):
        while True:
            payload = await _deserialize_payload(self.sock)

            logger.debug(f"Received payload: {payload}")
            self._incoming_queue.append(payload)
            # Signal to any waiting tasks that we have a new payload
            self._queue_park.set()
            self._queue_park = trio.Event() # Reset the event
            logger.debug(f"Queue length: {len(self._incoming_queue)}")
    
    async def _keep_alive(self):
        while True:
            #await trio.sleep(300)
            await trio.sleep(1)
            logger.debug("Sending keep alive message")
            await self._send(0x0C, [])
            await self._receive(0x0D)
            logger.debug("Got keep alive response")

    @asynccontextmanager
    async def start(credentials: PushCredentials | None = None):
        """Sets up a nursery and connection and yields the connection"""
        async with trio.open_nursery() as nursery:
            connection = APNSConnection(nursery, credentials)
            await connection.connect()
            yield connection
            nursery.cancel_scope.cancel() # Cancel heartbeat and queue filler tasks     
            await connection.sock.aclose() # Close the socket

    def __init__(self, nursery: trio.Nursery, credentials: PushCredentials | None = None):
        self._nursery = nursery
        self.credentials = credentials

    async def connect(self):
        """Connects to the APNs server and starts the keep alive and queue filler tasks"""
        sock = await trio.open_tcp_stream(COURIER_HOST, COURIER_PORT)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.set_alpn_protocols(["apns-security-v3"])

        self.sock = trio.SSLStream(sock, context, server_hostname=COURIER_HOST)

        await self.sock.do_handshake()

        logger.info(f"Connected to APNs ({COURIER_HOST})")

        if self.credentials is None:
            self.credentials = PushCredentials(*albert.generate_push_cert(), None)

        # Start the queue filler and keep alive tasks
        self._nursery.start_soon(self._queue_filler)
        self._nursery.start_soon(self._keep_alive)

        self.credentials.token = await self._connect(self.credentials.token)

    async def _connect(self, token: bytes | None = None, root: bool = False) -> bytes:
        """Sends the APNs connect message"""
        # Parse self.certificate
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(self.credentials.cert.encode())
        # Parse private key
        from cryptography.hazmat.primitives import serialization
        private_key = serialization.load_pem_private_key(self.credentials.private_key.encode(), password=None)

        if token is None:
            logger.debug(f"Sending connect message without token (root={root})")
        else:
            logger.debug(f"Sending connect message with token {b64encode(token).decode()} (root={root})")
        flags = 0b01000001
        if root:
            flags |= 0b0100

        #  1 byte fixed 00, 8 bytes timestamp (milliseconds since Unix epoch), 8 bytes random
        cert = cert.public_bytes(serialization.Encoding.DER)
        nonce = b"\x00" + int(time.time() * 1000).to_bytes(8, "big") + random.randbytes(8)
        #signature = private_key.sign(nonce, signature_algorithm=serialization.NoEncryption())
        # RSASSA-PKCS1-SHA1
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = b"\x01\x01" + private_key.sign(nonce, padding.PKCS1v15(), hashes.SHA1())
        
        payload = [
            (2, b"\x01"),
            (5, flags.to_bytes(4, "big")),
            (0x0c, cert),
            (0x0d, nonce),
            (0x0e, signature),
        ]
        if token is not None:
            payload.insert(0, (1, token))
        
        await self._send(7, payload)
       
        payload = await self._receive(8)

        if _get_field(payload[1], 1) != b"\x00":
            raise Exception("Failed to connect")
        
        new_token = _get_field(payload[1], 3)

        logger.debug(f"Recieved connect response with token {b64encode(new_token).decode()}")

        return new_token

    def filter(self, topics: list[str]):
        logger.debug(f"Sending filter message with topics {topics}")
        fields = [(1, self.token)]

        for topic in topics:
            fields.append((2, sha1(topic.encode()).digest()))

        payload = _serialize_payload(9, fields)

        self.sock.sendall(payload)

    def send_message(self, topic: str, payload: str, id=None):
        logger.debug(f"Sending message to topic {topic} with payload {payload}")
        if id is None:
            id = random.randbytes(4)

        payload = _serialize_payload(
            0x0A,
            [
                (4, id),
                (1, sha1(topic.encode()).digest()),
                (2, self.token),
                (3, payload),
            ],
        )

        self.sock.sendall(payload)

        # Wait for ACK
        payload = self.incoming_queue.wait_pop_find(lambda i: i[0] == 0x0B)

        if payload[1][0][1] != 0x00.to_bytes(1, "big"):
            raise Exception("Failed to send message")

    async def set_state(self, state: int):
        logger.debug(f"Sending state message with state {state}")
        await self._send(0x14, [(1, b"\x01"),  (2, 0x7FFFFFFF.to_bytes(4, "big"))])
        

    def _send_ack(self, id: bytes):
        logger.debug(f"Sending ACK for message {id}")
        payload = _serialize_payload(0x0B, [(1, self.token), (4, id), (8, b"\x00")])
        self.sock.sendall(payload)
    #     #self.sock.write(_serialize_payload(0x0B, [(4, id)])
    #     #pass

    # def recieve_message(self):
    #     payload = self.incoming_queue.wait_pop_find(lambda i: i[0] == 0x0A)
    #     # Send ACK
    #     self._send_ack(_get_field(payload[1], 4))
    #     return _get_field(payload[1], 3)

    # TODO: Find a way to make this non-blocking
    # def expect_message(self) -> tuple[int, list[tuple[int, bytes]]] | None:
    #   return _deserialize_payload(self.sock)


def _serialize_field(id: int, value: bytes) -> bytes:
    return id.to_bytes(1, "big") + len(value).to_bytes(2, "big") + value


def _serialize_payload(id: int, fields: list[(int, bytes)]) -> bytes:
    payload = b""

    for fid, value in fields:
        if fid is not None:
            payload += _serialize_field(fid, value)

    return id.to_bytes(1, "big") + len(payload).to_bytes(4, "big") + payload


def _deserialize_field(stream: bytes) -> tuple[int, bytes]:
    id = int.from_bytes(stream[:1], "big")
    length = int.from_bytes(stream[1:3], "big")
    value = stream[3 : 3 + length]
    return id, value


# Note: Takes a stream, not a buffer, as we do not know the length of the payload
# WILL BLOCK IF THE STREAM IS EMPTY
async def _deserialize_payload(stream: trio.SSLStream) -> tuple[int, list[tuple[int, bytes]]] | None:
    id = int.from_bytes(await stream.receive_some(1), "big")

    if id == 0x0:
        return None

    length = int.from_bytes(await stream.receive_some(4), "big")

    if length == 0:
        return id, []

    buffer = await stream.receive_some(length)

    fields = []

    while len(buffer) > 0:
        fid, value = _deserialize_field(buffer)
        fields.append((fid, value))
        buffer = buffer[3 + len(value) :]

    return id, fields


def _deserialize_payload_from_buffer(
    buffer: bytes,
) -> tuple[int, list[tuple[int, bytes]]] | None:
    id = int.from_bytes(buffer[:1], "big")

    if id == 0x0:
        return None

    length = int.from_bytes(buffer[1:5], "big")

    buffer = buffer[5:]

    if len(buffer) < length:
        raise Exception("Buffer is too short")

    fields = []

    while len(buffer) > 0:
        fid, value = _deserialize_field(buffer)
        fields.append((fid, value))
        buffer = buffer[3 + len(value) :]

    return id, fields


# Returns the value of the first field with the given id
def _get_field(fields: list[tuple[int, bytes]], id: int) -> bytes:
    for field_id, value in fields:
        if field_id == id:
            return value
    return None

if __name__ == "__main__":
    main()