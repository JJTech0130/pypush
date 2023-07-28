from __future__ import annotations

import random
import socket
import threading
import time
from hashlib import sha1
from base64 import b64encode, b64decode
import logging
logger = logging.getLogger("apns")

import tlslite
if tlslite.__version__ != "0.8.0-alpha43":
    logger.warning("tlslite-ng is not the correct version!")
    logger.warning("Please install tlslite-ng==0.8.0a43 or you will experience issues!")

import albert
import bags

#COURIER_HOST = "windows.courier.push.apple.com"  # TODO: Get this from config
# Pick a random courier server from 01 to APNSCourierHostcount
COURIER_HOST = f"{random.randint(1, bags.apns_init_bag()['APNSCourierHostcount'])}-{bags.apns_init_bag()['APNSCourierHostname']}"
COURIER_PORT = 5223
ALPN = [b"apns-security-v2"]


# Connect to the courier server
def _connect(private_key: str, cert: str) -> tlslite.TLSConnection:
    # Connect to the courier server
    sock = socket.create_connection((COURIER_HOST, COURIER_PORT))
    # Wrap the socket in TLS
    sock = tlslite.TLSConnection(sock)
    # Parse the certificate and private key
    cert = tlslite.X509CertChain([tlslite.X509().parse(cert)])
    private_key = tlslite.parsePEMKey(private_key, private=True)
    # Handshake with the server
    sock.handshakeClientCert(cert, private_key, alpn=ALPN)

    logger.info(f"Connected to APNs ({COURIER_HOST})")

    return sock


class IncomingQueue:
    def __init__(self):
        self.queue = []
        self.lock = threading.Lock()

    def append(self, item):
        with self.lock:
            self.queue.append(item)

    def pop(self, index = -1):
        with self.lock:
            return self.queue.pop(index)

    def __getitem__(self, index):
        with self.lock:
            return self.queue[index]

    def __len__(self):
        with self.lock:
            return len(self.queue)

    def find(self, finder):
        with self.lock:
            return next((i for i in self.queue if finder(i)), None)

    def pop_find(self, finder):
        with self.lock:
            found = next((i for i in self.queue if finder(i)), None)
            if found is not None:
                # We have the lock, so we can safely remove it
                self.queue.remove(found)
            return found
        
    def remove_all(self, id):
        with self.lock:
            self.queue = [i for i in self.queue if i[0] != id]

    def wait_pop_find(self, finder, delay=0.1):
        found = None
        while found is None:
            found = self.pop_find(finder)
            if found is None:
                time.sleep(delay)
        return found


class APNSConnection:
    incoming_queue = IncomingQueue()

    # Sink everything in the queue
    def sink(self):
        self.incoming_queue = IncomingQueue()

    def _queue_filler(self):
        while True and not self.sock.closed:
            payload = _deserialize_payload(self.sock)

            if payload is not None:
                # Automatically ACK incoming notifications to prevent APNs from getting mad at us
                if payload[0] == 0x0A:
                    logger.debug("Sending automatic ACK")
                    self._send_ack(_get_field(payload[1], 4))
                logger.debug(f"Received payload: {payload}")
                self.incoming_queue.append(payload)
                logger.debug(f"Queue length: {len(self.incoming_queue)}")

    def _keep_alive_loop(self):
        while True and not self.sock.closed:
            time.sleep(300)
            self._keep_alive()

    def __init__(self, private_key=None, cert=None):
        # Generate the private key and certificate if they're not provided
        if private_key is None or cert is None:
            logger.debug("APNs needs a new push certificate")
            self.private_key, self.cert = albert.generate_push_cert()
        else:
            self.private_key, self.cert = private_key, cert

        self.sock = _connect(self.private_key, self.cert)

        self.queue_filler_thread = threading.Thread(
            target=self._queue_filler, daemon=True
        )
        self.queue_filler_thread.start()

        self.keep_alive_thread = threading.Thread(
            target=self._keep_alive_loop, daemon=True
        )
        self.keep_alive_thread.start()


    def connect(self, root: bool = True, token: bytes = None):
        if token is None:
            logger.debug(f"Sending connect message without token (root={root})")
        else:
            logger.debug(f"Sending connect message with token {b64encode(token).decode()} (root={root})")
        flags = 0b01000001
        if root:
            flags |= 0b0100

        if token is None:
            payload = _serialize_payload(
                7, [(2, 0x01.to_bytes(1, "big")), (5, flags.to_bytes(4, "big"))]
            )
        else:
            payload = _serialize_payload(
                7,
                [
                    (1, token),
                    (2, 0x01.to_bytes(1, "big")),
                    (5, flags.to_bytes(4, "big")),
                ],
            )

        self.sock.write(payload)

        payload = self.incoming_queue.wait_pop_find(lambda i: i[0] == 8)

        if (
            payload == None
            or payload[0] != 8
            or _get_field(payload[1], 1) != 0x00.to_bytes(1, "big")
        ):
            raise Exception("Failed to connect")

        new_token = _get_field(payload[1], 3)
        if new_token is not None:
            self.token = new_token
        elif token is not None:
            self.token = token
        else:
            raise Exception("No token")
        
        logger.debug(f"Recieved connect response with token {b64encode(self.token).decode()}")

        return self.token

    def filter(self, topics: list[str]):
        logger.debug(f"Sending filter message with topics {topics}")
        fields = [(1, self.token)]

        for topic in topics:
            fields.append((2, sha1(topic.encode()).digest()))

        payload = _serialize_payload(9, fields)

        self.sock.write(payload)

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

        self.sock.write(payload)

        # Wait for ACK
        payload = self.incoming_queue.wait_pop_find(lambda i: i[0] == 0x0B)

        if payload[1][0][1] != 0x00.to_bytes(1, "big"):
            raise Exception("Failed to send message")

    def set_state(self, state: int):
        logger.debug(f"Sending state message with state {state}")
        self.sock.write(
            _serialize_payload(
                0x14,
                [(1, state.to_bytes(1, "big")), (2, 0x7FFFFFFF.to_bytes(4, "big"))],
            )
        )

    def _keep_alive(self):
        logger.debug("Sending keep alive message")
        self.sock.write(_serialize_payload(0x0C, []))
        # Remove any keep alive responses we have or missed
        self.incoming_queue.remove_all(0x0D)
        

    def _send_ack(self, id: bytes):
        logger.debug(f"Sending ACK for message {id}")
        payload = _serialize_payload(0x0B, [(1, self.token), (4, id), (8, b"\x00")])
        self.sock.write(payload)
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
def _deserialize_payload(stream) -> tuple[int, list[tuple[int, bytes]]] | None:
    id = int.from_bytes(stream.read(1), "big")

    if id == 0x0:
        return None

    length = int.from_bytes(stream.read(4), "big")

    buffer = stream.read(length)

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
