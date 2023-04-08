from __future__ import annotations

import courier, albert
from hashlib import sha1
import threading
import time
import random

class APNSConnection:
    incoming_queue = []

    def _queue_filler(self):
        while True and not self.sock.closed:
            #print(self.sock.closed)
            #print("QUEUE: Waiting for payload...")
            #self.sock.read(1)
            print("QUEUE: Got payload?")
            payload = _deserialize_payload(self.sock)
            #print("QUEUE: Got payload?")

            if payload is not None:
                print("QUEUE: Received payload: " + str(payload))
                self.incoming_queue.append(payload)
        print("QUEUE: Thread ended")

    def _pop_by_id(self, id: int) -> tuple[int, list[tuple[int, bytes]]] | None:
        print("QUEUE: Looking for id " + str(id) + " in " + str(self.incoming_queue))
        for i in range(len(self.incoming_queue)):
            if self.incoming_queue[i][0] == id:
                return self.incoming_queue.pop(i)
        return None
    
    def wait_for_packet(self, id: int) -> tuple[int, list[tuple[int, bytes]]]:
        payload = self._pop_by_id(id)
        while payload is None:
            payload = self._pop_by_id(id)
            time.sleep(0.1)
        return payload
    
    def __init__(self, private_key=None, cert=None):
        # Generate the private key and certificate if they're not provided
        if private_key is None or cert is None:
            self.private_key, self.cert = albert.generate_push_cert()
        else:
            self.private_key, self.cert = private_key, cert

        self.sock = courier.connect(self.private_key, self.cert)

        # Start the queue filler thread
        self.queue_filler_thread = threading.Thread(target=self._queue_filler, daemon=True)
        self.queue_filler_thread.start()

    def connect(self, root: bool = True, token: bytes = None):
        flags = 0b01000001
        if root:
            flags |= 0b0100
        
        if token is None:
            payload = _serialize_payload(7, [(2, 0x01.to_bytes()), (5, flags.to_bytes(4))])
        else:
            payload = _serialize_payload(7, [(1, token), (2, 0x01.to_bytes()), (5, flags.to_bytes(4))])

        self.sock.write(payload)

        payload = self.wait_for_packet(8)

        if payload == None or payload[0] != 8 or _get_field(payload[1], 1) != 0x00.to_bytes():
            raise Exception("Failed to connect")
        
        self.token = _get_field(payload[1], 3)

        return self.token

    def filter(self, topics: list[str]):
        fields = [(1, self.token)]

        for topic in topics:
            fields.append((2, sha1(topic.encode()).digest()))

        payload = _serialize_payload(9, fields)

        self.sock.write(payload)
    
    def send_message(self, topic: str, payload: str):
        payload = _serialize_payload(0x0a,
                                     [(4, random.randbytes(4)),
                                      (1, sha1(topic.encode()).digest()),
                                      (2, self.token),
                                      (3, payload)])
        #print(payload)
        
        self.sock.write(payload)

        payload = self.wait_for_packet(0x0b)

        #payload = _deserialize_payload(self.sock)

        print(payload)

    def set_state(self, state: int):
        self.sock.write(_serialize_payload(0x14, [(1, state.to_bytes(1)), (2, 0x7FFFFFFF.to_bytes(4))]))

    def keep_alive(self):
        self.sock.write(_serialize_payload(0x0c, []))

    # TODO: Find a way to make this non-blocking
    #def expect_message(self) -> tuple[int, list[tuple[int, bytes]]] | None:
    #   return _deserialize_payload(self.sock)


def _serialize_field(id: int, value: bytes) -> bytes:
    return id.to_bytes() + len(value).to_bytes(2, "big") + value


def _serialize_payload(id: int, fields: list[(int, bytes)]) -> bytes:
    payload = b""

    for fid, value in fields:
        if fid is not None:
            payload += _serialize_field(fid, value)

    return id.to_bytes() + len(payload).to_bytes(4, "big") + payload


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

def _deserialize_payload_from_buffer(buffer: bytes) -> tuple[int, list[tuple[int, bytes]]] | None:
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