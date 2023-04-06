from __future__ import annotations

import courier, albert
from hashlib import sha1


def _serialize_field(id: int, value: bytes) -> bytes:
    return id.to_bytes() + len(value).to_bytes(2, "big") + value


def _serialize_payload(id: int, fields: list[(int, bytes)]) -> bytes:
    payload = b""

    for fid, value in fields:
        payload += _serialize_field(fid, value)

    return id.to_bytes() + len(payload).to_bytes(4, "big") + payload


def _deserialize_field(stream: bytes) -> tuple[int, bytes]:
    id = int.from_bytes(stream[:1], "big")
    length = int.from_bytes(stream[1:3], "big")
    value = stream[3 : 3 + length]
    return id, value


# Note: Takes a stream, not a buffer, as we do not know the length of the payload
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


# Returns the value of the first field with the given id
def _get_field(fields: list[tuple[int, bytes]], id: int) -> bytes:
    for field_id, value in fields:
        if field_id == id:
            return value
    return None


class APNSConnection:
    def __init__(self, private_key=None, cert=None):
        # Generate the private key and certificate if they're not provided
        if private_key is None or cert is None:
            self.private_key, self.cert = albert.generate_push_cert()
        else:
            self.private_key, self.cert = private_key, cert

        self.sock = courier.connect(self.private_key, self.cert)

    def connect(self, token: bytes = None):
        if token is None:
            payload = _serialize_payload(7, [(2, 0x01.to_bytes())])
        else:
            payload = _serialize_payload(7, [(1, token), (2, 0x01.to_bytes())])

        self.sock.write(payload)

        payload = _deserialize_payload(self.sock)

        if payload == None or payload[0] != 8 or _get_field(payload[1], 1) != 0x00.to_bytes():
            raise Exception("Failed to connect")
        
        self.token = _get_field(payload[1], 3)

    def filter(self, topics: list[str]):
        fields = [(1, self.token)]

        for topic in topics:
            fields.append((2, sha1(topic.encode()).digest()))

        payload = _serialize_payload(9, fields)

        self.sock.write(payload)
