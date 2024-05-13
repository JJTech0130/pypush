from __future__ import annotations

from dataclasses import dataclass
from asyncio import StreamReader, StreamWriter


@dataclass
class Field:
    id: int
    value: bytes

    @staticmethod
    def from_buffer(stream: bytes) -> Field:
        id = int.from_bytes(stream[:1], "big")
        length = int.from_bytes(stream[1:3], "big")
        value = stream[3 : 3 + length]
        return Field(id, value)

    def to_buffer(self) -> bytes:
        return (
            self.id.to_bytes(1, "big") + len(self.value).to_bytes(2, "big") + self.value
        )


@dataclass
class Payload:
    id: int
    fields: list[Field]

    @staticmethod
    async def read_from_stream(stream: StreamReader) -> Payload:
        # TODO: Can some of this error handling be removed with readexactly?
        if not (id_bytes := await stream.readexactly(1)):
            raise Exception("Unable to read payload id from stream")
        id: int = int.from_bytes(id_bytes, "big")

        if (length := await stream.readexactly(4)) is None:
            raise Exception("Unable to read payload length from stream")
        length = int.from_bytes(length, "big")

        if length == 0:
            return Payload(id, [])

        # buffer = await receive_exact(stream, length)
        # if buffer is None:
        #    raise Exception("Unable to read payload from stream")
        buffer = await stream.readexactly(length)
        fields = []

        while len(buffer) > 0:
            field = Field.from_buffer(buffer)
            fields.append(field)
            buffer = buffer[3 + len(field.value) :]

        return Payload(id, fields)

    async def write_to_stream(self, stream: StreamWriter):
        payload = b""

        for field in self.fields:
            payload += field.to_buffer()

        buffer = self.id.to_bytes(1, "big") + len(payload).to_bytes(4, "big") + payload

        stream.write(buffer)
        await stream.drain()

    def fields_with_id(self, id: int):
        return [field for field in self.fields if field.id == id]
