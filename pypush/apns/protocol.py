from __future__ import annotations

from enum import Enum
from dataclasses import dataclass
from typing import Optional
from anyio.abc import ByteStream


# Implement receive_exact on ByteStream
async def receive_exact(stream: ByteStream, length: int) -> bytes:
    buffer = b""
    while len(buffer) < length:
        buffer += await stream.receive(length - len(buffer))
    return buffer


class Command(Enum):
    Connect = 7
    ConnectAck = 8
    FilterTopics = 9
    SendMessage = 10
    SendMessageAck = 11
    KeepAlive = 12
    KeepAliveAck = 13
    Unknown3 = 14
    SetState = 20
    Unknown = 29
    Unknown2 = 32


def connect(
    certificate: bytes,
    nonce: bytes,
    signature: bytes,
    flags: int,
    token: Optional[bytes] = None,
) -> Packet:
    fields = [
        Field(0x2, b"\x01"),
        Field(0x5, flags.to_bytes(4, "big")),
        Field(0xC, certificate),
        Field(0xD, nonce),
        Field(0xE, signature),
    ]
    if token:
        fields.insert(0, Field(0x1, token))
    return Packet(Command.Connect, fields)


def keep_alive() -> Packet:
    return Packet(Command.KeepAlive, [])


def set_state(state: int) -> Packet:
    return Packet(
        Command.SetState,
        [Field(1, state.to_bytes(1, "big")), Field(2, 0x7FFFFFFF.to_bytes(4, "big"))],
    )


@dataclass
class Field:
    id: int
    value: bytes

    @staticmethod
    def _from_bytes(stream: bytes) -> Field:
        id = int.from_bytes(stream[:1], "big")
        length = int.from_bytes(stream[1:3], "big")
        value = stream[3 : 3 + length]
        return Field(id, value)

    @staticmethod
    def _packed_from_bytes(stream: bytes) -> Field:
        raise NotImplementedError()

    @staticmethod
    def from_bytes(stream: bytes, packed: bool = False) -> Field:
        if packed:
            return Field._packed_from_bytes(stream)
        return Field._from_bytes(stream)

    def _to_bytes(self) -> bytes:
        return (
            self.id.to_bytes(1, "big") + len(self.value).to_bytes(2, "big") + self.value
        )

    def _packed_to_bytes(self) -> bytes:
        raise NotImplementedError()

    def to_bytes(self, packed: bool = False) -> bytes:
        if packed:
            return self._packed_to_bytes()
        return self._to_bytes()


@dataclass
class Packet:
    command: Command
    fields: list[Field]

    def _packed_to_bytes(self) -> bytes:
        raise NotImplementedError()

    def _to_bytes(self) -> bytes:
        payload = b""

        for field in self.fields:
            payload += field.to_bytes()

        return (
            self.command.value.to_bytes(1, "big")
            + len(payload).to_bytes(4, "big")
            + payload
        )

    def to_bytes(self, packed: bool = False) -> bytes:
        if packed:
            return self._packed_to_bytes()
        return self._to_bytes()

    @staticmethod
    async def _packed_from_stream(stream: ByteStream) -> Packet:
        raise NotImplementedError()

    @staticmethod
    async def _from_stream(stream: ByteStream) -> Packet:
        #id = int.from_bytes(await receive_exact(stream, 1), "big")
        #print("got id")

        # TODO: Can some of this error handling be removed with readexactly?
        if not (id_bytes := await receive_exact(stream, 1)):
            raise Exception("Unable to read payload id from stream")
        id: int = int.from_bytes(id_bytes, "big")

        if (length := await receive_exact(stream, 4)) is None:
            raise Exception("Unable to read payload length from stream")
        length = int.from_bytes(length, "big")

        if length == 0:
            return Packet(Command(id), [])

        # buffer = await receive_exact(stream, length)
        # if buffer is None:
        #    raise Exception("Unable to read payload from stream")
        buffer = await receive_exact(stream, length)
        fields = []

        while len(buffer) > 0:
            field = Field.from_bytes(buffer)
            fields.append(field)
            buffer = buffer[3 + len(field.value) :]

        return Packet(Command(id), fields)

    @staticmethod
    async def from_stream(stream: ByteStream, packed: bool = False) -> Packet:
        """
        Stream methods are directly implemented in the Packet class so that we know the length of the packet
        """
        if packed:
            return await Packet._packed_from_stream(stream)
        return await Packet._from_stream(stream)
