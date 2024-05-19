from __future__ import annotations

import ssl
from dataclasses import dataclass
from enum import Enum

import anyio
from anyio.abc import ByteStream, ObjectStream

# Pick a random courier server from 01 to APNSCourierHostcount
COURIER_PORT = 5223
ALPN = ["apns-security-v3"]

# Manages TLS connection to courier, parses into raw packets


@dataclass
class Packet:
    @dataclass
    class Field:
        id: int
        value: bytes

    class Type(Enum):
        Connect = 7
        ConnectAck = 8
        FilterTopics = 9
        SendMessage = 10
        SendMessageAck = 11
        KeepAlive = 12
        KeepAliveAck = 13
        NoStorage = 14
        ScopedToken = 17
        ScopedTokenAck = 18
        SetState = 20
        UNKNOWN = "Unknown"

        def __new__(cls, value):
            # Create a new instance of Enum
            obj = object.__new__(cls)
            obj._value_ = value
            return obj

        @classmethod
        def _missing_(cls, value):
            # Handle unknown values
            instance = cls.UNKNOWN
            instance._value_ = value  # Assign the unknown value
            return instance

        def __str__(self):
            if self is Packet.Type.UNKNOWN:
                return f"Unknown({self._value_})"
            return self.name

    id: Type
    fields: list[Field]

    def fields_for_id(self, id: int) -> list[bytes]:
        return [field.value for field in self.fields if field.id == id]


async def create_courier_connection(
    sandbox: bool = False,
    courier: str = "1-courier.push.apple.com",
) -> PacketStream:
    context = ssl.create_default_context()
    context.set_alpn_protocols(ALPN)

    sni = "courier.sandbox.push.apple.com" if sandbox else "courier.push.apple.com"

    # TODO: Verify courier certificate
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return PacketStream(
        await anyio.connect_tcp(
            courier,
            COURIER_PORT,
            ssl_context=context,
            tls_standard_compatible=False,
            tls_hostname=sni,
        )
    )


async def receive_exact(stream: ByteStream, length: int) -> bytes:
    buffer = b""
    while len(buffer) < length:
        buffer += await stream.receive(length - len(buffer))
    return buffer


@dataclass
class PacketStream(ObjectStream[Packet]):
    transport_stream: ByteStream

    def _serialize_field(self, field: Packet.Field) -> bytes:
        return (
            field.id.to_bytes(1, "big")
            + len(field.value).to_bytes(2, "big")
            + field.value
        )

    def _serialize_packet(self, packet: Packet) -> bytes:
        payload = b""
        for field in packet.fields:
            payload += self._serialize_field(field)
        return (
            packet.id.value.to_bytes(1, "big")
            + len(payload).to_bytes(4, "big")
            + payload
        )

    async def send(self, item: Packet) -> None:
        await self.transport_stream.send(self._serialize_packet(item))

    async def receive(self) -> Packet:
        packet_id = int.from_bytes(await receive_exact(self.transport_stream, 1), "big")
        packet_length = int.from_bytes(
            await receive_exact(self.transport_stream, 4), "big"
        )
        if packet_length == 0:
            return Packet(Packet.Type(packet_id), [])
        payload = await receive_exact(self.transport_stream, packet_length)
        assert len(payload) == packet_length
        fields = []
        while len(payload) > 0:
            field_id = int.from_bytes(payload[:1], "big")
            field_length = int.from_bytes(payload[1:3], "big")
            field_value = payload[3 : 3 + field_length]
            fields.append(Packet.Field(field_id, field_value))
            payload = payload[3 + field_length :]
        return Packet(Packet.Type(packet_id), fields)

    async def aclose(self) -> None:
        await self.transport_stream.aclose()

    async def send_eof(self) -> None:
        await self.transport_stream.send_eof()
