from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pypush.apns.new.transport import Packet
from pypush.apns.new._protocol import auto_packet, fid


@dataclass
class Command:
    @classmethod
    def from_packet(cls, packet: Packet):
        raise NotImplementedError

    def to_packet(self) -> Packet:
        raise NotImplementedError


@auto_packet
@dataclass
class ConnectCommand(Command):
    PacketType = Packet.Type.Connect

    push_token: bytes = fid(1)
    state: Optional[int] = fid(2)
    flags: int = fid(5, byte_len=4)
    certificate: Optional[bytes] = fid(12)
    nonce: Optional[bytes] = fid(13)
    signature: Optional[bytes] = fid(14)

    interface: Optional[int] = fid(6, default=None)
    carrier_name: Optional[str] = fid(8, default=None)
    os_version: Optional[str] = fid(9, default=None)
    os_build: Optional[str] = fid(10, default=None)
    hardware_version: Optional[str] = fid(11, default=None)
    protocol_version: Optional[int] = fid(16, default=11, byte_len=2)
    redirect_count: Optional[int] = fid(17, default=None, byte_len=2)
    dns_resolve_time: Optional[int] = fid(19, default=None, byte_len=2)
    tls_handshake_time: Optional[int] = fid(20, default=None, byte_len=2)
    unknown1: Optional[bytes] = fid(22, default=None)
    unknown2: Optional[bytes] = fid(26, default=None)


class ConnectAckCommand(Command):
    pass


@auto_packet
@dataclass
class KeepAliveCommand(Command):
    PacketType = Packet.Type.KeepAlive

    connection_method: Optional[str] = fid(1, default=None)
    ios_version: Optional[str] = fid(2, default=None)
    ios_build: Optional[str] = fid(3, default=None)
    device_model: Optional[str] = fid(4, default=None)
    unknown1: Optional[int] = fid(5, default=None, byte_len=2)


@dataclass
class UnknownCommand(Command):
    id: Packet.Type
    fields: list[Packet.Field]

    @classmethod
    def from_packet(cls, packet: Packet):
        return cls(id=packet.id, fields=packet.fields)

    def to_packet(self) -> Packet:
        return Packet(id=self.id, fields=self.fields)


# Factory function to create Command instances from Packets
def command_from_packet(packet: Packet) -> Command:
    command_classes: dict[Packet.Type, type[Command]] = {
        Packet.Type.Connect: ConnectCommand,
        Packet.Type.KeepAlive: KeepAliveCommand,
        # Add other mappings here...
    }
    command_class = command_classes.get(packet.id, None)
    if command_class:
        return command_class.from_packet(packet)
    else:
        return UnknownCommand.from_packet(packet)
