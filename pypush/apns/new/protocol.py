# DO NOT FORMAT THIS FILE

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from pypush.apns.new.transport import Packet


@dataclass
class Command:
    @classmethod
    def from_packet(cls, packet: Packet):
        raise NotImplementedError

    def to_packet(self) -> Packet:
        raise NotImplementedError


@dataclass
class ConnectCommand(Command):
    push_token: bytes
    state: Optional[int]
    flags: int
    interface: Optional[int]
    carrier_name: Optional[str]
    os_version: Optional[str]
    os_build: Optional[str]
    hardware_version: Optional[str]
    certificate: Optional[bytes]
    nonce: Optional[bytes]
    signature: Optional[bytes]
    protocol_version: Optional[int]
    redirect_count: Optional[int]
    dns_resolve_time: Optional[int]
    tls_handshake_time: Optional[int]


    @classmethod
    def from_packet(cls, packet: Packet):
        assert packet.id == Packet.Type.Connect
        # Extract fields relevant to ConnectCommand
        push_token = packet.fields_for_id(1)[0]
        state = int.from_bytes(packet.fields_for_id(2)[0], "big") if packet.fields_for_id(2) else None
        flags = int.from_bytes(packet.fields_for_id(5)[0], "big")
        interface = int.from_bytes(packet.fields_for_id(6)[0], "big") if packet.fields_for_id(6) else None
        carrier_name = packet.fields_for_id(8)[0].decode() if packet.fields_for_id(8) else None
        os_version = packet.fields_for_id(9)[0].decode() if packet.fields_for_id(9) else None
        os_build = packet.fields_for_id(10)[0].decode() if packet.fields_for_id(10) else None
        hardware_version = packet.fields_for_id(11)[0].decode() if packet.fields_for_id(11) else None
        certificate = packet.fields_for_id(12)[0] if packet.fields_for_id(12) else None
        nonce = packet.fields_for_id(13)[0] if packet.fields_for_id(13) else None
        signature = packet.fields_for_id(14)[0] if packet.fields_for_id(14) else None
        protocol_version = int.from_bytes(packet.fields_for_id(16)[0], "big") if packet.fields_for_id(16) else None
        redirect_count = int.from_bytes(packet.fields_for_id(17)[0], "big") if packet.fields_for_id(17) else None
        dns_resolve_time = int.from_bytes(packet.fields_for_id(19)[0], "big") if packet.fields_for_id(19) else None
        tls_handshake_time = int.from_bytes(packet.fields_for_id(20)[0], "big") if packet.fields_for_id(20) else None

        return cls(
            push_token=push_token,
            state=state,
            flags=flags,
            interface=interface,
            carrier_name=carrier_name,
            os_version=os_version,
            os_build=os_build,
            hardware_version=hardware_version,
            certificate=certificate,
            nonce=nonce,
            signature=signature,
            protocol_version=protocol_version,
            redirect_count=redirect_count,
            dns_resolve_time=dns_resolve_time,
            tls_handshake_time=tls_handshake_time
        )

    def to_packet(self) -> Packet:
        fields: list[Packet.Field] = [field for field in [
            Packet.Field(id=1, value=self.push_token),
            Packet.Field(id=2, value=self.state.to_bytes(1, "big")) if self.state else None,
            Packet.Field(id=5, value=self.flags.to_bytes(4, "big")),
            Packet.Field(id=6, value=self.interface.to_bytes(1, "big")) if self.interface else None,
            Packet.Field(id=8, value=self.carrier_name.encode()) if self.carrier_name else None,
            Packet.Field(id=9, value=self.os_version.encode()) if self.os_version else None,
            Packet.Field(id=10, value=self.os_build.encode()) if self.os_build else None,
            Packet.Field(id=11, value=self.hardware_version.encode()) if self.hardware_version else None,
            Packet.Field(id=12, value=self.certificate) if self.certificate else None,
            Packet.Field(id=13, value=self.nonce) if self.nonce else None,
            Packet.Field(id=14, value=self.signature) if self.signature else None,
            Packet.Field(id=16, value=self.protocol_version.to_bytes(2, "big")) if self.protocol_version else None,
            Packet.Field(id=17, value=self.redirect_count.to_bytes(2, "big")) if self.redirect_count else None,
            Packet.Field(id=19, value=self.dns_resolve_time.to_bytes(2, "big")) if self.dns_resolve_time else None,
            Packet.Field(id=20, value=self.tls_handshake_time.to_bytes(2, "big")) if self.tls_handshake_time else None,
        ] if field]
        return Packet(id=Packet.Type.Connect, fields=fields)


@dataclass
class KeepAliveCommand(Command):
    connect_method: Optional[str]
    ios_version: Optional[str]
    ios_build: Optional[str]
    device_model: Optional[str]
    unknown: Optional[int]

    @classmethod
    def from_packet(cls, packet: Packet):
        assert packet.id == Packet.Type.KeepAlive
        # Extract fields relevant to KeepAliveCommand
        connect_method = packet.fields_for_id(1)[0].decode() if packet.fields_for_id(1) else None
        ios_version = packet.fields_for_id(2)[0].decode() if packet.fields_for_id(2) else None
        ios_build = packet.fields_for_id(3)[0].decode() if packet.fields_for_id(3) else None
        device_model = packet.fields_for_id(4)[0].decode() if packet.fields_for_id(4) else None
        unknown = int.from_bytes(packet.fields_for_id(5)[0], "big") if packet.fields_for_id(5) else None

        return cls(
            connect_method=connect_method,
            ios_version=ios_version,
            ios_build=ios_build,
            device_model=device_model,
            unknown=unknown
        )

    def to_packet(self) -> Packet:
        fields = [field for field in [
            Packet.Field(id=1, value=self.connect_method.encode()) if self.connect_method else None,
            Packet.Field(id=2, value=self.ios_version.encode()) if self.ios_version else None,
            Packet.Field(id=3, value=self.ios_build.encode()) if self.ios_build else None,
            Packet.Field(id=4, value=self.device_model.encode()) if self.device_model else None,
            Packet.Field(id=5, value=self.unknown.to_bytes(1, "big")) if self.unknown else None,
        ] if field]
        return Packet(id=Packet.Type.KeepAlive, fields=fields)

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
