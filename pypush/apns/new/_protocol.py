from __future__ import annotations

from dataclasses import field, fields as dataclass_fields, MISSING
from typing import TypeVar, Any

from pypush.apns.new.transport import Packet

T = TypeVar("T")


def auto_packet(cls: T) -> T:
    """
    Automatically add from_packet and to_packet methods to a dataclass
    """

    def from_packet(cls, packet: Packet):
        assert packet.id == cls.PacketType
        field_values = {}
        for f in dataclass_fields(cls):
            field_value = packet.fields_for_id(f.metadata["packet_id"])
            t = f.type
            if "Optional[" in str(f.type):
                t = t.split("[")[1].split("]")[0]
                if not field_value:
                    field_values[f.name] = None
                    continue
            elif not field_value:
                raise ValueError(
                    f"Field with packet ID {f.metadata['packet_id']} not found in packet"
                )

            # Assume bytes can be converted directly or via custom type conversion
            if t == "int":
                # print(len(field_value[0]), f.metadata["packet_bytes"], "for field", f.name)
                assert len(field_value[0]) == f.metadata["packet_bytes"]
                field_values[f.name] = int.from_bytes(field_value[0], "big")
            elif t == "str":
                field_values[f.name] = field_value[0].decode()
            elif t == "bytes":
                field_values[f.name] = field_value[0]
            elif t == "list[bytes]":
                field_values[f.name] = field_value
            else:
                raise TypeError(f"Unsupported field type: {t}")
        return cls(**field_values)

    def to_packet(self) -> Packet:
        packet_fields = []
        for f in dataclass_fields(self):
            value = getattr(self, f.name)
            if isinstance(value, int):
                packet_value = value.to_bytes(f.metadata["packet_bytes"], "big")
            elif isinstance(value, str):
                packet_value = value.encode()
            elif isinstance(value, bytes):
                packet_value = value
            elif value is None:
                continue
            elif isinstance(value, list):
                for v in value:
                    packet_fields.append(
                        Packet.Field(id=f.metadata["packet_id"], value=v)
                    )
                continue
            else:
                raise TypeError(f"Unsupported field type: {f.type}")
            packet_fields.append(
                Packet.Field(id=f.metadata["packet_id"], value=packet_value)
            )
        return Packet(id=self.PacketType, fields=packet_fields)

    setattr(cls, "from_packet", classmethod(from_packet))
    setattr(cls, "to_packet", to_packet)
    return cls


def fid(packet_id: int, byte_len: int = 1, default: Any = MISSING):
    """
    :param packet_id: The packet ID of the field
    :param byte_len: The length of the field in bytes (for int fields)
    :param default: The default value of the field
    """
    if default is MISSING:
        return field(metadata={"packet_id": packet_id, "packet_bytes": byte_len})
    return field(
        metadata={"packet_id": packet_id, "packet_bytes": byte_len}, default=default
    )
