from __future__ import annotations

import logging
from dataclasses import MISSING, field
from dataclasses import fields as dataclass_fields
from typing import Any, TypeVar

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
            if f.metadata is None or "packet_id" not in f.metadata:
                continue
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
            elif t == "list":
                field_values[f.name] = field_value
            else:
                raise TypeError(f"Unsupported field type: {t}")
        # Check for extra fields
        for field in packet.fields:
            if field.id not in [
                f.metadata["packet_id"]
                for f in dataclass_fields(cls)
                if f.metadata is not None and "packet_id" in f.metadata
            ]:
                logging.warning(
                    f"Unexpected field with packet ID {field.id} in packet {packet}"
                )
                # raise ValueError(f"Unexpected field with packet ID {field.id}")
        return cls(**field_values)

    def to_packet(self) -> Packet:
        packet_fields = []
        for f in dataclass_fields(self):
            if f.metadata is None or "packet_id" not in f.metadata:
                continue
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


def fid(
    packet_id: int,
    byte_len: int = 1,
    default: Any = MISSING,
    default_factory: Any = MISSING,
    repr: bool = True,
):
    """
    :param packet_id: The packet ID of the field
    :param byte_len: The length of the field in bytes (for int fields)
    :param default: The default value of the field
    """
    if not default == MISSING and not default_factory == MISSING:
        raise ValueError("Cannot specify both default and default_factory")
    if not default == MISSING:
        return field(
            metadata={"packet_id": packet_id, "packet_bytes": byte_len},
            default=default,
            repr=repr,
        )
    if not default_factory == MISSING:
        return field(
            metadata={"packet_id": packet_id, "packet_bytes": byte_len},
            default_factory=default_factory,
            repr=repr,
        )
    else:
        return field(
            metadata={"packet_id": packet_id, "packet_bytes": byte_len}, repr=repr
        )
