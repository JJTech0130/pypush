from __future__ import annotations

import logging
from dataclasses import MISSING, field
from dataclasses import fields as dataclass_fields
from typing import Any, TypeVar, Union, get_args, get_origin

from pypush.apns.transport import Packet

T = TypeVar("T")


def command(cls: T) -> T:
    """
    Automatically add from_packet and to_packet methods to a dataclass
    """

    def from_packet(cls, packet: Packet):
        assert packet.id == cls.PacketType
        field_values = {}
        for current_field in dataclass_fields(cls):
            if (
                current_field.metadata is None
                or "packet_id" not in current_field.metadata
            ):
                # This isn't meant for us, just skip it
                continue

            packet_value = packet.fields_for_id(current_field.metadata["packet_id"])

            current_field_type = current_field.type

            if get_origin(current_field_type) is Union and type(None) in get_args(
                current_field_type
            ):  # Optional
                if not packet_value:
                    field_values[current_field.name] = None
                    continue
                current_field_type = get_args(current_field.type)[0]
            else:
                # If the field is not optional, it must be present
                if not packet_value:
                    raise ValueError(
                        f"Field with packet ID {current_field.metadata['packet_id']} not found in packet"
                    )

            if get_origin(current_field_type) is list:
                assert get_args(current_field_type) == (bytes,)
                field_values[current_field.name] = packet_value
            else:
                # If it's not supposed to be a list, assume that there is only 1 field with this ID
                assert len(packet_value) == 1
                packet_value = packet_value[0]

                if current_field_type == int:
                    assert len(packet_value) == current_field.metadata["packet_bytes"]
                    field_values[current_field.name] = int.from_bytes(
                        packet_value, "big"
                    )
                elif current_field_type == str:
                    field_values[current_field.name] = packet_value.decode()
                elif current_field_type == bytes:
                    field_values[current_field.name] = packet_value
                else:
                    raise TypeError(
                        f"Unsupported field type: {repr(current_field_type)} for field '{current_field.name}' in {cls.__name__}"
                    )

        # Check for extra fields
        for current_field in packet.fields:
            if current_field.id not in [
                f.metadata["packet_id"]
                for f in dataclass_fields(cls)
                if f.metadata is not None and "packet_id" in f.metadata
            ]:
                logging.warning(
                    f"Unexpected field with packet ID {current_field.id} in packet {packet}"
                )
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
    if default != MISSING and default_factory != MISSING:
        raise ValueError("Cannot specify both default and default_factory")
    if default != MISSING:
        return field(
            metadata={"packet_id": packet_id, "packet_bytes": byte_len},
            default=default,
            repr=repr,
        )
    if default_factory != MISSING:
        return field(
            metadata={"packet_id": packet_id, "packet_bytes": byte_len},
            default_factory=default_factory,
            repr=repr,
        )
    else:
        return field(
            metadata={"packet_id": packet_id, "packet_bytes": byte_len}, repr=repr
        )
