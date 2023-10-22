from typing import Literal
from . import cloudkit_pb2
import uuid
import dataclasses
import typing

@dataclasses.dataclass
class Record:
    name: uuid.UUID
    type: str
    fields: dict[str, typing.Any]

def build_record_save_request(
    record: Record,
    container: str,
    sandbox: bool = False,
    database: Literal["PUBLIC"] | Literal["PRIVATE"] | Literal["SHARED"] = "PUBLIC",
    zone: str = "_defaultZone",
    owner: str = "_defaultOwner",
):
    MAGIC_BYTES = b"\xfe\x03"

    hardware_id = uuid.uuid4() # Generate a new hardware ID for each request?
    operation_uuid = uuid.uuid4() # Generate a new operation UUID for each request?
    record_id = uuid.uuid4() # Generate a new record ID for each request?

    request = cloudkit_pb2.RequestOperation()
    request.header.applicationContainer = container
    request.header.applicationContainerEnvironment = cloudkit_pb2.RequestOperation.Header.ContainerEnvironment.SANDBOX if sandbox else cloudkit_pb2.RequestOperation.Header.ContainerEnvironment.PRODUCTION

    request.header.deviceHardwareID = str(hardware_id).upper()

    if database == "PUBLIC":
        request.header.targetDatabase = cloudkit_pb2.RequestOperation.Header.Database.PUBLIC_DB
    elif database == "PRIVATE":
        request.header.targetDatabase = cloudkit_pb2.RequestOperation.Header.Database.PRIVATE_DB
    elif database == "SHARED":
        request.header.targetDatabase = cloudkit_pb2.RequestOperation.Header.Database.SHARED_DB

    request.header.isolationLevel = cloudkit_pb2.RequestOperation.Header.IsolationLevel.ZONE


    request.request.operationUUID = str(operation_uuid).upper()
    request.request.type = cloudkit_pb2.Operation.Type.RECORD_SAVE_TYPE
    request.request.last = True


    request.recordSaveRequest.record.recordIdentifier.value.name = str(record_id).upper()
    request.recordSaveRequest.record.recordIdentifier.value.type = cloudkit_pb2.Identifier.Type.RECORD

    request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.value.name = zone
    request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.value.type = cloudkit_pb2.Identifier.Type.RECORD_ZONE

    request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.ownerIdentifier.name = owner
    request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.ownerIdentifier.type = cloudkit_pb2.Identifier.Type.USER

    request.recordSaveRequest.record.type.name = record.type

    for key, value in record.fields.items():
        request.recordSaveRequest.record.recordField.append(cloudkit_pb2.Record.Field())
        request.recordSaveRequest.record.recordField[-1].identifier.name = key
        request.recordSaveRequest.record.recordField[-1].value.type = cloudkit_pb2.Record.Field.Value.Type.STRING_TYPE
        request.recordSaveRequest.record.recordField[-1].value.stringValue = value

    return MAGIC_BYTES + request.SerializeToString()