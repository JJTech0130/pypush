import dataclasses
import logging
import random
import typing
import uuid
from typing import Literal
from io import BytesIO


import requests

from . import _utils, cloudkit_pb2, gsa

logger = logging.getLogger("cloudkit")


@dataclasses.dataclass
class Record:
    name: uuid.UUID
    type: str
    fields: dict[str, typing.Any]


class CloudKit:
    def __init__(
        self, dsid: str, cloudkit_token: str, mme_token: str, sandbox: bool = False
    ):
        """
        Represents a CloudKit user.
        `dsid`: The user's DSID.
        `cloudkit_token`: `cloudKitToken` from the `com.apple.mobileme` delegate.
        `mme_token`: `mmeAuthToken` from the `com.apple.mobileme` delegate.
        `sandbox`: Whether to use the CloudKit sandbox environment.
        """
        self.dsid = dsid
        self.cloudkit_token = cloudkit_token
        self.mme_token = mme_token
        self.sandbox = sandbox

    def container(
        self,
        container: str,
        scope: Literal["PUBLIC"] | Literal["PRIVATE"] | Literal["SHARED"] = "PUBLIC",
    ) -> "CloudKitContainer":
        """
        Convenience method for creating a CloudKitContainer object.
        """
        return CloudKitContainer(container, self, scope)


class CloudKitContainer:
    def __init__(
        self,
        container: str,
        user: CloudKit,
        scope: Literal["PUBLIC"] | Literal["PRIVATE"] | Literal["SHARED"] = "PUBLIC",
    ):
        """
        Represents a CloudKit container.
        container: The CloudKit container ID. (e.g. "iCloud.dev.jjtech.experiments.cktest")
        user: The CloudKit user to use for authentication.
        scope: The CloudKit database scope to use.
        """
        self.container = container
        self.user = user
        self.scope = scope
        self.user_id = self._fetch_user_id()

    def _fetch_user_id(self):
        headers = {
            "x-cloudkit-containerid": self.container,
            "x-cloudkit-bundleid": ".".join(
                self.container.split(".")[1:]
            ),  # Remove the "iCloud." prefix
            "x-cloudkit-databasescope": self.scope,
            "x-cloudkit-environment": "Sandbox" if self.user.sandbox else "Production",
            "accept": "application/x-protobuf",
            "x-apple-operation-id": random.randbytes(8).hex(),
            "x-apple-request-uuid": str(uuid.uuid4()).upper(),
        }

        headers.update(gsa.generate_anisette_headers())

        r = requests.post(
            "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit",
            params={"container": self.container},
            headers=headers,
            auth=(self.user.dsid, self.user.mme_token),
            verify=False,
        )

        logger.debug("Got app init response: ", r.content)
        return r.json()["cloudKitUserId"]

    def save_record(
        self, record: Record, zone: str = "_defaultZone", owner: str = "_defaultOwner"
    ) -> None:
        """
        Saves a record to the container.
        """
        logger.info(f"Saving record {record.name} to {self.container}")

        headers = {
            "x-cloudkit-authtoken": self.user.cloudkit_token,
            "x-cloudkit-userid": self.user_id,
            "x-cloudkit-containerid": self.container,
            "x-cloudkit-bundleid": ".".join(
                self.container.split(".")[1:]
            ),  # Remove the "iCloud." prefix
            "x-cloudkit-databasescope": self.scope,
            "x-cloudkit-environment": "Sandbox" if self.user.sandbox else "Production",
            "accept": "application/x-protobuf",
            "content-type": 'application/x-protobuf; desc="https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc"; messageType=RequestOperation; delimited=true',
            "x-apple-operation-id": random.randbytes(8).hex(),
            "x-apple-request-uuid": str(uuid.uuid4()).upper(),
            "user-agent": "CloudKit/2060.11 (22F82)",
        }

        headers.update(gsa.generate_anisette_headers())

        body = _build_record_save_request(
            record, self.container, self.user.sandbox, self.scope, zone, owner
        )
        r = requests.post(
            "https://gateway.icloud.com/ckdatabase/api/client/record/save",
            headers=headers,
            data=body,
            verify=False,
        )

        _parse_response(r.content) # Will raise an exception if the response is an error

def _parse_response(response: bytes):
    from io import BytesIO
    length, read = _utils.ULEB128.decode_reader(BytesIO(response))
    if length + read < len(response):
        logger.warning(f"Response is longer than expected: {length + read} < {len(response)} (multiple messages?)")
    response = response[read:length+read]

    try:
        r = cloudkit_pb2.ResponseOperation.FromString(response)
    except Exception as e:
        logger.warning(f"Failed to parse response: {e} {response.hex()}")
        raise
    
    if r.result.code != cloudkit_pb2.ResponseOperation.Result.Code.SUCCESS:
        if r.result.code == cloudkit_pb2.ResponseOperation.Result.Code.FAILURE:
            raise Exception(f"CloudKit request failed: {r.result.error.errorDescription}")
        else:
            raise Exception("Unknown CloudKit error")


def _build_record_save_request(
    record: Record,
    container: str,
    sandbox: bool = False,
    database: Literal["PUBLIC"] | Literal["PRIVATE"] | Literal["SHARED"] = "PUBLIC",
    zone: str = "_defaultZone",
    owner: str = "_defaultOwner",
):
    hardware_id = uuid.uuid4()  # Generate a new hardware ID for each request?
    operation_uuid = uuid.uuid4()  # Generate a new operation UUID for each request?
    record_id = uuid.uuid4()  # Generate a new record ID for each request?

    request = cloudkit_pb2.RequestOperation()
    request.header.applicationContainer = container
    request.header.applicationContainerEnvironment = (
        cloudkit_pb2.RequestOperation.Header.ContainerEnvironment.SANDBOX
        if sandbox
        else cloudkit_pb2.RequestOperation.Header.ContainerEnvironment.PRODUCTION
    )

    request.header.deviceHardwareID = str(hardware_id).upper()

    if database == "PUBLIC":
        request.header.targetDatabase = (
            cloudkit_pb2.RequestOperation.Header.Database.PUBLIC_DB
        )
    elif database == "PRIVATE":
        request.header.targetDatabase = (
            cloudkit_pb2.RequestOperation.Header.Database.PRIVATE_DB
        )
    elif database == "SHARED":
        request.header.targetDatabase = (
            cloudkit_pb2.RequestOperation.Header.Database.SHARED_DB
        )

    request.header.isolationLevel = (
        cloudkit_pb2.RequestOperation.Header.IsolationLevel.ZONE
    )

    request.request.operationUUID = str(operation_uuid).upper()
    request.request.type = cloudkit_pb2.Operation.Type.RECORD_SAVE_TYPE
    request.request.last = True

    request.recordSaveRequest.record.recordIdentifier.value.name = str(
        record_id
    ).upper()
    request.recordSaveRequest.record.recordIdentifier.value.type = (
        cloudkit_pb2.Identifier.Type.RECORD
    )

    request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.value.name = zone
    request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.value.type = (
        cloudkit_pb2.Identifier.Type.RECORD_ZONE
    )

    request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.ownerIdentifier.name = (
        owner
    )
    request.recordSaveRequest.record.recordIdentifier.zoneIdentifier.ownerIdentifier.type = (
        cloudkit_pb2.Identifier.Type.USER
    )

    request.recordSaveRequest.record.type.name = record.type

    for key, value in record.fields.items():
        request.recordSaveRequest.record.recordField.append(cloudkit_pb2.Record.Field())
        request.recordSaveRequest.record.recordField[-1].identifier.name = key
        request.recordSaveRequest.record.recordField[
            -1
        ].value.type = cloudkit_pb2.Record.Field.Value.Type.STRING_TYPE
        request.recordSaveRequest.record.recordField[-1].value.stringValue = value

    len_bytes = _utils.ULEB128.encode(len(request.SerializeToString()))

    return len_bytes + request.SerializeToString()
