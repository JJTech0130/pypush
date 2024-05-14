import typing
import random
import plistlib
import anyio.streams
import anyio.streams.tls
import httpx
import ssl
import time
import logging
import base64
import anyio
from anyio.abc import TaskGroup

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

from . import protocol

log = logging.getLogger(__name__)

APNS_CONFIG = plistlib.loads(
    plistlib.loads(httpx.get("http://init-p01st.push.apple.com/bag").content)["bag"]
)

# Pick a random courier server from 01 to APNSCourierHostcount
COURIER_HOST = f"{random.randint(1, APNS_CONFIG['APNSCourierHostcount'])}-{APNS_CONFIG['APNSCourierHostname']}"
COURIER_PORT = 5223
ALPN = ["apns-security-v3"]


def command_filter(
    command: protocol.Command,
) -> typing.Callable[[protocol.Packet], bool]:
    return lambda x: x.command == command


class Connection:
    def __init__(
        self,
        certificate: typing.Optional[x509.Certificate],
        private_key: typing.Optional[rsa.RSAPrivateKey],
        token: typing.Optional[bytes] = None,
        packed: bool = False,
    ):
        """
        Create a new APNs connection
        Please use the async context manager to manage the connection

        :param certificate: activation certificate from Albert to authenticate with APNs
        :param private_key: private key for the activation certificate

        :param token: optional token root token to use when connecting
        """
        self._packed = packed

        self.certificate = certificate
        self.private_key = private_key
        self.token = token

        self._incoming_queue: typing.List[protocol.Packet] = []
        self._queue_event = anyio.Event()

        self._filters: dict[str, int] = {}
        self._socket = None

    async def _queue_messages(self):
        while True:
            assert self._socket is not None
            self._incoming_queue.append(await protocol.Packet.from_stream(self._socket))
            # except:
            #     # Reconnect if the connection is dropped
            #     await self._connect(None)
            #     continue
            self._queue_event.set()
            self._queue_event = anyio.Event()

    async def _ping(self):
        while True:
            await anyio.sleep(60)
            await self._send_packet(protocol.keep_alive())
            await self._receive_packet(command_filter(protocol.Command.KeepAliveAck))
            # except:
            #     # Reconnect if the connection is dropped
            #     await self._connect(None)
            #     continue

    async def _connect_socket(self, task_group: typing.Union[TaskGroup, None]):
        # If task_group is None, don't spawn background tasks, assume they will continue from a previous connection
        # Must be able to call this function repeatedly to reconnect the socket if dropped
        assert (
            self._socket is None or task_group is None
        )  # Either this is a fresh connection (socket is None) or we are reconnecting (task_group is None)

        context = ssl.create_default_context()
        if self._packed:
            raise NotImplementedError("Packed mode not implemented")
        else:
            context.set_alpn_protocols(ALPN)

        # TODO: Verify courier certificate
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        self._socket = await anyio.connect_tcp(
            COURIER_HOST, COURIER_PORT, ssl_context=context
        )

        if task_group is not None:
            if False:
                task_group.start_soon(self._queue_messages)
            task_group.start_soon(self._ping)

    async def _connect(self):
        assert self.certificate and self.private_key
        cert = self.certificate.public_bytes(serialization.Encoding.DER)
        nonce = (
            b"\x00" + int(time.time() * 1000).to_bytes(8, "big") + random.randbytes(8)
        )
        signature = b"\x01\x01" + self.private_key.sign(
            nonce, padding.PKCS1v15(), hashes.SHA1()
        )

        # TODO: Send authenticated connect packet
        await self._send_packet(
            protocol.connect(cert, nonce, signature, 0b1000001, self.token)
        )
        # TODO: Send set state packet
        await self._send_packet(protocol.set_state(0x01))
        await self._update_filters()

    async def _aclose(self):
        if self._socket is not None:
            await self._socket.aclose()
            self._socket = None

    async def __aenter__(self):
        # self._tg must be managed using __aenter__ and __aexit__ to ensure it is properly closed
        self._tg = anyio.create_task_group()
        await self._tg.__aenter__()

        await self._connect_socket(self._tg)
        if self.certificate is not None:
            await self._connect()

        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self._tg.__aexit__(exc_type, exc_value, traceback)

        await self._aclose()

    async def _send_packet(self, packet: protocol.Packet):
        if self._socket is None:
            raise Exception("Not connected")
        await self._socket.send(packet.to_bytes(self._packed))

    async def _receive_packet(
        self, filter: typing.Callable[[protocol.Packet], bool] = lambda x: True
    ):
        while True:
            # TODO: Come up with a more efficient way to search for messages
            for message in self._incoming_queue:
                if filter(message):
                    # remove the message from the queue and return it
                    self._incoming_queue.remove(message)
                    return message

            # If no messages were found, wait for the queue to be updated
            await self._queue_event.wait()

    async def _update_filters(self):
        # TODO: Send filter packet with filter list
        pass

    async def _add_filter(self, filter: str):
        if filter in self._filters:
            self._filters[filter] += 1
        else:
            self._filters[filter] = 1
        await self._update_filters()

    async def _remove_filter(self, filter: str):
        if filter in self._filters:
            self._filters[filter] -= 1
            if self._filters[filter] == 0:
                del self._filters[filter]
            await self._update_filters()

    # async def

    ## BIG IDEAS:
    # - Create proxy to test decoding
    # - Use subclasses of Packet, with abstracted serialization

    # @property
    # def connected(self):
    #    return self._socket is not None

    # async def __aenter__(self, reconnect: bool = True):

    #     async with httpx.AsyncClient() as client:
    #         response = await client.get("http://init-p01st.push.apple.com/bag")
    #         APNS_CONFIG = plistlib.loads(plistlib.loads(response.content)["bag"])
    #     # TODO: Implement auto reconnection
    #     self._event_loop = asyncio.get_event_loop()

    #     context = ssl.create_default_context()
    #     context.set_alpn_protocols(ALPN)

    #     # TODO: Verify courier certificate
    #     context.check_hostname = False
    #     context.verify_mode = ssl.CERT_NONE

    #     self._socket = await anyio.connect_tcp(COURIER_HOST, COURIER_PORT, ssl_context=context)
    #     self._socket.
    #     self._socket.__aenter__
    #     self._tg = anyio.create_task_group()
    #     await self._tg.__aenter__()
    #     # Create a task group to manage the queue and keepalive tasks
    #     async with anyio.create_task_group() as tg:
    #         tg.start_soon(self._queue_messages)

    #         await self._connect_pkt(self.certificate, self.private_key, self.token)
    #         await self._state_pkt(0x01)

    #     self._tasks.append(self._event_loop.create_task(self._queue_messages()))

    #     await self._connect_pkt(self.certificate, self.private_key, self.token)
    #     await self._state_pkt(0x01)

    # async def _queue_messages(self):
    #     while True:
    #         self._incoming_queue.append(
    #             await payload.Payload.read_from_stream(self._reader)
    #         )
    #         self._queue_event.set()
    #         self._queue_event.clear()

    # async def _state_pkt(self, state: int):
    #     log.debug(f"Sending state message with state {state}")
    #     await self._send(
    #         payload.Payload(
    #             0x14,
    #             [
    #                 payload.Field(1, state.to_bytes(1, "big")),
    #                 payload.Field(2, 0x7FFFFFFF.to_bytes(4, "big")),
    #             ],
    #         )
    #     )

    # async def _connect_pkt(
    #     self,
    #     certificate: x509.Certificate,
    #     private_key: rsa.RSAPrivateKey,
    #     token: typing.Union[bytes, None],
    # ):
    #     flags = 0b01000001  # TODO: Root/sub-connection flags

    #     cert = certificate.public_bytes(serialization.Encoding.DER)
    #     nonce = (
    #         b"\x00" + int(time.time() * 1000).to_bytes(8, "big") + random.randbytes(8)
    #     )
    #     signature = b"\x01\x01" + private_key.sign(
    #         nonce, padding.PKCS1v15(), hashes.SHA1()
    #     )

    #     p = payload.Payload(
    #         7,
    #         [
    #             payload.Field(0x2, b"\x01"),
    #             payload.Field(0x5, flags.to_bytes(4, "big")),
    #             payload.Field(0xC, cert),
    #             payload.Field(0xD, nonce),
    #             payload.Field(0xE, signature),
    #             # TODO: Metrics/optional device info fields
    #         ],
    #     )

    #     if token:
    #         p.fields.insert(0, payload.Field(0x1, token))

    #     await self._send(p)

    #     resp = await self._receive(8)

    #     if resp.fields_with_id(1)[0].value != b"\x00":
    #         raise Exception("Failed to connect")

    #     if len(resp.fields_with_id(3)) > 0:
    #         new_token = resp.fields_with_id(3)[0].value
    #     else:
    #         if token is None:
    #             raise Exception("No token received")
    #         new_token = token

    #     log.debug(
    #         f"Received connect response with token {base64.b64encode(new_token).decode()}"
    #     )

    #     return new_token


# TODO: Implement sub-connections
