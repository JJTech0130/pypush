# Lifecycle management, reconnection, etc
from __future__ import annotations

import logging
import random
import time
import typing
from contextlib import asynccontextmanager
from hashlib import sha1

import anyio
from anyio.abc import TaskGroup
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import protocol, transport, _util


@asynccontextmanager
async def create_apns_connection(
    certificate: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
    token: typing.Optional[bytes] = None,
    courier: typing.Optional[str] = None,
):
    async with anyio.create_task_group() as tg:
        conn = Connection(tg, certificate, private_key, token, courier)\
        # Await connected for first time here, so that base token is set
        await conn._connected.wait()
        yield conn
        tg.cancel_scope.cancel()  # Cancel the task group when the context manager exits
    await conn.aclose()  # Make sure to close the connection after the task group is cancelled


class Connection:
    def __init__(
        self,
        task_group: TaskGroup,
        certificate: x509.Certificate,
        private_key: rsa.RSAPrivateKey,
        token: typing.Optional[bytes] = None,
        courier: typing.Optional[str] = None,
    ):

        self.certificate = certificate
        self.private_key = private_key
        self.base_token = token

        self._connected = anyio.Event() # Set when the connection is first established

        self._conn = None
        self._tg = task_group
        self._broadcast = _util.BroadcastStream[protocol.Command]()
        self._reconnect_lock = anyio.Lock()

        if courier is None:
            # Pick a random courier server from 1 to 50
            courier = f"{random.randint(1, 50)}-courier.push.apple.com"
        self.courier = courier

        self._tg.start_soon(self.reconnect)
        self._tg.start_soon(self._ping_task)

    async def _receive_task(self):
        assert self._conn is not None
        async for command in self._conn:
            logging.debug(f"Received command: {command}")
            await self._broadcast.broadcast(command)
        logging.warning("Receive task ended")

    async def _ping_task(self):
        while True:
            await anyio.sleep(30)
            logging.debug("Sending keepalive")
            await self.send(protocol.KeepAliveCommand())
            await self.receive(protocol.KeepAliveAck)

    @_util.exponential_backoff
    async def reconnect(self):
        async with self._reconnect_lock:  # Prevent weird situations where multiple reconnects are happening at once
            if self._conn is not None:
                logging.warning("Closing existing connection")
                await self._conn.aclose()
            self._conn = protocol.CommandStream(
                await transport.create_courier_connection(courier=self.courier)
            )
            cert = self.certificate.public_bytes(serialization.Encoding.DER)
            nonce = (
                b"\x00"
                + int(time.time() * 1000).to_bytes(8, "big")
                + random.randbytes(8)
            )
            signature = b"\x01\x01" + self.private_key.sign(
                nonce, padding.PKCS1v15(), hashes.SHA1()
            )
            await self._conn.send(
                protocol.ConnectCommand(
                    push_token=self.base_token,
                    state=1,
                    flags=65, #69
                    certificate=cert,
                    nonce=nonce,
                    signature=signature,
                )
            )
            self._tg.start_soon(self._receive_task)
            ack = await self.receive(protocol.ConnectAck)
            logging.debug(f"Connected with ack: {ack}")
            assert ack.status == 0
            if self.base_token is None:
                self.base_token = ack.token
            else:
                assert ack.token == self.base_token
            if not self._connected.is_set():
                self._connected.set()

    async def aclose(self):
        if self._conn is not None:
            await self._conn.aclose()
        # Note: Will be reopened if task group is still running and ping task is still running

    T = typing.TypeVar("T", bound=protocol.Command)

    # async def receive_stream(
    #     self, filter: typing.Type[T], max: int = -1
    # ) -> typing.AsyncIterator[T]:
    #     async with self._broadcast.open_stream() as stream:
    #         async for command in stream:
    #             if isinstance(command, filter):
    #                 max -= 1
    #                 yield command
    #             if max == 0:
    #                 break
    #         logging.error("Stream ended") # BUG: Will never happen, async iterators don't autoclose

    async def receive(self, filter: typing.Type[T]) -> T:
        async with self._broadcast.open_stream() as stream:
            async for command in stream:
                if isinstance(command, filter):
                    return command
        raise ValueError("Did not receive expected command")

    async def send(self, command: protocol.Command):
        try:
            assert self._conn is not None
            await self._conn.send(command)
        except Exception as e:
            logging.warning(f"Error sending command, reconnecting")
            await self.reconnect()
            await self.send(command)

    async def filter(self, topics: list[str]):
        assert self.base_token is not None
        await self.send(protocol.FilterCommand(token=self.base_token, enabled_topic_hashes=[sha1(topic.encode()).digest() for topic in topics]))

    async def request_scoped_token(self, topic: str) -> bytes:
        topic_hash = sha1(topic.encode()).digest()
        assert self.base_token is not None
        await self.send(protocol.ScopedTokenCommand(token=self.base_token, topic=topic_hash))
        ack = await self.receive(protocol.ScopedTokenAck)
        assert ack.status == 0
        return ack.scoped_token
