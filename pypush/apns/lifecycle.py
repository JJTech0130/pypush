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

from . import _util, filters, protocol, transport


@asynccontextmanager
async def create_apns_connection(
    certificate: x509.Certificate,
    private_key: rsa.RSAPrivateKey,
    token: typing.Optional[bytes] = None,
    sandbox: bool = False,
    courier: typing.Optional[str] = None,
):
    async with anyio.create_task_group() as tg:
        conn = Connection(
            tg, certificate, private_key, token, sandbox, courier
        )  # Await connected for first time here, so that base token is set
        yield conn
        tg.cancel_scope.cancel()  # Cancel the task group when the context manager exits
    await (
        conn.aclose()
    )  # Make sure to close the connection after the task group is cancelled


class Connection:
    def __init__(
        self,
        task_group: TaskGroup,
        certificate: x509.Certificate,
        private_key: rsa.RSAPrivateKey,
        token: typing.Optional[bytes] = None,
        sandbox: bool = False,
        courier: typing.Optional[str] = None,
    ):
        self.certificate = certificate
        self.private_key = private_key
        self._base_token = token

        self._filters: dict[str, int] = {}  # topic -> use count

        self._connected = anyio.Event()  # Only use for base_token property

        self._conn = None
        self._tg = task_group
        self._broadcast = _util.BroadcastStream[protocol.Command]()
        self._reconnect_lock = anyio.Lock()
        self._send_lock = anyio.Lock()

        self.sandbox = sandbox
        if courier is None:
            # Pick a random courier server from 1 to 50
            courier = (
                f"{random.randint(1, 50)}-courier.push.apple.com"
                if not sandbox
                else f"{random.randint(1, 10)}-courier.sandbox.push.apple.com"
            )
        logging.debug(f"Using courier: {courier}")
        self.courier = courier

        self._tg.start_soon(self.reconnect)
        self._tg.start_soon(self._ping_task)

    @property
    async def base_token(self) -> bytes:
        if self._base_token is None:
            await self._connected.wait()
        assert self._base_token is not None
        return self._base_token

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
            await self._send(protocol.KeepAliveCommand())
            await self._receive(
                filters.cmd(protocol.KeepAliveAck), backlog=False
            )  # Explicitly disable the backlog since we don't want to receive old acks

    @_util.exponential_backoff
    async def reconnect(self):
        async with (
            self._reconnect_lock
        ):  # Prevent weird situations where multiple reconnects are happening at once
            if self._conn is not None:
                logging.warning("Closing existing connection")
                await self._conn.aclose()

            self._broadcast.backlog = []  # Clear the backlog

            conn = protocol.CommandStream(
                await transport.create_courier_connection(self.sandbox, self.courier)
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
            await conn.send(
                protocol.ConnectCommand(
                    push_token=self._base_token,
                    state=1,
                    flags=65,  # 69
                    certificate=cert,
                    nonce=nonce,
                    signature=signature,
                )
            )

            # Don't set self._conn until we've sent the connect command
            self._conn = conn

            self._tg.start_soon(self._receive_task)
            ack = await self._receive(
                filters.chain(
                    filters.cmd(protocol.ConnectAck),
                    lambda c: (
                        c
                        if (
                            c.token == self._base_token
                            if self._base_token is not None
                            else True
                        )
                        else None
                    ),
                )
            )
            logging.debug(f"Connected with ack: {ack}")
            assert ack.status == 0
            if self._base_token is None:
                self._base_token = ack.token
            else:
                assert ack.token == self._base_token
            if not self._connected.is_set():
                self._connected.set()

            await self._update_filter()

    async def aclose(self):
        if self._conn is not None:
            await self._conn.aclose()
        # Note: Will be reopened if task group is still running and ping task is still running

    T = typing.TypeVar("T")

    @asynccontextmanager
    async def _receive_stream(
        self,
        filter: filters.Filter[protocol.Command, T] = lambda c: c,
        backlog: bool = True,
    ):
        async with self._broadcast.open_stream(backlog) as stream:
            yield filters.FilteredStream(stream, filter)

    async def _receive(
        self, filter: filters.Filter[protocol.Command, T], backlog: bool = True
    ):
        async with self._receive_stream(filter, backlog) as stream:
            async for command in stream:
                return command
        raise ValueError("Did not receive expected command")

    async def _send(self, command: protocol.Command):
        try:
            async with self._send_lock:
                assert self._conn is not None
                await self._conn.send(command)
        except Exception:
            logging.warning("Error sending command, reconnecting")
            await self.reconnect()
            await self._send(command)

    async def _update_filter(self):
        await self._send(
            protocol.FilterCommand(
                token=await self.base_token,
                enabled_topic_hashes=[
                    sha1(topic.encode()).digest() for topic in self._filters
                ],
            )
        )

    @asynccontextmanager
    async def _filter(self, topics: list[str]):
        for topic in topics:
            self._filters[topic] = self._filters.get(topic, 0) + 1
        await self._update_filter()
        yield
        for topic in topics:
            self._filters[topic] -= 1
            if self._filters[topic] == 0:
                del self._filters[topic]
        await self._update_filter()

    async def mint_scoped_token(self, topic: str) -> bytes:
        topic_hash = sha1(topic.encode()).digest()
        await self._send(
            protocol.ScopedTokenCommand(token=await self.base_token, topic=topic_hash)
        )
        ack = await self._receive(filters.cmd(protocol.ScopedTokenAck))
        assert ack.status == 0
        return ack.scoped_token

    @asynccontextmanager
    async def notification_stream(
        self,
        topic: str,
        token: typing.Optional[bytes] = None,
        filter: filters.Filter[
            protocol.SendMessageCommand, protocol.SendMessageCommand
        ] = filters.ALL,
    ):
        if token is None:
            token = await self.base_token
        async with (
            self._filter([topic]),
            self._receive_stream(
                filters.chain(
                    filters.chain(
                        filters.chain(
                            filters.cmd(protocol.SendMessageCommand),
                            lambda c: c if c.token == token else None,
                        ),
                        lambda c: (c if c.topic == topic else None),
                    ),
                    filter,
                )
            ) as stream,
        ):
            yield stream

    async def ack(self, command: protocol.SendMessageCommand, status: int = 0):
        await self._send(
            protocol.SendMessageAck(status=status, token=command.token, id=command.id)
        )

    async def expect_notification(
        self,
        topic: str,
        token: typing.Optional[bytes] = None,
        filter: filters.Filter[
            protocol.SendMessageCommand, protocol.SendMessageCommand
        ] = filters.ALL,
    ) -> protocol.SendMessageCommand:
        async with self.notification_stream(topic, token, filter) as stream:
            command = await stream.receive()
            await self.ack(command)
            return command
