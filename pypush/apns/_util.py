import logging
from contextlib import asynccontextmanager
from typing import Generic, TypeVar

import anyio
from anyio.abc import ObjectSendStream

T = TypeVar("T")


class BroadcastStream(Generic[T]):
    def __init__(self, backlog: int = 50):
        self.streams: list[ObjectSendStream[T]] = []
        self.backlog: list[T] = []
        self._backlog_size = backlog

    async def broadcast(self, packet):
        logging.debug(f"Broadcasting {packet} to {len(self.streams)} streams")
        for stream in self.streams:
            try:
                await stream.send(packet)
            except anyio.BrokenResourceError:
                logging.error("Broken resource error")
                # self.streams.remove(stream)
        # If we have a backlog, add the packet to it
        if len(self.backlog) >= self._backlog_size:
            self.backlog.pop(0)
        self.backlog.append(packet)

    @asynccontextmanager
    async def open_stream(self, backlog: bool = True):
        # 1000 seems like a reasonable number, if more than 1000 messages come in before someone deals with them it will
        #  start stalling the APNs connection itself
        send, recv = anyio.create_memory_object_stream[T](max_buffer_size=1000)
        if backlog:
            for packet in self.backlog:
                await send.send(packet)
        self.streams.append(send)
        async with recv:
            yield recv
            self.streams.remove(send)
            await send.aclose()


def exponential_backoff(f):
    async def wrapper(*args, **kwargs):
        backoff = 1
        while True:
            try:
                return await f(*args, **kwargs)
            except Exception as e:
                logging.warning(
                    f"Error in {f.__name__}: {e}, retrying in {backoff} seconds"
                )
                await anyio.sleep(backoff)
                backoff *= 2

    return wrapper
