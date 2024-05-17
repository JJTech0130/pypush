import logging
from contextlib import asynccontextmanager
from typing import Generic, TypeVar

import anyio
from anyio.abc import ObjectSendStream

T = TypeVar("T")


class BroadcastStream(Generic[T]):
    def __init__(self):
        self.streams: list[ObjectSendStream[T]] = []

    async def broadcast(self, packet):
        for stream in self.streams:
            await stream.send(packet)

    @asynccontextmanager
    async def open_stream(self):
        send, recv = anyio.create_memory_object_stream[T]()
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
