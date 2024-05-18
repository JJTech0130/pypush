import pytest
from pypush import apns
import asyncio

# from aioapns import *
import uuid
import anyio

# from pypush.apns import _util
# from pypush.apns import albert, lifecycle, protocol
from pypush import apns

import logging
from rich.logging import RichHandler

logging.basicConfig(level=logging.DEBUG, handlers=[RichHandler()], format="%(message)s")


@pytest.mark.asyncio
async def test_activate():
    global certificate, key
    certificate, key = await apns.activate()
    assert certificate is not None
    assert key is not None


@pytest.mark.asyncio
async def test_lifecycle_2():
    async with apns.create_apns_connection(
        certificate, key, courier="localhost"
    ) as connection:
        pass

@pytest.mark.asyncio
async def test_shorthand():
    async with apns.create_apns_connection(
        *await apns.activate(), courier="localhost"
    ) as connection:
        pass

@pytest.mark.asyncio
async def test_scoped_token():
    async with apns.create_apns_connection(
        *await apns.activate(), courier="1-courier.sandbox.push.apple.com"
    ) as connection:
        token = await connection.request_scoped_token("dev.jjtech.pypush.tests")
        logging.warning(f"Got token: {token.hex()}")
        await connection.filter(["dev.jjtech.pypush.tests"])
        logging.warning(f"waiting on topic 'dev.jjtech.pypush.tests'")
        async with connection._broadcast.open_stream() as stream:
            async for command in stream:
                if isinstance(command, apns.protocol.SendMessageCommand) and command.topic == "dev.jjtech.pypush.tests" and command.token == token:
                    logging.warning(f"Got message: {command.payload.decode()}")
                    break
