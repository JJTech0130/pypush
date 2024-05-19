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
        await connection.receive(
            apns.protocol.ConnectAck
        )  # Just wait until the initial connection is established. Don't do this in real code plz.


@pytest.mark.asyncio
async def test_shorthand():
    async with apns.create_apns_connection(
        *await apns.activate(), courier="localhost"
    ) as connection:
        await connection.receive(apns.protocol.ConnectAck)
