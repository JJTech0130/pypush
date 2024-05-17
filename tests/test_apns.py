import pytest
from pypush import apns
import asyncio
from aioapns import *
import uuid
import anyio
from pypush.apns.new import _util, lifecycle, protocol
from pypush.apns import albert

import logging
from rich.logging import RichHandler

logging.basicConfig(level=logging.DEBUG, handlers=[RichHandler()], format="%(message)s")


@pytest.mark.asyncio
async def test_activate():
    global certificate, key
    certificate, key = await albert.activate()
    assert certificate is not None
    assert key is not None

@pytest.mark.asyncio
async def test_lifecycle_2():
    async with lifecycle.create_apns_connection(certificate, key) as connection:
        await connection.receive(protocol.ConnectAck) # Just wait until the initial connection is established. Don't do this in real code plz.