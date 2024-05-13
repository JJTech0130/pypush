import pytest
from pypush import apns
import asyncio

@pytest.mark.asyncio
async def test_activate():
    global certificate, key
    certificate, key = await apns.albert.activate()
    assert certificate is not None
    assert key is not None


@pytest.mark.asyncio
async def test_connect():
    connection = apns.connection.Connection(certificate, key)
    await connection.connect()
    assert connection.connected == True
    await connection.aclose()
    assert connection.connected == False
