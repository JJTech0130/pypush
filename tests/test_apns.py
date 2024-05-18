import logging
import uuid
from pathlib import Path

import httpx
import pytest
from rich.logging import RichHandler

from pypush import apns

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


ASSETS_DIR = Path(__file__).parent / "assets"


async def send_test_notification(device_token, payload=b"hello, world"):
    async with httpx.AsyncClient(
        cert=str(ASSETS_DIR / "dev.jjtech.pypush.tests.pem"), http2=True
    ) as client:
        # Use the certificate and key from above
        response = await client.post(
            f"https://api.sandbox.push.apple.com/3/device/{device_token}",
            content=payload,
            headers={
                "apns-topic": "dev.jjtech.pypush.tests",
                "apns-push-type": "alert",
                "apns-priority": "10",
            },
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_scoped_token():
    async with apns.create_apns_connection(
        *await apns.activate(), courier="1-courier.sandbox.push.apple.com"
    ) as connection:

        token = await connection.mint_scoped_token("dev.jjtech.pypush.tests")

        async with connection._filter(["dev.jjtech.pypush.tests"]):
            test_message = f"test-message-{uuid.uuid4().hex}"

            # Must use a receive_stream because the notification might arrive before the HTTP response
            async with connection.receive_stream(
                apns.protocol.SendMessageCommand
            ) as stream:
                await send_test_notification(token.hex(), test_message.encode())
                async for command in stream:
                    if command.payload == test_message.encode():
                        break
