import pytest
from pypush import apns
import asyncio
from aioapns import *
import uuid
import anyio

# @pytest.mark.asyncio
# async def test_activate():
#     global certificate, key
#     certificate, key = await apns.albert.activate()
#     assert certificate is not None
#     assert key is not None


# # @pytest.mark.asyncio
# # async def test_connect():
# #     connection = apns.connection.Connection(certificate, key)
# #     await connection.connect()
# #     assert connection.connected == True
# #     await connection.aclose()
# #     assert connection.connected == False


# @pytest.mark.asyncio
# async def test_with_block():
#     async with apns.connection.Connection(certificate, key) as connection:
#         pass
#         # assert connection.connected == True
#     # assert connection.connected == False


@pytest.mark.asyncio
async def test_more():
    apns_cert_client = APNs(
        client_cert="/Users/jjtech/Downloads/dev.jjtech.pypush.tests.pem",
        use_sandbox=True,
    )
    request = NotificationRequest(
        device_token="496945db19bed82226c24900daa0ee71fda92c315a956c1044fc49d0f1fda394",
        message={
            "aps": {
                "alert": "test",
                "badge": 1,
            }
        },
        notification_id=str(uuid.uuid4()),
        time_to_live=3,
        push_type=PushType.ALERT,
    )
    await apns_cert_client.send_notification(request)

    await anyio.sleep_forever()
