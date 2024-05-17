import pytest
from pypush import apns
import asyncio
from aioapns import *
import uuid
import anyio
from pypush.apns.new import _util, lifecycle
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


# @pytest.mark.asyncio
# async def test_more():
#     apns_cert_client = APNs(
#         client_cert="/Users/jjtech/Downloads/dev.jjtech.pypush.tests.pem",
#         use_sandbox=True,
#     )
#     request = NotificationRequest(
#         device_token="496945db19bed82226c24900daa0ee71fda92c315a956c1044fc49d0f1fda394",
#         message={
#             "aps": {
#                 "alert": "test",
#                 "badge": 1,
#             }
#         },
#         notification_id=str(uuid.uuid4()),
#         time_to_live=3,
#         push_type=PushType.ALERT,
#     )
#     await apns_cert_client.send_notification(request)

#     await anyio.sleep_forever()


# @pytest.mark.asyncio
# async def test_lifecycle():
#     async with anyio.create_task_group() as tg:
#         connection = lifecycle.Connection(tg, certificate, key)
#         async with connection._broadcast.open_stream() as stream:
#             pass
#             #async for command in stream:
#             #    print(command)

@pytest.mark.asyncio
async def test_lifecycle_2():
    async with lifecycle.create_apns_connection(certificate, key) as connection:
        await anyio.sleep(10)
        pass