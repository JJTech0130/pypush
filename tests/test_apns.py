import pytest
from pypush import apns
import asyncio


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
    import pypush.apns.new.transport

    conn = await pypush.apns.new.transport.create_apns_connection()
    await conn.send(
        pypush.apns.new.transport.Packet(
            pypush.apns.new.transport.Packet.Type.Connect,
            [pypush.apns.new.transport.Packet.Field(1, b"hello")],
        )
    )
    print(await conn.receive())
