import pytest
from pypush import apns

@pytest.mark.asyncio
async def test_activate():
    await apns.albert.activate()
    print("Albert is activated!")

def test():
    print("Albert is testing!")