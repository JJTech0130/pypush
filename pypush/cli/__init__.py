import contextlib
import logging
from asyncio import CancelledError

import anyio
import typer
from rich.logging import RichHandler
from typing_extensions import Annotated

from pypush import apns

from . import proxy as _proxy

logging.basicConfig(level=logging.INFO, handlers=[RichHandler()], format="%(message)s")

app = typer.Typer()


@app.command()
def proxy(
    attach: Annotated[
        bool, typer.Option(help="Use Frida to attach to the running `apsd`")
    ] = True,
):
    """
    Proxy APNs traffic between the local machine and the APNs courier

    Attach requires SIP to be disabled and to be running as root
    """
    with contextlib.suppress(CancelledError):
        _proxy.main(attach)


@app.command()
def notifications(
    topic: Annotated[str, typer.Argument(help="app topic to listen on")],
    sandbox: Annotated[
        bool, typer.Option("--sandbox/--production", help="APNs courier to use")
    ] = True,
):
    """
    Connect to the APNs courier and listen for app notifications on the given topic
    """
    logging.getLogger("httpx").setLevel(logging.WARNING)
    with contextlib.suppress(CancelledError):
        anyio.run(notifications_async, topic, sandbox)


async def notifications_async(topic: str, sandbox: bool):
    async with apns.create_apns_connection(
        *await apns.activate(),
        courier="1-courier.sandbox.push.apple.com"
        if sandbox
        else "1-courier.push.apple.com",
    ) as connection:
        token = await connection.mint_scoped_token(topic)

        async with connection.notification_stream(topic, token) as stream:
            logging.info(
                f"Listening for notifications on topic {topic} ({'sandbox' if sandbox else 'production'})"
            )
            logging.info(f"Token: {token.hex()}")

            async for notification in stream:
                await connection.ack(notification)
                logging.info(notification.payload.decode())


def main():
    app()


if __name__ == "__main__":
    main()
