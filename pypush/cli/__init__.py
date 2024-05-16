import typer
from typing_extensions import Annotated
import logging
from rich.logging import RichHandler

logging.basicConfig(level=logging.DEBUG, handlers=[RichHandler()], format="%(message)s")

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
    from . import apnsproxy

    apnsproxy.main(attach)


@app.command()
def client(
    topic: Annotated[str, typer.Argument(help="app topic to listen on")],
    sandbox: Annotated[
        bool, typer.Option("--sandbox/--production", help="APNs courier to use")
    ] = True,
):
    """
    Connect to the APNs courier and listen for app notifications on the given topic
    """
    typer.echo("Running APNs client")
    raise NotImplementedError("Not implemented yet")


def main():
    app()


if __name__ == "__main__":
    main()
