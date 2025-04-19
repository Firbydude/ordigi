import asyncio
import logging
import sys
import termios
import tty

import click
from websockets import ConnectionClosedOK
from websockets.asyncio.connection import Connection

from ordigi.cli.util import handle_client_errors
from ordigi.client import OrdigiClient

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


async def forward_shell(client: OrdigiClient, session_id: str):
    """Forward a shell to the client.

    The websockets client does not support fileno() and is unusable with select().
    So its threads or this.

    Args:
        client: The OrdigiClient instance to use for the connection.
        session_id: The ID of the session to forward the shell for.
    """

    async def from_ws(ws: Connection, stdout: asyncio.StreamWriter):
        try:
            while data := await ws.recv(False):
                stdout.write(data)
                await stdout.drain()
        except ConnectionClosedOK:
            pass
        except asyncio.CancelledError:
            pass
        finally:
            logger.debug("closing ws->stdout")

    async def from_stdin(stdin: asyncio.StreamReader, ws: Connection):
        try:
            while data := await stdin.read(1024):
                # Prevent cancelling ws.send as it can result in partial data.
                await asyncio.shield(ws.send(data))
        except ConnectionClosedOK:
            pass
        except asyncio.CancelledError:
            pass
        finally:
            logger.debug("closing stdin->ws")

    async def log_exceptions(fut: asyncio.Future):
        try:
            await fut
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Exception in shell task")

    # Get asyncio stream reader and writer for stdin and stdout respectively.
    loop = asyncio.get_running_loop()
    stdin_reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(stdin_reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    writer_transport, writer_protocol = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, sys.stdout
    )
    stdout_writer = asyncio.StreamWriter(
        writer_transport, writer_protocol, stdin_reader, loop
    )

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        # Set the terminal to raw mode. This means that the terminal will not
        # perform interpret any special characters (e.g. Ctrl-C) and will
        # pass all input directly to the remote shell.
        tty.setraw(fd)

        async with await client.open_async_shell(session_id) as ws:
            click.secho("Shell opened", file=sys.stdout, fg="green")

            fws = asyncio.create_task(from_ws(ws, stdout_writer))
            fstdin = asyncio.create_task(from_stdin(stdin_reader, ws))
            try:
                # Use asyncio.wait with FIRST_COMPLETED to wait for either the
                # websocket or stdin to close.
                await asyncio.wait(
                    [fws, fstdin],
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                fws.cancel()
                fstdin.cancel()

                await ws.close()

                await asyncio.gather(
                    log_exceptions(fws),
                    log_exceptions(fstdin),
                )
    finally:
        # Restore terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


@click.command(short_help="Open a shell")
@click.argument("session_id", required=True)
@click.pass_context
@handle_client_errors
def shell(ctx, session_id: str):
    """Open a shell."""
    client = ctx.obj["ordigi_client"]

    return asyncio.run(forward_shell(client, session_id))
