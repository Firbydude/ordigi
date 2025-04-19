from pathlib import Path

import click

from ordigi.cli.util import handle_client_errors


@click.command("put-file", short_help="Copy files to a remote host")
@click.argument("session_id", required=True)
@click.argument(
    "local_path", type=click.Path(exists=True, path_type=Path), required=True
)
@click.argument("remote_path", type=click.Path(path_type=Path), required=True)
@click.pass_context
@handle_client_errors
def put_file(ctx, session_id: str, local_path: Path, remote_path: Path):
    """Copy files to a remote host."""
    client = ctx.obj["shade_client"]

    client.put_file(session_id, local_path, remote_path)


@click.command("get-file", short_help="Copy files from a remote host")
@click.argument("session_id", required=True)
@click.argument("remote_path", type=click.Path(path_type=Path), required=True)
@click.argument(
    "local_path",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    required=True,
)
@click.pass_context
@handle_client_errors
def get_file(ctx, session_id: str, remote_path: Path, local_path: Path):
    """Copy files to a remote host."""
    client = ctx.obj["shade_client"]

    client.get_file(session_id, remote_path, local_path)
