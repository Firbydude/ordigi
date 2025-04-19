#!/usr/bin/env python3

import asyncio
import os
import sys
from typing import Literal, Optional, cast

import click
from tabulate import tabulate

from ordigi.cli.scp import get_file, put_file
from ordigi.cli.shell import shell
from ordigi.cli.util import handle_client_errors
from ordigi.client import OrdigiClient
from ordigi.models.ssh import PortForwardModel, SessionModel


def get_base_url():
    """Get the base URL from environment variable or use default."""
    return os.environ.get("ORDIGI_URL", "http://localhost:8090")


@click.group(name="ssh")
@click.pass_context
def ssh_cli(ctx):
    """Ordigi SSH client CLI for managing SSH sessions and port forwards."""
    ctx.ensure_object(dict)
    ctx.obj["ordigi_client"] = OrdigiClient(get_base_url())


@ssh_cli.command("connect", short_help="Create a new SSH session")
@click.argument("remote", required=True)
@click.option("-p", "--port", default=22, help="Port to connect to on the remote host")
@click.option("--password", is_flag=True, help="Prompt for password")
@click.option("-i", "--identity", "key_path", help="Path to private key file")
@click.option("--passphrase", is_flag=True, help="Prompt for key passphrase")
@click.option(
    "--proxy",
    type=click.Choice(["corkscrew"]),
    help="Proxy command (only 'corkscrew' supported)",
    default=None,
)
@click.option("--session-id", help="Custom session ID (optional)")
@click.pass_context
@handle_client_errors
def connect(
    ctx,
    remote: str,
    port: int,
    password: bool,
    key_path: Optional[str],
    passphrase: bool,
    proxy: Optional[Literal["corkscrew"]],
    session_id: Optional[str],
):
    """
    Create a new SSH session with REMOTE being [user@]hostname.

    Similar to standard SSH client, but sessions persist on the server
    until explicitly disconnected.
    """
    client = ctx.obj["ordigi_client"]

    # Parse remote into user and host
    if "@" in remote:
        user, host = remote.split("@", 1)
    else:
        user = os.environ.get("USER", "")
        host = remote

    # Handle password input if requested
    remote_password = None
    if password:
        remote_password = click.prompt("Password", hide_input=True, show_default=False)

    # Handle key passphrase if requested
    key_passphrase = None
    if passphrase and key_path:
        key_passphrase = click.prompt(
            "Key passphrase", hide_input=True, show_default=False
        )

    # Create session model
    session = SessionModel(
        id=session_id,
        remote_host=host,
        remote_port=port,
        remote_user=user,
        remote_password=remote_password,
        local_key_path=key_path,
        local_key_passphrase=key_passphrase,
        proxy_command=proxy,
        port_forwards=[],  # Empty initially
    )

    # Connect and display result
    result = client.connect(session)
    session_id = result.id
    click.secho(f"Connected: {session_id}", file=sys.stdout, fg="green")


@ssh_cli.command("ls", short_help="List active SSH sessions")
@click.pass_context
@handle_client_errors
def list_sessions(ctx):
    """List all active SSH sessions."""
    client: OrdigiClient = ctx.obj["ordigi_client"]
    sessions = client.get_sessions()

    if not sessions:
        click.echo("No active sessions")
        return

    # Prepare table data
    headers = ["ID", "User", "Host", "Port", "Connected", "Port Forwards"]
    table_data = []

    for session in sessions:
        fwps = ", ".join(str(fwp.id) for fwp in session.port_forwards)
        table_data.append(
            [
                session.id,
                session.remote_user,
                session.remote_host,
                session.remote_port,
                session.is_connected,
                fwps,
            ]
        )

    click.echo(tabulate(table_data, headers=headers, tablefmt="simple"))


@ssh_cli.command("info", short_help="Get information about a specific SSH session")
@click.argument("session_id", required=True)
@click.pass_context
@handle_client_errors
def session_info(ctx, session_id: str):
    """Get detailed information about a specific SSH session."""
    client = ctx.obj["ordigi_client"]
    session = client.get_session(session_id)

    # Display session details
    click.echo(f"Session ID: {session.id}")
    click.echo(
        f"Connection: {session.remote_user}@{session.remote_host}:{session.remote_port}"
    )

    # Display port forwarding information if any
    forwards = session.port_forwards
    if forwards:
        click.echo("\nPort Forwards:")
        headers = ["ID", "Local Port", "Remote Host", "Remote Port"]
        table_data = []

        for fwd in forwards:
            table_data.append(
                [
                    fwd.id,
                    fwd.port,
                    fwd.host,
                    fwd.hostport,
                ]
            )

        click.echo(tabulate(table_data, headers=headers, tablefmt="simple"))
    else:
        click.echo("\nNo active port forwards")


@ssh_cli.command("disconnect", short_help="Disconnect an SSH session")
@click.argument("session_id", required=True)
@click.pass_context
@handle_client_errors
def disconnect(ctx, session_id: str):
    """Disconnect from an active SSH session."""
    client = ctx.obj["ordigi_client"]
    client.disconnect(session_id)
    click.secho(f"Disconnected: {session_id}", file=sys.stdout, fg="green")


@ssh_cli.command("forward", short_help="Forward a local port to a remote host")
@click.argument("session_id", required=True)
@click.option(
    "-L",
    required=True,
    help="Local port forwarding spec: [bind_address:]port:host:hostport",
)
@click.pass_context
@handle_client_errors
def forward(ctx, session_id: str, l: str):
    """
    Forward a local port to a remote host via an SSH session.

    Similar to SSH -L option, format is: [bind_address:]port:host:hostport
    """
    client = ctx.obj["ordigi_client"]

    # Parse the forwarding specification
    parts = l.split(":")

    if len(parts) == 3:
        bind_address = "127.0.0.1"
        local_port, remote_host, remote_port = parts
    elif len(parts) == 4:
        bind_address, local_port, remote_host, remote_port = parts
    else:
        click.secho(
            "Invalid forwarding spec. Format: [bind_address:]port:host:hostport",
            file=sys.stderr,
            fg="red",
        )
        sys.exit(1)

    # Create port forward model
    port_forward = PortForwardModel(
        port=int(local_port),
        host=remote_host,
        hostport=int(remote_port),
        bind_address=bind_address,
        connections=[],
    )

    # Create the port forward
    result = client.forward_port(session_id, port_forward)

    # Display success message
    fwd_id = result.id
    local_port = result.port
    remote_host = result.host
    remote_port = result.hostport
    bind_address = result.bind_address

    click.secho(
        f"Port forward active: {fwd_id}\n"
        f"Local {bind_address}:{local_port} -> {remote_host}:{remote_port}",
        file=sys.stdout,
        fg="green",
    )


@ssh_cli.command("forwards", short_help="List port forwards for a session")
@click.argument("session_id", required=True)
@click.pass_context
@handle_client_errors
def list_forwards(ctx, session_id: str):
    """List all port forwards for a specific SSH session."""
    client = ctx.obj["ordigi_client"]
    forwards = client.get_forwarded_ports(session_id)

    if not forwards:
        click.echo("No active port forwards")
        return

    # Prepare table data
    headers = [
        "ID",
        "Local Address",
        "Local Port",
        "Remote Host",
        "Remote Port",
        "Connected",
        "Connections",
    ]
    table_data = []

    for fwd in forwards:
        table_data.append(
            [
                fwd.id,
                fwd.bind_address,
                fwd.port,
                fwd.host,
                fwd.hostport,
                fwd.is_connected,
                ", ".join(fwd.connections),
            ]
        )

    click.echo(tabulate(table_data, headers=headers, tablefmt="simple"))


@ssh_cli.command("forward-info", short_help="Get information about a port forward")
@click.argument("session_id", required=True)
@click.argument("forward_id", required=True)
@click.pass_context
@handle_client_errors
def forward_info(ctx, session_id: str, forward_id: str):
    """Get detailed information about a specific port forward."""
    client = ctx.obj["ordigi_client"]
    fwd = client.get_forwarded_port(session_id, forward_id)

    # Display port forward details
    click.echo(f"Forward ID: {fwd.id}")
    click.echo(f"Local: {fwd.bind_address or '127.0.0.1'}:{fwd.port}")
    click.echo(f"Remote: {fwd.host}:{fwd.hostport}")


@ssh_cli.command("close-forward", short_help="Close a port forward")
@click.argument("session_id", required=True)
@click.argument("forward_id", required=True)
@click.pass_context
@handle_client_errors
def close_forward(ctx, session_id: str, forward_id: str):
    """Close a specific port forward."""
    client = ctx.obj["ordigi_client"]
    client.close_forwarded_port(session_id, forward_id)
    click.secho(f"Closed forward: {forward_id}", file=sys.stdout, fg="green")


# Shell forwarding.
ssh_cli.add_command(shell)

ssh_cli.add_command(put_file)
ssh_cli.add_command(get_file)


if __name__ == "__main__":
    # Use asyncio.run to run the async click command
    asyncio.run(ssh_cli(_anyio_backend="asyncio"))
