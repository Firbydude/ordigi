
# About

Ordigi is a management interface and orchestrator for SSH connections built on Paramiko. It is intended to provide to facilitate workflows that may have many connections or tunnels involved.

The project name is inspired by Paramiko, which is a combination of the esperanto words **para**noja (paranoid) and a**miko** (friend). Ordigi is the esperanto word meaning: arrange, put in order, tidy. 

## Benefits

- No need for sshpass
- Embedded python implementation of [corkscrew](https://github.com/bryanpkc/corkscrew) for tunnelling connections through an HTTP proxy.
- Simplified port forwarding over existing SSH connections.
- Persistence of connections & tunnels with automatic reconnection attempts.
- No need to manually manage ssh processes.
- Named connections.
- Provides a documented REST interface with full typing via Pydantic v2 models.

## Disclaimer

1. This project is experimental. It is *not* intended to offer the same security guarantees as SSH or the underlying Paramiko implementation. Use at your own risk.
2. The full capabilities of Paramiko are not exposed at this time.
3. All connections go through a single Python async server. If you are sending or receiving large amounts of data over multiple connections there may be performance degredation.

# BUILDING

This project depends on `uv` for building. `uv build` will create a distribution wheel in the dist/ folder. 

```sh
uv venv && uv sync && uv build
```

# INSTALLATION

Wheels can be obtained and pip installed from the github releases.

# Usage

Ordigi has two main components: a stateful HTTP server and a CLI client.

## Server

Running `ordigi server up` will start the HTTP server listening on 127.0.0.1:8090. The port can be overridden with `-p <port>`.

```sh
Usage: ordigi server [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  openapi  Output the OpenAPI schema.
  up       Start the Ordigi server.
```

## CLI

### Sessions

SSH connections are tracked as sessions. New sessions are created with `ordigi ssh connect`. Most commands require a session ID. A session ID can be provided to `connect` or a default (`user@hostname:port`) will be used. Active sessions can be listed with `ordigi ssh ls`.

### Port Forwarding

Forarding local ports is supported over an active session. Similar to SSH -L option, format is: `[bind_address:]port:host:hostport`. Active port forwards for a session can be listed wih `ordigi ssh forwards <session_id>`.

### Embedding

The CLI is built using `click`. The CLI is entirely composable and can be embedded in other applications using click easily. Simply import `ssh_cli` and add it to your command group.

```python
import click
from ordigi.cli.ssh import ssh_cli

@click.group()
@click.option("--verbose", "-v", count=True, help="Increase logging level.")
@click.pass_context
def cli(ctx: click.Context, verbose: int):
    ctx.ensure_object(dict)
    ordigi.logging.configure(verbose)

cli.add_command(ssh_cli)

if __name__ == "__main__":
    cli()
```

## HTTP Proxy Tunnelling

A Python port of [corkscrew](https://github.com/bryanpkc/corkscrew) is embedded in the server. It can be used for connections by setting `proxy_command` to `corkscrew` in the API or in the CLI via `connect --proxy corkscrew ...`. Corkscrew can be configured with HTTP basic auth. All configuration is done on the server and can be set through one of the following mechanisms in order of precedence:
1. `CORKSCREW_AUTH` env variable
2. ./.corkscrew-auth
3. ~/.corkscrew-auth
4. ~/.ssh/.corkscrew-auth

Auth variable or file contents are `username:password`.

Arbitrary `proxy_command` settings are not supported at this time.
