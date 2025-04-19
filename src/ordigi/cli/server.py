import asyncio
import io

import click
import dotenv
import uvicorn
import yaml


@click.group()
def server():
    pass


@server.command()
@click.option("--port", "-p", type=int, default=8090)
def up(port: int):
    """Start the Ordigi server."""
    # Defer this import so the whole API isn't loading on every CLI invocation.
    dotenv.load_dotenv()

    from ordigi.server import app

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="info")
    server = uvicorn.Server(config)
    return asyncio.run(server.serve())


@server.command()
@click.option(
    "-o",
    "--output",
    type=click.File("w"),
    default="-",
    show_default=True,
    help="Output file.",
)
def openapi(output: io.FileIO):
    """Output the OpenAPI schema."""
    # Defer this import so the whole API isn't loading on every CLI invocation.
    from ordigi.server import app

    schema = app.openapi()
    yaml.dump(schema, output)
