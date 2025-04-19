import click

import ordigi.logging
from ordigi.cli.server import server
from ordigi.cli.ssh import ssh_cli


@click.group()
@click.option("--verbose", "-v", count=True, help="Increase logging level.")
@click.pass_context
def cli(ctx: click.Context, verbose: int):
    ctx.ensure_object(dict)

    ordigi.logging.configure(verbose)


cli.add_command(server)
cli.add_command(ssh_cli)
