import functools
import sys
import traceback
from typing import Callable, ParamSpec, TypeVar, cast

import click

P = ParamSpec("P")
R = TypeVar("R")


def handle_client_errors(f: Callable[P, R]) -> Callable[P, R]:
    """Handle exceptions from client calls."""

    @functools.wraps(f)
    def handle(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return f(*args, **kwargs)
        except Exception as e:
            click.secho(f"Error: {str(e)}", file=sys.stderr, fg="red")
            for frame in traceback.format_exception(e):
                click.secho(frame, file=sys.stderr, fg="red")
            sys.exit(1)

    return cast(Callable[P, R], handle)
