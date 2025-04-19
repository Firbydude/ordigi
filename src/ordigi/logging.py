import logging

import click

LOG_NAME = "ordigi"


class ClickLogHandler(logging.Handler):
    """Technicolor logging of the future."""

    def __init__(self, filter=None):
        super().__init__()
        self._filter = filter or (lambda x: True)

    def filter(self, record: logging.LogRecord) -> bool:
        return self._filter(record)

    def emit(self, record: logging.LogRecord) -> None:
        if record.levelno >= logging.ERROR:
            click.secho(self.format(record), fg="red")
        elif record.levelno >= logging.WARN:
            click.secho(self.format(record), fg="yellow")
        elif record.levelno >= logging.INFO:
            click.secho(self.format(record), fg="bright_white")
        else:
            click.secho(self.format(record), fg="magenta")


def configure(verbosity: int):
    """Configure the logging system.

    Args:
        verbosity: The number of times the user has requested verbose output.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    root_handler = ClickLogHandler(lambda x: not x.name.startswith(LOG_NAME))
    root_handler.setFormatter(logging.Formatter("[%(name)s] %(message)s"))
    root_handler.setLevel(logging.WARNING)
    root_logger.addHandler(root_handler)

    handler = logging.FileHandler(f"{LOG_NAME}.log")
    handler.setFormatter(logging.Formatter("[%(name)s] %(message)s"))
    handler.setLevel(logging.DEBUG)
    root_logger.addHandler(handler)

    logger = logging.getLogger(LOG_NAME)
    logger.setLevel(logging.DEBUG)

    handler = ClickLogHandler(lambda x: x.name.startswith(LOG_NAME))
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    handler.setLevel(logging.WARNING)

    if verbosity:
        handler.setLevel(logging.INFO)
    if verbosity > 1:
        handler.setLevel(logging.INFO)
        logger.debug("Logging debug messages")
    if verbosity > 2:
        root_handler.setLevel(level=logging.INFO)
    if verbosity > 3:
        root_handler.setLevel(logging.DEBUG)
        root_logger.debug("Logging debug messages")
