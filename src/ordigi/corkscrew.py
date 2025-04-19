import base64
import http.client
import logging
import os
from pathlib import Path
from typing import Optional

from paramiko.util import ClosingContextManager

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Corkscrew(ClosingContextManager):
    """
    Wraps an HTTP-proxied socket.

    This class implements a the socket-like interface needed by the
    `.Transport` and `.Packetizer` classes. Using this class instead of a
    regular socket makes it possible to talk with route through an HTTP proxy
    in a corkscrew-like manner.

    Instances of this class may be used as context managers.
    """

    ENV_CORKSCREW_AUTH = "CORKSCREW_AUTH"
    ENV_CORKSCREW_HOST = "CORKSCREW_HOST"
    ENV_CORKSCREW_PORT = "CORKSCREW_PORT"
    FILE_CORKSCREW_AUTH = ".corkscrew-auth"

    def __init__(
        self,
        proxyhost: str,
        proxyport: int,
        desthost: str,
        destport: int,
        proxyauth: Optional[str],
    ):
        self.proxyhost = proxyhost
        self.proxyport = proxyport
        self.desthost = desthost
        self.destport = destport
        self.proxyauth = proxyauth
        self.timeout: int | None = None
        self._cnn: http.client.HTTPConnection | None = None

    @classmethod
    def auth(cls) -> str | None:
        # Load from env var
        if corkscrew_auth := os.environ.get(cls.ENV_CORKSCREW_AUTH):
            logger.info("Using credentials from environment")
            return corkscrew_auth

        # Load from .corkscrew-auth
        paths = [Path(os.getcwd())]
        home = os.environ.get("HOME")
        if home:
            home = Path(home)
            paths.append(home)
            paths.append(home / ".ssh")

        for p in paths:
            filepath = p / cls.FILE_CORKSCREW_AUTH
            if filepath.exists() and filepath.is_file():
                logger.info("Loading credentials from %s", filepath)
                with filepath.open("r") as fp:
                    return fp.readline().strip()

        return None

    @classmethod
    def from_env(cls, desthost: str, destport: int):
        proxyhost = os.environ.get(cls.ENV_CORKSCREW_HOST)
        if not proxyhost:
            raise ValueError(f"{cls.ENV_CORKSCREW_HOST} is not set")

        proxyport = int(os.environ.get(cls.ENV_CORKSCREW_PORT, 3128))

        return cls(
            proxyhost,
            proxyport,
            desthost,
            destport,
            cls.auth(),
        )

    @property
    def name(self) -> str:
        return "corkscrew"

    def connect(self):
        # Use http.client library to connect to http proxy and authorize.
        self._cnn = http.client.HTTPConnection(
            self.proxyhost, self.proxyport, timeout=5
        )

        headers = {}
        if self.proxyauth:
            headers = {
                "Proxy-Authorization": f"Basic {base64.b64encode(self.proxyauth.encode()).decode().rstrip()}"
            }

        self._cnn.set_tunnel(self.desthost, self.destport, headers=headers)
        self._cnn.connect()

        # Route data through the connected socket.
        csock = self._cnn.sock
        csock.setblocking(False)
        csock.settimeout(self.timeout)

    def send(self, content):
        """
        Write the content received from the SSH client to the standard
        input of the forked command.

        :param str content: string to be sent to the forked command
        """
        if self._cnn is None:
            raise IOError("Not connected")
        sock = self._cnn.sock
        return sock.send(content)

    def recv(self, size):
        """
        Read from the standard output of the forked program.

        :param int size: how many chars should be read

        :return: the string of bytes read, which may be shorter than requested
        """
        if self._cnn is None:
            raise IOError("Not connected")
        sock = self._cnn.sock
        return sock.recv(size)

    def close(self):
        if self._cnn is not None:
            self._cnn.close()
            self._cnn = None

    @property
    def closed(self):
        return self._cnn is None

    @property
    def _closed(self):
        # Concession to Python 3 socket-like API
        return self.closed

    def settimeout(self, timeout):
        self.timeout = timeout
        if self._cnn is not None:
            self._cnn.sock.settimeout(timeout)
