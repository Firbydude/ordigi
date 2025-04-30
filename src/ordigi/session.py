import asyncio
import functools
import logging
from asyncio import Task
from ipaddress import IPv4Address
from pathlib import Path
from typing import IO, Dict, Iterator, Optional, Protocol, Tuple, Union

import paramiko
import paramiko.auth_strategy
import paramiko.config
import paramiko.pkey
from paramiko.channel import Channel

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class ProxySock(Protocol):
    def connect(self) -> None: ...

    def send(self, content) -> int: ...

    def recv(self, size) -> bytes | None: ...

    def close(self): ...

    @property
    def closed(self) -> bool: ...

    @property
    def _closed(self) -> bool: ...

    def settimeout(self, timeout): ...


class Auth(paramiko.auth_strategy.AuthStrategy):
    def __init__(
        self,
        ssh_config: paramiko.SSHConfig,
        remote_user: str,
        remote_password: Optional[str] = None,
        local_key_path: Optional[str] = None,
        local_key_passphrase: Optional[str] = None,
    ) -> None:
        super().__init__(ssh_config)
        self.remote_user = remote_user
        self.remote_password = remote_password
        self.local_key_path = local_key_path
        self.local_key_passphrase = local_key_passphrase

    def get_sources(self) -> Iterator[paramiko.auth_strategy.AuthSource]:
        if self.remote_password is not None:
            logger.info("Trying password")
            yield paramiko.auth_strategy.Password(
                self.remote_user, lambda: str(self.remote_password)
            )

        if self.local_key_path:
            logger.info("Trying local key")
            password = (
                self.local_key_passphrase.encode()
                if self.local_key_passphrase
                else None
            )
            pkey = paramiko.pkey.PKey.from_path(self.local_key_path, password)
            yield paramiko.auth_strategy.OnDiskPrivateKey(
                self.remote_user, "python-config", Path(self.local_key_path), pkey
            )

        for key in paramiko.Agent().get_keys():
            logger.info("Trying agent key %s", key.name)
            yield paramiko.auth_strategy.InMemoryPrivateKey(self.remote_user, key)


# TODO handle IPv6
class PortForward:
    """
    A forwarded port over an SSH connection.

    Conforms to behavior specified for ssh -L.

    Specifies that the given port on the local (client) host is to be forwarded to the given host
    and port on the remote side. This works by allocating a socket to listen to port on the local
    side, optionally bound to the specified bind_address. Whenever a connection is made to this
    port, the connection is forwarded over the secure channel, and a connection is made to host port
    hostport from the remote machine.

    Args:
        port (int): The local port to forward.
        host (str): The remote host to forward to.
        hostport (int): The remote port to forward to.
        bind_address (str, optional): The local address to bind to. Defaults to "0.0.0.0".
    """

    def __init__(
        self,
        port: int,
        host: str,
        hostport: int,
        bind_address: str | None = None,
    ) -> None:
        self.port = port
        self.host = host
        self.hostport = hostport
        self.bind_address = bind_address or "0.0.0.0"

        self._is_connected = False
        self._cond_connected = asyncio.Condition()

        # Listening server on local forward.
        self._server: Optional[asyncio.Server] = None

        # SSH transport
        self._transport: Optional[paramiko.Transport] = None

        # One per client connected through the forward.
        self._forward_tasks: Dict[Tuple[str, int], Task] = {}

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    @property
    def transport(self) -> paramiko.Transport:
        if self._transport is None:
            raise RuntimeError("Transport is none")

        return self._transport

    @property
    def connections(self) -> list[tuple[str, int]]:
        return list(self._forward_tasks.keys())

    def __eq__(self, other):
        if isinstance(other, PortForward):
            return (
                self.port == other.port
                and self.host == other.host
                and self.hostport == other.hostport
                and self.bind_address == other.bind_address
            )

        return False

    def __hash__(self) -> int:
        return hash((self.port, self.host, self.hostport, self.bind_address))

    def __str__(self) -> str:
        return f"{self.bind_address}:{self.port}:{self.host}:{self.hostport}"

    def _start_client_task(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        client_addr = writer.get_extra_info("peername")

        # Reject
        if client_addr in self._forward_tasks:
            logger.warning(
                "Task already exists for client address %s:%d",
                client_addr[0],
                client_addr[1],
            )
            return

        logger.info(f"Accepted connection from {client_addr}")

        # Handle each client connection in a separate task
        self._forward_tasks[client_addr] = task = asyncio.create_task(
            self._handle_client_connection_asyncio(
                client_addr, self.transport, reader, writer
            )
        )

        # Remove reference to task when complete.
        task.add_done_callback(lambda t: self._forward_tasks.pop(client_addr))

    async def _handle_client_connection_asyncio(
        self,
        client_addr,
        transport: paramiko.Transport,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        """Handle a client connection to the local forwarded port."""

        async def from_sock(reader: asyncio.StreamReader, channel: Channel):
            try:
                while data := await reader.read(4096):
                    await asyncio.get_running_loop().run_in_executor(
                        None, channel.sendall, data
                    )
            except asyncio.CancelledError:
                pass
            finally:
                logger.debug("closing sock->channel")

        async def from_channel(channel: Channel, writer: asyncio.StreamWriter):
            try:
                while data := await asyncio.get_running_loop().run_in_executor(
                    None, channel.recv, 4096
                ):
                    writer.write(data)
                    await writer.drain()
            except asyncio.CancelledError:
                pass
            finally:
                logger.debug("closing channel->sock")

        async def log_exceptions(fut: asyncio.Future):
            try:
                await fut
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception("Exception in tunnel task")

        # Create a direct channel to the destination
        if not transport.active:
            logger.error("SSH transport not available")
            return

        # Use run_in_executor for the blocking channel open
        dest_addr = (self.host, self.hostport)
        channel = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: transport.open_channel("direct-tcpip", dest_addr, client_addr),
        )

        if channel is None:
            logger.error("Failed to create direct-tcpip channel")
            return

        try:
            # Start two tasks to forward data in both directions
            forward_client_to_channel = asyncio.create_task(from_sock(reader, channel))
            forward_channel_to_client = asyncio.create_task(
                from_channel(channel, writer)
            )

            # Wait for a forwarding tasks to complete
            await asyncio.wait(
                [forward_client_to_channel, forward_channel_to_client],
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            logger.info("Client forward cancelled %s", client_addr)
        finally:
            forward_client_to_channel.cancel()
            forward_channel_to_client.cancel()

            reader.feed_eof()
            writer.close()

            if not channel.closed:
                channel.close()

            await asyncio.gather(
                log_exceptions(forward_client_to_channel),
                log_exceptions(forward_channel_to_client),
            )

    async def connect(self, transport: paramiko.Transport) -> None:
        """Establish and maintains a forwarded port over an SSH tunnel.

        Args:
            transport: Paramiko transport over the SSH connection to create
                channels for client connections.
        """
        if self._server is not None:
            raise RuntimeError("Tunnel is already connected")

        self._transport = transport

        while True:
            try:
                # Set up the local server socket for forwarding
                self._server = await asyncio.start_server(
                    self._start_client_task, self.bind_address, self.port
                )
                await self._server.start_serving()

                logger.info(
                    f"Forwarding {self.bind_address}:{self.port} to {self.host}:{self.hostport}"
                )

                # Update connection state
                async with self._cond_connected:
                    self._is_connected = True
                    self._cond_connected.notify_all()

                await self._server.wait_closed()

            except asyncio.CancelledError:
                logger.debug("SSH tunnel task cancelled")
                await self._cleanup()
                raise
            except Exception as e:
                logger.error(f"Error in SSH tunnel. Will reconnect.", exc_info=True)
                await self._cleanup()

    async def _cleanup(self) -> None:
        """Clean up resources when the tunnel is disconnected."""
        self._transport = None

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Cancel and await all forwarded connections. This will clean up opened
        # forwarding channels.
        for t in self._forward_tasks.values():
            t.cancel()
        await asyncio.gather(*self._forward_tasks.values(), return_exceptions=True)
        self._forward_tasks.clear()

        # Notify waiting coroutines
        async with self._cond_connected:
            self._is_connected = False
            self._cond_connected.notify_all()

    async def wait_for_connection(self, timeout: Optional[float] = 10.0) -> bool:
        """
        Wait for tunnel to be connected to the remote host.

        This method waits for the background task that manages the connection to establish with
        the remote host. If the connection is already established, this method returns immediately.
        If the timeout is exceeded before the connection is established, raises TimeoutError.
        If the connection is disconnected while waiting, returns False.

        Args:
            timeout (float | None, optional): The maximum number of seconds to wait for the connection
                to establish. If None, this method waits indefinitely. Defaults to 10.0.

        Returns:
            bool: True if the connection is established with the remote host within the specified
                timeout, False otherwise.
        """
        async with self._cond_connected:
            if self._is_connected:
                return True

            await asyncio.wait_for(self._cond_connected.wait(), timeout)

            return self._is_connected


class ParamikoSession:
    """Wrapper around Paramiko Connection object with added functionality.

    Args:
        name (str): The name of the session.
        remote_user (str | None, optional): The remote user to connect as. Defaults to None.
        remote_host (str | IPv4Address): The remote host to connect to.
        remote_port (int | None): The remote port to connect to.
        remote_password (str | None, optional): The remote password to use for authentication. Defaults to None.
        local_key_path (str | None, optional): Path to the local SSH key file. Defaults to None.
        local_key_passphrase (str | None, optional): The passphrase for the local SSH key. Defaults to None.
        proxy_sock (ProxySock | None, optional): The proxy socket to use for the connection. Defaults to None.
        enable_compression (bool, optional): Whether to enable compression. Defaults to False.
    """

    def __init__(
        self,
        name: str,
        remote_user: str,
        remote_host: Union[str, IPv4Address] = "localhost",
        remote_port: Optional[int] = None,
        remote_password: Optional[str] = None,
        local_key_path: Optional[str] = None,
        local_key_passphrase: Optional[str] = None,
        proxy_sock: Optional[ProxySock] = None,
        enable_compression: bool = False,
    ):
        self.name = name
        self.remote_host = str(remote_host)
        self.remote_port = remote_port or 22
        self.proxy_sock = proxy_sock
        self.enable_compression = enable_compression

        self._task: Optional[Task] = None
        self._cond_connected = asyncio.Condition()
        self._is_connected = False
        self._client: Optional[paramiko.SSHClient] = None
        self._forwarded_ports: dict[PortForward, Task | None] = {}

        config = paramiko.config.SSHConfig()
        self._auth = Auth(
            config, remote_user, remote_password, local_key_path, local_key_passphrase
        )

    @property
    def remote_user(self) -> str:
        return self._auth.remote_user

    @property
    def remote_password(self) -> str | None:
        return self._auth.remote_password

    @property
    def local_key_path(self) -> str | None:
        return self._auth.local_key_path

    @property
    def local_key_passphrase(self) -> str | None:
        return self._auth.local_key_passphrase

    @property
    def client(self) -> paramiko.SSHClient:
        if not self.is_connected or self._client is None:
            raise ValueError("Not connected")

        return self._client

    @property
    def transport(self) -> paramiko.Transport:
        transport = self.client.get_transport()
        if transport is None:
            raise ValueError("Transport not available")

        return transport

    @property
    def forwarded_ports(self) -> list[PortForward]:
        """
        Returns a list of all forwarded ports.
        """
        return list(self._forwarded_ports.keys())

    def close_forward(self, fwp: PortForward):
        """
        Closes a forwarded port.
        """
        if fwp not in self._forwarded_ports:
            raise ValueError(f"{fwp} is not forwarded")

        t = self._forwarded_ports[fwp]
        if t is not None and not t.cancelled() and not t.done():
            t.cancel()

        self._forwarded_ports.pop(fwp)

    def forward_local(
        self, port: int, host: str, hostport: int, bind_address: str | None = None
    ) -> PortForward:
        """
        Forwards a local port to a remote port on a remote host, similar to the `ssh -L` command.

        Specifies that the given port on the local (client) host is to be forwarded
        to the given host and port on the remote side. This works by allocating a
        socket to listen to port on the local side, optionally bound to the specified
        bind_address. Whenever a connection is made to this port, the connection is
        forwarded over the secure channel, and a connection is made to host:hostport
        from the remote machine.

        Args:
            port (int): The local port to bind the tunnel to.
            host (str): The host to connect to on the remote end of the tunnel.
            hostport (int): The port to connect to on the remote end of the tunnel.
            bind_address (str | None, optional): The local host to bind the tunnel to.
                If not provided, the tunnel will be bound to all local interfaces.
                Defaults to None.

        Returns:
            PortForward: Created port forward.

        Raises:
            ValueError: If the specified forwarding entry already exists.
        """
        fwp = PortForward(port, host, hostport, bind_address)
        if fwp in self._forwarded_ports:
            raise ValueError("Port forward exists for %s", fwp)

        # Create a new port forward. The main task will manage the connection.
        self._forwarded_ports[fwp] = None

        return fwp

    @property
    def is_connected(self) -> bool:
        """
        Check if the tunnel is currently connected to the remote host.

        Returns:
            bool: True if the tunnel is connected, False otherwise.
        """
        return (
            self._task is not None
            and not self._task.done()
            and self._is_connected
            and self._client is not None
            and self._client.get_transport() is not None
            and self._client.get_transport().is_active()  # type: ignore
        )

    def connect(self) -> None:
        """
        Establish an SSH connection to the remote host.

        This method starts a background task that runs in the event loop. The task
        establishes the SSH connection and sets up port forwarding. The method
        does not wait for the connection to be established before returning.

        Raises:
            RuntimeError: If the background task is already active.
        """
        if self._task is not None and not self._task.done():
            raise RuntimeError("Tunnel is already connected")
        self._task = asyncio.create_task(self._connect())

    async def _connect(self) -> None:
        """Background task that establishes and maintains the SSH connection."""

        while True:
            try:
                # Create a new SSH client
                self._client = paramiko.SSHClient()
                self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                # Add proxy socket if provided
                if self.proxy_sock:
                    self.proxy_sock.connect()

                logger.info(
                    f"Connecting to SSH tunnel: {self.remote_user}@{self.remote_host}"
                )

                # Use run_in_executor to perform the blocking connect operation
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self._client.connect(  # type: ignore
                        hostname=self.remote_host,
                        port=self.remote_port,
                        timeout=10.0,
                        auth_strategy=self._auth,
                        sock=self.proxy_sock,  # type: ignore
                        compress=self.enable_compression,
                    ),
                )

                # Update connection state
                async with self._cond_connected:
                    self._is_connected = True
                    self._cond_connected.notify_all()

                # Manage tunnels
                while True:
                    await asyncio.sleep(1)

                    for fwp in self._forwarded_ports:
                        fwt = self._forwarded_ports[fwp]

                        # Handle task completion.
                        if fwt is not None and fwt.done() and not fwt.cancelled():
                            if e := fwt.exception():
                                logger.exception(
                                    "Forward task %s raised exception", fwt, exc_info=e
                                )
                            if result := fwt.result():
                                logger.debug(
                                    "Forward task %s returned result: %s", fwt, result
                                )

                        # Create new forward connection task.
                        if fwt is None or fwt.done():
                            transport = self._client.get_transport()
                            if transport is None:
                                logger.warning("Unable to get SSH transport.")
                                continue
                            fwt = asyncio.create_task(fwp.connect(transport))
                            self._forwarded_ports[fwp] = fwt

            except asyncio.CancelledError:
                logger.debug("SSH connection task cancelled")
                await self._cleanup()
                raise
            except Exception as e:
                logger.error(f"Error in SSH connection: {e}", exc_info=True)
                await self._cleanup()

                # Wait before reconnecting
                await asyncio.sleep(1)

    async def _cleanup(self) -> None:
        """Clean up resources when the tunnel is disconnected."""
        # Close all active forwarding channels
        for t in self._forwarded_ports.values():
            if t is not None:
                t.cancel()
        await asyncio.gather(
            *(t for t in self._forwarded_ports.values() if t is not None),
            return_exceptions=True,
        )
        self._forwarded_ports.clear()

        # Close the SSH client
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

        # Notify waiting coroutines
        async with self._cond_connected:
            self._is_connected = False
            self._cond_connected.notify_all()

    async def disconnect(self) -> None:
        """
        Disconnect the SSH connection from the remote host.

        This method cancels the background task that manages the connection and waits for it to complete.
        If the connection is not currently active, this method does nothing.
        """
        if self._task:
            if not self._task.cancelled():
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None

    async def wait_for_connection(self, timeout: Optional[float] = 10.0) -> bool:
        """
        Wait for SSH to be connected to the remote host.

        This method waits for the background task that manages the connection to establish with
        the remote host. If the connection is already established, this method returns immediately.
        If the timeout is exceeded before the connection is established, raises TimeoutError.
        If the connection is disconnected while waiting, returns False.

        Args:
            timeout (float | None, optional): The maximum number of seconds to wait for the connection
                to establish. If None, this method waits indefinitely. Defaults to 10.0.

        Returns:
            bool: True if the connection is established with the remote host within the specified
                timeout, False otherwise.
        """
        if self._task is None or self._task.done():
            raise RuntimeError("Connection is not active")

        async with self._cond_connected:
            if self.is_connected:
                return True

            await asyncio.wait_for(self._cond_connected.wait(), timeout)

            return self.is_connected

    async def put_file(self, fin: IO[bytes], remote_path: Path):
        """
        Uploads a file to the remote host.

        Args:
            fin (IO[bytes]): The file-like object to upload.
            remote_path (Path): The path to the file on the remote host.
        """
        with self.client.open_sftp() as sftp:
            return await asyncio.get_running_loop().run_in_executor(
                None,
                functools.partial(sftp.putfo, fin, str(remote_path)),
            )

    async def get_file(self, fout: IO[bytes], remote_path: Path):
        """
        Downloads a file from the remote host.

        Args:
            fout (IO[bytes]): The file-like object to download to.
            remote_path (Path): The path to the file on the remote
        """
        with self.client.open_sftp() as sftp:
            return await asyncio.get_running_loop().run_in_executor(
                None,
                functools.partial(sftp.getfo, str(remote_path), fout),
            )
