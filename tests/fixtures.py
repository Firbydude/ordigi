import socket
import threading
import time
from pathlib import Path
from typing import Generator, Tuple

import paramiko
import paramiko.common
import pytest


class SSHServer(paramiko.ServerInterface):
    """Simple SSH server for testing."""

    def __init__(self, server_key_path: Path):
        self.event = threading.Event()
        # Load server key
        self.server_key = paramiko.RSAKey.from_private_key_file(str(server_key_path))
        self.authorized_keys = {}

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.common.OPEN_SUCCEEDED
        if kind == "direct-tcpip":
            return paramiko.common.OPEN_SUCCEEDED
        return paramiko.common.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        # Accept password 'test_password' for user 'test_user'
        if username == "test_user" and password == "test_password":
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        # Check if the key is in authorized_keys
        if username in self.authorized_keys:
            if key.get_fingerprint() in [
                k.get_fingerprint() for k in self.authorized_keys[username]
            ]:
                return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def add_authorized_key(self, username: str, key: paramiko.PKey) -> None:
        """Add a public key to the authorized keys for a user."""
        if username not in self.authorized_keys:
            self.authorized_keys[username] = []
        self.authorized_keys[username].append(key)

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(
        self, channel: paramiko.Channel, command: str
    ) -> bool:
        channel.send(f"Executed: {command}\r\n".encode())
        channel.send_exit_status(0)
        channel.close()
        return True

    def check_channel_forward_agent_request(self, channel: paramiko.Channel) -> bool:
        return False


class SSHServerThread(threading.Thread):
    """Thread to run the SSH server."""

    def __init__(self, server_key_path: Path):
        super().__init__()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.server_socket.bind(("127.0.0.1", 0))  # Bind to a random port
        self.server_socket.listen(5)
        self.port = self.server_socket.getsockname()[1]
        self.running = True
        self.daemon = True

        self.server = SSHServer(server_key_path)

    def run(self) -> None:
        """Run the SSH server."""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client, addr = self.server_socket.accept()
                self._handle_connection(client)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Server error: {e}")
                break

    def _handle_connection(self, client_socket: socket.socket) -> None:
        """Handle a new SSH connection."""
        # Create a new transport for the connection
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(self.server.server_key)

        try:
            transport.start_server(server=self.server)

            # Wait for authentication
            chan = transport.accept(5.0)
            if chan is None:
                print("No channel established")
                return

            # Client has authenticated, now set up port forwarding if needed
            while transport.is_active() and self.running:
                time.sleep(0.1)
        except Exception as e:
            print(f"SSH server error: {e}")
        finally:
            if transport.is_active():
                transport.close()

    def stop(self) -> None:
        """Stop the SSH server."""
        self.running = False
        self.server_socket.close()


def generate_test_keys(tmp_path: Path) -> Tuple[Path, Path, Path]:
    """Generate SSH keys for testing."""
    # Generate server key
    server_key_path = tmp_path / "server_key"
    client_key_path = tmp_path / "client_key"
    client_pub_key_path = tmp_path / "client_key.pub"

    # Generate server key
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(server_key_path))

    # Generate client key
    client_key = paramiko.RSAKey.generate(2048)
    client_key.write_private_key_file(str(client_key_path))

    # Write client public key
    with open(client_pub_key_path, "w") as f:
        f.write(f"{client_key.get_name()} {client_key.get_base64()}")

    return server_key_path, client_key_path, client_pub_key_path


@pytest.fixture
def ssh_server(tmp_path: Path) -> Generator[Tuple[int, Path], None, None]:
    """
    Pytest fixture that creates and runs an SSH server for testing.

    Returns:
        Tuple[int, Path]: A tuple containing the port number on which the server is
                          listening and the path to the client key file.
    """
    # Generate keys
    server_key_path, client_key_path, client_pub_key_path = generate_test_keys(tmp_path)

    # Create and start the server
    server_thread = SSHServerThread(server_key_path)

    # Add the client public key to authorized keys
    client_key = paramiko.RSAKey.from_private_key_file(str(client_key_path))
    server_thread.server.add_authorized_key("test_user", client_key)

    # Start the server
    server_thread.start()

    # Give the server a moment to start up
    time.sleep(0.5)

    try:
        # Return the port and client key path
        yield server_thread.port, client_key_path
    finally:
        # Stop the server
        server_thread.stop()
        server_thread.join(timeout=10.0)
