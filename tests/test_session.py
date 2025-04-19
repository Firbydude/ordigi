import pytest

from ordigi.session import ParamikoSession


@pytest.mark.asyncio
async def test_paramiko_session_connect(ssh_server):
    """Test connecting to the SSH server."""
    port, client_key_path = ssh_server

    # Create a session
    session = ParamikoSession(
        name="test_session",
        remote_user="test_user",
        remote_host="127.0.0.1",
        remote_port=port,
        local_key_path=str(client_key_path),
    )

    # Connect to the server
    session.connect()

    # Wait for the connection to be established
    connected = await session.wait_for_connection(timeout=5.0)
    assert connected

    # Disconnect
    await session.disconnect()


@pytest.mark.asyncio
async def test_paramiko_session_password_auth(ssh_server):
    """Test connecting to the SSH server with password authentication."""
    port, _ = ssh_server

    # Create a session with password authentication
    session = ParamikoSession(
        name="test_session",
        remote_user="test_user",
        remote_host="127.0.0.1",
        remote_port=port,
        remote_password="test_password",
    )

    # Connect to the server
    session.connect()

    # Wait for the connection to be established
    connected = await session.wait_for_connection(timeout=5.0)
    assert connected

    # Disconnect
    await session.disconnect()


@pytest.mark.asyncio
async def test_port_forwarding(ssh_server):
    """Test port forwarding functionality."""
    port, client_key_path = ssh_server

    # Create a session
    session = ParamikoSession(
        name="test_session",
        remote_user="test_user",
        remote_host="127.0.0.1",
        remote_port=port,
        local_key_path=str(client_key_path),
    )

    # Connect to the server
    session.connect()

    # Wait for the connection to be established
    connected = await session.wait_for_connection(timeout=5.0)
    assert connected

    # Set up port forwarding
    forward = session.forward_local(
        port=0,  # Use port 0 to get a random available port
        host="localhost",
        hostport=8080,
        bind_address="127.0.0.1",
    )

    # Wait for the port forwarding to be established
    connected = await forward.wait_for_connection(5.0)
    assert connected

    # Check that the port forward is in the list of forwarded ports
    assert forward in session.forwarded_ports

    # Close the port forwarding
    session.close_forward(forward)

    # Disconnect
    await session.disconnect()
