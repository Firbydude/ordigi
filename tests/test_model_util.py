from unittest.mock import MagicMock, patch

from ordigi.corkscrew import Corkscrew
from ordigi.models.ssh import PortForwardModel, SessionModel
from ordigi.server.util import port_forward_to_model, session_to_model
from ordigi.session import ParamikoSession, PortForward


class TestPortForwardToModel:
    def test_basic_conversion(self):
        """Test basic conversion from PortForward to PortForwardModel."""
        # Create a mock PortForward
        port_forward = MagicMock(spec=PortForward)
        port_forward.__str__.return_value = "localhost:8080:example.com:80"
        port_forward.port = 8080
        port_forward.host = "example.com"
        port_forward.hostport = 80
        port_forward.bind_address = "localhost"
        port_forward.is_connected = True
        port_forward.connections = [("192.168.1.2", 54321), ("192.168.1.3", 65432)]

        # Convert to model
        model = port_forward_to_model(port_forward)

        # Verify the model is correct
        assert isinstance(model, PortForwardModel)
        assert model.id == "localhost:8080:example.com:80"
        assert model.port == 8080
        assert model.host == "example.com"
        assert model.hostport == 80
        assert model.bind_address == "localhost"
        assert model.is_connected == True
        assert model.connections == ["192.168.1.2:54321", "192.168.1.3:65432"]

    def test_empty_connections(self):
        """Test conversion with empty connections list."""
        port_forward = MagicMock(spec=PortForward)
        port_forward.__str__.return_value = "0.0.0.0:9000:internal.host:22"
        port_forward.port = 9000
        port_forward.host = "internal.host"
        port_forward.hostport = 22
        port_forward.bind_address = "0.0.0.0"
        port_forward.is_connected = False
        port_forward.connections = []

        model = port_forward_to_model(port_forward)

        assert model.id == "0.0.0.0:9000:internal.host:22"
        assert model.is_connected == False
        assert model.connections == []


class TestSessionToModel:
    def test_basic_session_conversion(self):
        """Test basic conversion from ParamikoSession to SessionModel."""
        # Create a mock ParamikoSession
        session = MagicMock(spec=ParamikoSession)
        session.name = "test-session"
        session.remote_host = "ssh.example.com"
        session.remote_port = 22
        session.remote_user = "testuser"
        session.local_key_path = "/home/user/.ssh/id_rsa"
        session.proxy_sock = None
        session.is_connected = True
        session.enable_compression = True

        # Create mock port forwards
        port_forward1 = MagicMock(spec=PortForward)
        port_forward1.__str__.return_value = "localhost:8080:db.internal:3306"
        port_forward1.port = 8080
        port_forward1.host = "db.internal"
        port_forward1.hostport = 3306
        port_forward1.bind_address = "localhost"
        port_forward1.is_connected = True
        port_forward1.connections = [("127.0.0.1", 43210)]

        port_forward2 = MagicMock(spec=PortForward)
        port_forward2.__str__.return_value = "0.0.0.0:9090:web.internal:80"
        port_forward2.port = 9090
        port_forward2.host = "web.internal"
        port_forward2.hostport = 80
        port_forward2.bind_address = "0.0.0.0"
        port_forward2.is_connected = False
        port_forward2.connections = []

        session.forwarded_ports = [port_forward1, port_forward2]

        # Mock the port_forward_to_model function to return expected models
        with patch(
            "ordigi.server.util.port_forward_to_model"
        ) as mock_port_forward_to_model:
            # Set up the return values for the mocked function
            mock_port_forward_to_model.side_effect = [
                PortForwardModel(
                    id="localhost:8080:db.internal:3306",
                    port=8080,
                    host="db.internal",
                    hostport=3306,
                    bind_address="localhost",
                    is_connected=True,
                    connections=["127.0.0.1:43210"],
                ),
                PortForwardModel(
                    id="0.0.0.0:9090:web.internal:80",
                    port=9090,
                    host="web.internal",
                    hostport=80,
                    bind_address="0.0.0.0",
                    is_connected=False,
                    connections=[],
                ),
            ]

            # Convert to model
            model = session_to_model(session)

            # Verify the calls to port_forward_to_model
            assert mock_port_forward_to_model.call_count == 2
            mock_port_forward_to_model.assert_any_call(port_forward1)
            mock_port_forward_to_model.assert_any_call(port_forward2)

        # Verify the model is correct
        assert isinstance(model, SessionModel)
        assert model.id == "test-session"
        assert model.remote_host == "ssh.example.com"
        assert model.remote_port == 22
        assert model.remote_user == "testuser"
        assert model.local_key_path == "/home/user/.ssh/id_rsa"
        assert model.proxy_command is None
        assert model.is_connected == True
        assert model.enable_compression == True
        assert len(model.port_forwards) == 2

    def test_session_with_corkscrew_proxy(self):
        """Test conversion with Corkscrew proxy."""
        session = MagicMock(spec=ParamikoSession)
        session.name = "proxy-session"
        session.remote_host = "restricted.example.com"
        session.remote_port = 2222
        session.remote_user = "proxyuser"
        session.local_key_path = None
        session.is_connected = False
        session.forwarded_ports = []
        session.enable_compression = False

        # Mock a Corkscrew proxy
        corkscrew_mock = MagicMock(spec=Corkscrew)
        session.proxy_sock = corkscrew_mock

        model = session_to_model(session)

        assert model.id == "proxy-session"
        assert model.proxy_command == "corkscrew"
        assert model.port_forwards == []

    def test_session_with_other_proxy(self):
        """Test conversion with a non-Corkscrew proxy."""
        session = MagicMock(spec=ParamikoSession)
        session.name = "other-proxy"
        session.remote_host = "another.example.com"
        session.remote_port = 22
        session.remote_user = "otheruser"
        session.local_key_path = None
        session.is_connected = True
        session.enable_compression = False
        session.forwarded_ports = []

        # Mock a non-Corkscrew proxy
        other_proxy_mock = MagicMock()  # Not a Corkscrew instance
        session.proxy_sock = other_proxy_mock

        model = session_to_model(session)

        assert model.id == "other-proxy"
        assert model.proxy_command is None  # Should be None for non-Corkscrew proxies
