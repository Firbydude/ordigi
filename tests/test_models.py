import pytest
from pydantic import ValidationError

from ordigi.models.ssh import (  # Replace 'your_module' with the actual module name
    PortForwardModel, SessionModel, validate_host, validate_port)


class TestValidators:
    """Tests for the validator functions"""

    def test_validate_host_none(self):
        """Test that None is accepted as a valid host"""
        assert validate_host(None) is None

    def test_validate_host_localhost(self):
        """Test that 'localhost' is accepted as a valid host"""
        assert validate_host("localhost") == "localhost"

    def test_validate_host_ipv4(self):
        """Test that valid IPv4 addresses are accepted"""
        assert validate_host("127.0.0.1") == "127.0.0.1"
        assert validate_host("192.168.1.10") == "192.168.1.10"
        assert validate_host("8.8.8.8") == "8.8.8.8"

    def test_validate_host_ipv6(self):
        """Test that valid IPv6 addresses are accepted"""
        assert validate_host("::1") == "::1"
        assert validate_host("2001:db8::1") == "2001:db8::1"

    def test_validate_host_domain(self):
        """Test that valid domain names are accepted"""
        assert validate_host("example.com") == "example.com"
        assert validate_host("sub.domain.example.com") == "sub.domain.example.com"
        assert validate_host("a-valid-domain.co.uk") == "a-valid-domain.co.uk"

    def test_validate_host_invalid(self):
        """Test that invalid hostnames raise a ValueError"""
        with pytest.raises(ValueError):
            validate_host("invalid..domain")

        with pytest.raises(ValueError):
            validate_host("domain with spaces.com")

        with pytest.raises(ValueError):
            validate_host("-invalid-start.com")

        with pytest.raises(ValueError):
            validate_host("no_underscores.com")

    def test_validate_port_none(self):
        """Test that None is accepted as a valid port"""
        assert validate_port(None) is None

    def test_validate_port_valid(self):
        """Test that valid ports are accepted"""
        assert validate_port(0) == 0
        assert validate_port(1) == 1
        assert validate_port(80) == 80
        assert validate_port(8080) == 8080
        assert validate_port(65535) == 65535

    def test_validate_port_invalid(self):
        """Test that port numbers outside the valid range raise ValueError"""
        # Note: The validation function has a bug - it should be:
        # if value < 0 or value > (2**16 - 1):
        # Current implementation will not catch these invalid values
        # The tests below would fail with the current implementation

        with pytest.raises(ValueError):
            validate_port(-1)

        with pytest.raises(ValueError):
            validate_port(65536)


class TestPortForwardModel:
    """Tests for the PortForwardModel"""

    def test_valid_model_complete(self):
        """Test creating a valid PortForwardModel with all fields"""
        model = PortForwardModel(
            id="localhost:9001:192.168.1.10:9001",
            port=9001,
            host="192.168.1.10",
            hostport=9001,
            bind_address="localhost",
            is_connected=True,
            connections=["127.0.0.1:6543"],
        )

        assert model.id == "localhost:9001:192.168.1.10:9001"
        assert model.port == 9001
        assert model.host == "192.168.1.10"
        assert model.hostport == 9001
        assert model.bind_address == "localhost"
        assert model.is_connected is True
        assert model.connections == ["127.0.0.1:6543"]

    def test_valid_model_minimal(self):
        """Test creating a valid PortForwardModel with only required fields"""
        model = PortForwardModel(
            port=8080,
            host="example.com",
            hostport=80,
        )

        assert model.id is None
        assert model.port == 8080
        assert model.host == "example.com"
        assert model.hostport == 80
        assert model.bind_address == "0.0.0.0"  # Default value
        assert model.is_connected is False  # Default value
        assert model.connections == []  # Default value

    def test_invalid_port(self):
        """Test validation error for invalid port"""
        # This requires the validate_port function to be fixed
        with pytest.raises(ValidationError):
            PortForwardModel(
                port=-1,  # Invalid port
                host="example.com",
                hostport=80,
            )

    def test_invalid_hostport(self):
        """Test validation error for invalid hostport"""
        # This requires the validate_port function to be fixed
        with pytest.raises(ValidationError):
            PortForwardModel(
                port=8080,
                host="example.com",
                hostport=65536,  # Invalid port
            )

    def test_invalid_host(self):
        """Test validation error for invalid host"""
        with pytest.raises(ValidationError):
            PortForwardModel(
                port=8080,
                host="invalid..host",  # Invalid host
                hostport=80,
            )


class TestSessionModel:
    """Tests for the SessionModel"""

    def test_valid_model_complete(self):
        """Test creating a valid SessionModel with all fields"""
        port_forward = PortForwardModel(
            id="test-forward",
            port=8080,
            host="192.168.1.10",
            hostport=80,
        )

        model = SessionModel(
            id="lab",
            remote_user="root",
            remote_host="example.com",
            remote_port=2222,
            remote_password="correct horse battery staple",
            local_key_path="/home/user/.ssh/id_rsa",
            local_key_passphrase="secure passphrase",
            proxy_command="corkscrew",
            port_forwards=[port_forward],
            is_connected=True,
        )

        assert model.id == "lab"
        assert model.remote_user == "root"
        assert model.remote_host == "example.com"
        assert model.remote_port == 2222
        assert model.remote_password == "correct horse battery staple"
        assert model.local_key_path == "/home/user/.ssh/id_rsa"
        assert model.local_key_passphrase == "secure passphrase"
        assert model.proxy_command == "corkscrew"
        assert len(model.port_forwards) == 1
        assert model.port_forwards[0].id == "test-forward"
        assert model.is_connected is True

    def test_valid_model_minimal(self):
        """Test creating a valid SessionModel with only required fields"""
        model = SessionModel(
            remote_user="user",
            remote_host="example.com",
        )

        assert model.id is None
        assert model.remote_user == "user"
        assert model.remote_host == "example.com"
        assert model.remote_port == 22  # Default value
        assert model.remote_password is None  # Default value
        assert model.local_key_path is None  # Default value
        assert model.local_key_passphrase is None  # Default value
        assert model.proxy_command is None  # Default value
        assert model.port_forwards == []  # Default value
        assert model.is_connected is False  # Default value

    def test_invalid_remote_host(self):
        """Test validation error for invalid remote_host"""
        with pytest.raises(ValidationError):
            SessionModel(
                remote_user="user",
                remote_host="invalid..host",  # Invalid host
            )

    def test_invalid_remote_port(self):
        """Test validation error for invalid remote_port"""
        # This requires the validate_port function to be fixed
        with pytest.raises(ValidationError):
            SessionModel(
                remote_user="user",
                remote_host="example.com",
                remote_port=70000,  # Invalid port
            )

    def test_invalid_proxy_command(self):
        """Test validation error for invalid proxy_command"""
        with pytest.raises(ValidationError):
            SessionModel(
                remote_user="user",
                remote_host="example.com",
                # Not a valid option in Literal
                proxy_command="invalid_command",  # type: ignore
            )

    def test_nested_port_forwards_validation(self):
        """Test validation of nested PortForward models"""
        # Creating an invalid port forward
        with pytest.raises(ValidationError):
            SessionModel(
                remote_user="user",
                remote_host="example.com",
                port_forwards=[
                    PortForwardModel(
                        port=8080,
                        host="invalid..host",  # Invalid host
                        hostport=80,
                    )
                ],
            )
