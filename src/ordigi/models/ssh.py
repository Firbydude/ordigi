import ipaddress
import re
from typing import Annotated, Literal, Optional

from pydantic import AfterValidator, BaseModel, Field


def validate_host(value: str | None) -> str | None:
    if value is None:
        return value

    if value == "localhost":
        return value

    try:
        ipaddress.ip_address(value)
        return value
    except:
        pass

    m = re.match(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]",
        value,
    )

    if m is None:
        raise ValueError(f"Not a valid IP address or hostname: {value}")

    return value


def validate_port(value: int | None) -> int | None:
    if value is None:
        return value

    if value < 0 or value > (2**16 - 1):
        raise ValueError(f"Outside port range {value}")

    return value


class PortForwardModel(BaseModel):
    id: str | None = Field(
        default=None,
        title="Session-unique ID",
        examples=["localhost:9001:192.168.1.10:9001"],
    )
    port: Annotated[int, AfterValidator(validate_port)] = Field(
        title="Local port to bind",
        examples=[9001],
    )
    host: Annotated[str, AfterValidator(validate_host)] = Field(
        title="Remote host to forward to",
        examples=["192.168.1.10", "hostname.domain"],
    )
    hostport: Annotated[int, AfterValidator(validate_port)] = Field(
        title="Remote port to forward to",
        examples=[9001],
    )
    bind_address: str | None = Field(
        default="0.0.0.0",
        title="Local address to bind to",
        examples=["localhost", "0.0.0.0", "127.0.0.1"],
    )
    is_connected: bool = Field(
        default=False,
        title="Whether the local port is actively listening for connections",
    )
    connections: list[str] = Field(
        default_factory=list,
        title="Active client connections",
        examples=["127.0.0.1:6543"],
    )


class SessionModel(BaseModel):
    id: Optional[str] = Field(
        default=None,
        title="Session-unique ID",
        examples=["lab"],
    )
    remote_user: str = Field(
        title="Username for SSH authentication",
        examples=["root", "user"],
    )
    remote_host: Annotated[str, AfterValidator(validate_host)] = Field(
        title="Remote SSH server hostname or IP address",
        examples=["192.168.1.10", "hostname.domain"],
    )
    remote_port: Annotated[int, AfterValidator(validate_port)] = Field(
        default=22,
        title="Remote SSH server port",
        examples=[22],
    )
    remote_password: Optional[str] = Field(
        default=None,
        title="Password for SSH authentication",
        examples=["correct horse battery staple"],
    )
    local_key_path: Optional[str] = Field(
        default=None,
        title="Path to local SSH private key file",
        examples=["/home/user/.ssh/id_rsa"],
    )
    local_key_passphrase: Optional[str] = Field(
        default=None,
        title="Passphrase for encrypted SSH private key",
        description="Not required for keys available through the local SSH agent",
        examples=["correct horse battery staple"],
    )
    proxy_command: Literal["corkscrew"] | None = Field(
        default=None,
        title="SSH proxy command to use for connection",
        examples=["corkscrew"],
    )
    port_forwards: list[PortForwardModel] = Field(
        default_factory=list,
        title="List of port forwarding configurations",
    )
    is_connected: bool = Field(
        default=False,
        title="Whether the SSH session is currently connected",
    )
