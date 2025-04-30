from ordigi.corkscrew import Corkscrew
from ordigi.models.ssh import PortForwardModel, SessionModel
from ordigi.session import ParamikoSession, PortForward


def port_forward_to_model(fwp: PortForward) -> PortForwardModel:
    """Convert a PortForward instance to a PortForwardModel."""
    return PortForwardModel(
        id=str(fwp),
        port=fwp.port,
        host=fwp.host,
        hostport=fwp.hostport,
        bind_address=fwp.bind_address,
        is_connected=fwp.is_connected,
        connections=[f"{host}:{port}" for host, port in fwp.connections],
    )


def session_to_model(session: ParamikoSession) -> SessionModel:
    """Convert a ParamikoSession instance to a SessionModel.

    Password values are omitted.
    """
    return SessionModel(
        id=session.name,
        remote_host=session.remote_host,
        remote_port=session.remote_port,
        remote_user=session.remote_user,
        local_key_path=session.local_key_path,
        proxy_command=(
            "corkscrew" if isinstance(session.proxy_sock, Corkscrew) else None
        ),
        enable_compression=session.enable_compression,
        port_forwards=[port_forward_to_model(fwp) for fwp in session.forwarded_ports],
        is_connected=session.is_connected,
    )
