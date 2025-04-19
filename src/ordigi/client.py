from pathlib import Path

import httpx
from websockets.asyncio.client import connect as async_connect
from websockets.asyncio.connection import Connection as AsyncClientConnection
from websockets.sync.client import ClientConnection, connect

from ordigi.models.ssh import PortForwardModel, SessionModel


class OrdigiClient:
    def __init__(self, base_url: str):
        self.base_url = httpx.URL(base_url)

    @property
    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.base_url)

    def connect(self, session: SessionModel) -> SessionModel:
        """Create a new SSH session.

        Args:
            session: Session model with connection details

        Returns:
            The created session model

        Raises:
            Exception: If connection fails
        """
        with self.client as client:
            response = client.post("/sessions/", json=session.model_dump())
            if response.status_code != 201:
                raise Exception(f"Failed to connect: {response.text}")
            return SessionModel.model_validate(response.json())

    def get_sessions(self) -> list[SessionModel]:
        """Get all active SSH sessions.

        Returns:
            List of active session models

        Raises:
            Exception: If request fails
        """
        with self.client as client:
            response = client.get("/sessions/")
            if response.status_code != 200:
                raise Exception(f"Failed to get sessions: {response.text}")
            return [SessionModel.model_validate(item) for item in response.json()]

    def get_session(self, session_id: str) -> SessionModel:
        """Get an active SSH session by ID.

        Args:
            session_id: The session ID

        Returns:
            The requested session model

        Raises:
            Exception: If session not found or request fails
        """
        with self.client as client:
            response = client.get(f"/sessions/{session_id}")
            if response.status_code != 200:
                if response.status_code == 404:
                    raise Exception(f"No session with ID {session_id}")
                raise Exception(f"Failed to get session: {response.text}")
            return SessionModel.model_validate(response.json())

    def disconnect(self, session_id: str) -> None:
        """Delete an active SSH session.

        Args:
            session_id: The session ID to disconnect

        Raises:
            Exception: If session not found or disconnection fails
        """
        with self.client as client:
            response = client.delete(f"/sessions/{session_id}")
            if response.status_code != 204:
                if response.status_code == 404:
                    raise Exception(f"No session with ID {session_id}")
                raise Exception(f"Failed to disconnect: {response.text}")

    def forward_port(
        self, session_id: str, port_forward: PortForwardModel
    ) -> PortForwardModel:
        """Begin forwarding a port over an active SSH session.

        Args:
            session_id: The session ID
            port_forward: Port forwarding configuration

        Returns:
            The created port forward model

        Raises:
            Exception: If session not found or port forwarding fails
        """
        with self.client as client:
            response = client.post(
                f"/sessions/{session_id}/forwarded_ports/",
                json=port_forward.model_dump(),
            )
            if response.status_code != 201:
                if response.status_code == 404:
                    raise Exception(f"No session with ID {session_id}")
                elif response.status_code == 400:
                    raise Exception(f"Invalid port forward request: {response.text}")
                raise Exception(f"Failed to port forward: {response.text}")
            return PortForwardModel.model_validate(response.json())

    def get_forwarded_ports(self, session_id: str) -> list[PortForwardModel]:
        """Get all forwarded ports for an active SSH session.

        Args:
            session_id: The session ID

        Returns:
            List of port forward models

        Raises:
            Exception: If session not found or request fails
        """
        with self.client as client:
            response = client.get(f"/sessions/{session_id}/forwarded_ports/")
            if response.status_code != 200:
                if response.status_code == 404:
                    raise Exception(f"No session with ID {session_id}")
                raise Exception(f"Failed to get forwarded ports: {response.text}")
            return [PortForwardModel.model_validate(fwp) for fwp in response.json()]

    def get_forwarded_port(self, session_id: str, fwp_id: str) -> PortForwardModel:
        """Get a specific forwarded port for an active SSH session.

        Args:
            session_id: The session ID
            fwp_id: The forwarded port ID

        Returns:
            The requested port forward model

        Raises:
            Exception: If session or forwarded port not found
        """
        with self.client as client:
            response = client.get(f"/sessions/{session_id}/forwarded_ports/{fwp_id}")
            if response.status_code != 200:
                if response.status_code == 404:
                    raise Exception(
                        f"No forwarded port {fwp_id} for session {session_id}"
                    )
                raise Exception(f"Failed to get forwarded port: {response.text}")
            return PortForwardModel.model_validate(response.json())

    def close_forwarded_port(self, session_id: str, fwp_id: str) -> None:
        """Stop forwarding a port for an active SSH session.

        Args:
            session_id: The session ID
            fwp_id: The forwarded port ID to close

        Raises:
            Exception: If session or forwarded port not found
        """
        with self.client as client:
            response = client.delete(f"/sessions/{session_id}/forwarded_ports/{fwp_id}")
            if response.status_code != 204:
                if response.status_code == 404:
                    if "No session" in response.text:
                        raise Exception(f"No session with ID {session_id}")
                    raise Exception(
                        f"No forwarded port {fwp_id} for session {session_id}"
                    )
                raise Exception(f"Failed to close forwarded port: {response.text}")

    def open_shell(self, session_id: str) -> ClientConnection:
        """Open a shell on an active SSH session.
        Args:
            session_id: The session ID
        Returns:
            A client connection to the shell
        Raises:
            Exception: If session not found
        """
        ws_url = self.base_url.copy_with(scheme="ws").join(
            f"/sessions/{session_id}/shell"
        )
        return connect(str(ws_url))

    async def open_async_shell(self, session_id: str) -> AsyncClientConnection:
        """Open a shell on an active SSH session.
        Args:
            session_id: The session ID
        Returns:
            A client connection to the shell
        Raises:
            Exception: If session not found
        """
        ws_url = self.base_url.copy_with(scheme="ws").join(
            f"/sessions/{session_id}/shell"
        )
        return await async_connect(str(ws_url))

    def put_file(self, session_id: str, local_path: Path, remote_path: Path):
        with self.client as client:
            with local_path.open("rb") as f:
                files = {"file": f}
                params = {"remote_path": str(remote_path)}
                response = client.put(
                    f"/sessions/{session_id}/put_file",
                    params=params,
                    files=files,
                )
                if response.status_code != 200:
                    raise Exception(response.json()["detail"])
                return response.json()

    def get_file(self, session_id: str, remote_path: Path, local_path: Path):
        with local_path.open("wb") as f, self.client as client:
            with client.stream(
                "GET",
                f"/sessions/{session_id}/get_file",
                params={"remote_path": str(remote_path)},
            ) as response:
                if response.status_code != 201:
                    raise Exception(response.json()["detail"])

                for data in response.iter_bytes():
                    f.write(data)
