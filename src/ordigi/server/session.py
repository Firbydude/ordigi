import asyncio
import logging
import os
from pathlib import Path

from fastapi import (APIRouter, Depends, HTTPException, UploadFile, WebSocket,
                     WebSocketDisconnect, status)
from fastapi.responses import StreamingResponse
from fastapi.websockets import WebSocketState
from paramiko import Channel

from ordigi.corkscrew import Corkscrew
from ordigi.models.ssh import PortForwardModel, SessionModel
from ordigi.server.state import OrdigiServer
from ordigi.server.util import port_forward_to_model, session_to_model
from ordigi.session import ParamikoSession

logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/sessions",
    tags=["sessions"],
    responses={404: {"description": "Not found"}},
)


@router.post("/", status_code=status.HTTP_201_CREATED)
async def session_post(
    session: SessionModel, ordigi: OrdigiServer = Depends(OrdigiServer.instance)
) -> SessionModel:
    """
    Create a new SSH session. The session will be managed by the server. This endpoint
    returns immediately without waiting for the connection to be established.
    """
    session_id = session.id
    if session_id is None:
        # Generate a session ID if one is not provided.
        session_id = (
            f"{session.remote_user}@{session.remote_host}:{session.remote_port}"
        )

    if session_id in ordigi.sessions:
        raise HTTPException(422, f"ID '{session_id} is in use")

    if session.port_forwards:
        raise HTTPException(422, "Cannot forward ports when creating session.")

    proxy_command = None
    if session.proxy_command == "corkscrew":
        proxy_command = Corkscrew.from_env(
            session.remote_host,
            session.remote_port,
        )

    ssh_session = ParamikoSession(
        session_id,
        session.remote_user,
        session.remote_host,
        session.remote_port,
        session.remote_password,
        session.local_key_path,
        session.local_key_passphrase,
        proxy_command,
        session.enable_compression,
    )

    ordigi.sessions[session_id] = ssh_session

    ssh_session.connect()

    return session_to_model(ssh_session)


@router.get("/")
async def session_get_collection(
    ordigi: OrdigiServer = Depends(OrdigiServer.instance),
) -> list[SessionModel]:
    """
    Get all active SSH sessions.
    """
    return [session_to_model(s) for s in ordigi.sessions.values()]


@router.get("/{session_id}")
async def session_get(
    session_id: str, ordigi: OrdigiServer = Depends(OrdigiServer.instance)
) -> SessionModel:
    """
    Get an active SSH session.
    """
    if session_id in ordigi.sessions:
        return session_to_model(ordigi.sessions[session_id])

    raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def session_delete(
    session_id: str, ordigi: OrdigiServer = Depends(OrdigiServer.instance)
):
    """
    Delete an active SSH session. All channels using the session will be terminated, including
    active port forwards and TTY sessions.
    """
    if session_id in ordigi.sessions:
        await ordigi.sessions[session_id].disconnect()
        ordigi.sessions.pop(session_id)
        return

    raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")


@router.post("/{session_id}/forwarded_ports/", status_code=status.HTTP_201_CREATED)
async def fwp_post(
    session_id: str,
    fwpm: PortForwardModel,
    ordigi: OrdigiServer = Depends(OrdigiServer.instance),
) -> PortForwardModel:
    """
    Begin forwarding a port over an active SSH session. The forwarded port will be available on
    the local host at the specified port. This endpoint returns immediately without waiting for the
    port forward to be established.
    """
    if session_id in ordigi.sessions:
        session = ordigi.sessions[session_id]
        try:
            fwp = session.forward_local(
                fwpm.port, fwpm.host, fwpm.hostport, fwpm.bind_address
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        return port_forward_to_model(fwp)

    raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")


@router.get("/{session_id}/forwarded_ports/")
async def fwp_get_collection(
    session_id: str, ordigi: OrdigiServer = Depends(OrdigiServer.instance)
) -> list[PortForwardModel]:
    """
    Get forwarded ports for an active SSH session.
    """
    if session_id in ordigi.sessions:
        return [
            port_forward_to_model(fwp)
            for fwp in ordigi.sessions[session_id].forwarded_ports
        ]

    raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")


@router.get("/{session_id}/forwarded_ports/{fwp_id}")
async def fwp_get(
    session_id: str, fwp_id: str, ordigi: OrdigiServer = Depends(OrdigiServer.instance)
) -> PortForwardModel:
    """
    Get a forwarded port for an active SSH session.
    """
    if session_id in ordigi.sessions:
        session = ordigi.sessions[session_id]
        for fwp in session.forwarded_ports:
            if fwp_id == str(fwp):
                return port_forward_to_model(fwp)

        raise HTTPException(
            status_code=404,
            detail=f"No forwarded port {fwp_id} for session {session_id}",
        )

    raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")


@router.delete(
    "/{session_id}/forwarded_ports/{fwp_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def fwp_delete(
    session_id: str, fwp_id: str, ordigi: OrdigiServer = Depends(OrdigiServer.instance)
):
    """
    Stop forwarding a port for an active SSH session.
    """
    if session_id in ordigi.sessions:
        session = ordigi.sessions[session_id]
        for fwp in session.forwarded_ports:
            if fwp_id == str(fwp):
                session.close_forward(fwp)
                return

        raise HTTPException(
            status_code=404,
            detail=f"No forwarded port {fwp_id} for session {session_id}",
        )

    raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")


@router.websocket("/{session_id}/shell")
async def shell(
    session_id: str,
    ws: WebSocket,
    ordigi: OrdigiServer = Depends(OrdigiServer.instance),
):
    """
    Forward a shell to the client.
    """

    async def from_ws(ws: WebSocket, channel: Channel):
        try:
            while data := await ws.receive_bytes():
                await asyncio.get_running_loop().run_in_executor(
                    None, channel.sendall, data
                )
        except WebSocketDisconnect:
            pass
        except asyncio.CancelledError:
            pass
        finally:
            logger.debug("closing ws->channel")

    async def from_channel(channel: Channel, ws: WebSocket):
        try:
            while data := await asyncio.get_running_loop().run_in_executor(
                None, chan.recv, 4096
            ):
                await ws.send_bytes(data)
        except asyncio.CancelledError:
            pass
        finally:
            logger.debug("closing channel->ws")

    async def log_exceptions(fut: asyncio.Future):
        try:
            await fut
        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception("Exception in shell task")

    if session_id in ordigi.sessions:
        session = ordigi.sessions[session_id]

        await ws.accept()

        chan = session.client.invoke_shell()

        t_from_ws = asyncio.create_task(from_ws(ws, chan))
        t_from_channel = asyncio.create_task(from_channel(chan, ws))

        try:
            await asyncio.wait(
                [t_from_ws, t_from_channel],
                return_when=asyncio.FIRST_COMPLETED,
            )
        except WebSocketDisconnect:
            logger.debug("Websocket disconnected")
        except Exception:
            logger.exception("Shell terminated with exception")
        finally:
            t_from_ws.cancel()
            t_from_channel.cancel()

            try:
                chan.close()
            except:
                logger.exception("Failed to close channel")

            if ws.client_state == WebSocketState.CONNECTED:
                try:
                    await ws.close()
                except:
                    logger.exception("Failed to close websocket")

            await asyncio.gather(
                log_exceptions(t_from_ws), log_exceptions(t_from_channel)
            )

        return

    raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")


@router.put("/sessions/{session_id}/put_file", status_code=status.HTTP_204_NO_CONTENT)
async def put_file(
    session_id: str,
    remote_path: Path,
    f: UploadFile,
    ordigi: OrdigiServer = Depends(OrdigiServer.instance),
):
    """
    Upload a file to the remote host.

    Args:
        session_id (str): The ID of the session to upload the file to.
        remote_path (Path): The path to upload the file to.
        f (UploadFile): The file to upload.
    """
    if session_id not in ordigi.sessions:
        raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")

    session = ordigi.sessions[session_id]
    await session.put_file(f.file, remote_path)


@router.get("/sessions/{session_id}/get_file")
async def get_file(
    session_id: str,
    remote_path: Path,
    ordigi: OrdigiServer = Depends(OrdigiServer.instance),
):
    """
    Download a file from the remote host.

    Args:
        session_id (str): The ID of the session to download the file from.
        remote_path (Path): The path to download the file from.
    """
    if session_id not in ordigi.sessions:
        raise HTTPException(status_code=404, detail=f"No session with ID {session_id}")

    session = ordigi.sessions[session_id]

    async def stream():
        # This probably only works on unix-like systems.
        # Create r/w pipes.
        rp, wp = os.pipe()

        # Set read pipe non-blocking. Leave write pipe blocking since it's a dumb
        # loop on a thread.
        os.set_blocking(rp, False)

        # Open pipes as files.
        with open(rp, "rb") as rf, open(wp, "wb") as wf:
            # Connect the read pipe to a stream reader on the event loop.
            loop = asyncio.get_running_loop()
            reader = asyncio.StreamReader(loop=loop)
            await loop.connect_read_pipe(asyncio.Protocol, rf)

            # Create a task to write the file contents to the write pipe.
            t = asyncio.create_task(session.get_file(wf, remote_path))

            # Yield from the stream reader (read pipe) until exhausted.
            while data := await reader.read(1024):
                yield data

            # Wait for the write task to complete.
            await t

    # Yield the file contents as a stream.
    return StreamingResponse(stream(), media_type="application/octet-stream")
