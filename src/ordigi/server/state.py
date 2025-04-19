from __future__ import annotations

from ordigi.session import ParamikoSession


class OrdigiServer:
    _instance: OrdigiServer | None = None

    sessions: dict[str, ParamikoSession]

    def __init__(self) -> None:
        self.sessions = {}

    @classmethod
    def instance(cls) -> OrdigiServer:
        if cls._instance is None:
            cls._instance = OrdigiServer()

        return cls._instance
