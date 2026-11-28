from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._channels: dict[str, set[WebSocket]] = {}

    async def connect(self, channel: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._channels.setdefault(channel, set()).add(websocket)

    def disconnect(self, channel: str, websocket: WebSocket) -> None:
        connections = self._channels.get(channel)
        if connections is None:
            return
        connections.discard(websocket)
        if not connections:
            self._channels.pop(channel, None)

    async def broadcast(self, channel: str, payload: dict[str, Any]) -> None:
        connections = tuple(self._channels.get(channel, set()))
        for websocket in connections:
            try:
                await websocket.send_json(payload)
            except Exception:
                self.disconnect(channel, websocket)

    def connection_count(self, channel: str) -> int:
        return len(self._channels.get(channel, set()))


connection_manager = ConnectionManager()
