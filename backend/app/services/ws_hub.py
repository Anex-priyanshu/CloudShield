"""WebSocket connection manager – broadcast events to all connected clients."""
import json
import asyncio
from typing import Dict, List, Any
from fastapi import WebSocket
import logging

logger = logging.getLogger(__name__)


class WebSocketHub:
    def __init__(self):
        self._connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)
        logger.info(f"WS connected. Total: {len(self._connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
        logger.info(f"WS disconnected. Total: {len(self._connections)}")

    async def broadcast(self, message_type: str, data: Any):
        """Send a JSON message to all connected WebSocket clients."""
        payload = json.dumps({"type": message_type, "data": data}, default=str)
        dead: List[WebSocket] = []
        async with self._lock:
            connections = list(self._connections)

        for ws in connections:
            try:
                await ws.send_text(payload)
            except Exception as e:
                logger.warning(f"WS send failed: {e}")
                dead.append(ws)

        async with self._lock:
            for ws in dead:
                if ws in self._connections:
                    self._connections.remove(ws)

    async def send_to(self, websocket: WebSocket, message_type: str, data: Any):
        """Send a message to a specific WebSocket client."""
        payload = json.dumps({"type": message_type, "data": data}, default=str)
        try:
            await websocket.send_text(payload)
        except Exception as e:
            logger.warning(f"WS send_to failed: {e}")

    @property
    def connection_count(self) -> int:
        return len(self._connections)


ws_hub = WebSocketHub()
