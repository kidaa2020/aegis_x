"""
Gestor de conexiones WebSocket para la transmisión en tiempo real de eventos de escaneo,
capturas de tráfico HTTP y resultados de análisis asistidos por IA.
"""

import logging
from typing import Any, Dict, List
from fastapi import WebSocket

logger = logging.getLogger("aegis_x.websocket")


class ConnectionManager:
    """
    Administra el ciclo de vida de los sockets web conectados y distribuye mensajes JSON a los clientes.
    """

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Acepta y almacena una nueva conexión WebSocket."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("Cliente WebSocket conectado. Conexiones activas: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Elimina una conexión WebSocket activa cuando se cierra."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("Cliente WebSocket desconectado. Conexiones activas: %d", len(self.active_connections))

    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket) -> None:
        """Envía un mensaje JSON a una conexión WebSocket específica."""
        try:
            await websocket.send_json(message)
        except Exception as exc:
            logger.error("Error enviando mensaje personal por WebSocket: %s", exc)

    async def broadcast_json(self, message: Dict[str, Any]) -> None:
        """Envía un mensaje estructurado en formato JSON a todos los clientes WebSocket activos."""
        if not self.active_connections:
            return

        disconnected: List[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as exc:
                logger.warning("Error al emitir mensaje por WebSocket a un cliente: %s", exc)
                disconnected.append(connection)

        for dead_conn in disconnected:
            self.disconnect(dead_conn)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        """Alias para broadcast_json."""
        await self.broadcast_json(message)

    async def broadcast_traffic(self, traffic_data: Dict[str, Any]) -> None:
        """Emite un evento de nueva captura de tráfico HTTP hacia la vista de tráfico en vivo."""
        await self.broadcast_json({
            "type": "new_traffic",
            "data": traffic_data
        })

    async def broadcast_analysis(self, analysis_data: Dict[str, Any]) -> None:
        """Emite un evento con el resultado de análisis de seguridad IA generado."""
        await self.broadcast_json({
            "type": "new_analysis",
            "data": analysis_data
        })

    async def broadcast_target_event(
        self,
        target_id: int,
        scan_type: str,
        status: str,
        data: Any = None,
        message: str = "",
    ) -> None:
        """Emite un evento estandarizado sobre el progreso o conclusión de un escaneo en un objetivo."""
        payload = {
            "type": "scan_update",
            "event": "scan_update",
            "target_id": target_id,
            "scan_type": scan_type,
            "status": status,
            "data": data if data is not None else {},
            "message": message,
        }
        await self.broadcast_json(payload)


# Instancia global compartida del gestor de WebSockets
ws_manager = ConnectionManager()
manager = ws_manager
