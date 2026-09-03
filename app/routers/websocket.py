"""
Módulo de rutas WebSocket para la transmisión en tiempo real hacia el frontend.
"""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.websocket import ws_manager

logger = logging.getLogger("aegis_x.websocket_router")

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """
    Punto de enlace WebSocket (/ws) para clientes de la interfaz web.
    """
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "connection_established",
            "message": "Conectado al canal de eventos en tiempo real de Aegis_X"
        })
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
            else:
                logger.debug("Mensaje recibido por WebSocket: %s", data)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.debug("Conexión WebSocket finalizada: %s", exc)
        ws_manager.disconnect(websocket)
