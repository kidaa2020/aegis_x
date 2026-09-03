"""
Módulo de compatibilidad: re-exporta ws_manager desde app.websocket.
"""

from app.websocket import ws_manager, manager

__all__ = ["ws_manager", "manager"]
