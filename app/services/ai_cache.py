"""
Módulo alias para compatibilidad y exportación directa de AICache y utilidades de caché.
"""

from app.services.ai.cache import generate_hash, AICache

__all__ = ["generate_hash", "AICache"]
