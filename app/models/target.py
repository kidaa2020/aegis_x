"""
Módulo de compatibilidad: re-exporta Target desde app.models (módulo plano).
"""

from app.models import Target

__all__ = ["Target"]
