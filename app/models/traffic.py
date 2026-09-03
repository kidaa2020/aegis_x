"""
Módulo de compatibilidad: re-exporta modelos desde app.models (módulo plano)
para que importaciones como 'from app.models.traffic import TrafficEntry' funcionen.
"""

from app.models import TrafficEntry

__all__ = ["TrafficEntry"]
