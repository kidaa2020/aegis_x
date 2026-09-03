"""
Módulo de compatibilidad: re-exporta AIAnalysis y AICacheEntry desde app.models.
"""

from app.models import AIAnalysis, AICacheEntry

__all__ = ["AIAnalysis", "AICacheEntry"]
