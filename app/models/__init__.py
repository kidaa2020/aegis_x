"""
Re-exporta todos los modelos ORM de la plataforma para compatibilidad con cualquier estilo de importación.
"""

from app.models import (
    Target,
    Subdomain,
    PortResult,
    Technology,
    JSFile,
    JsAnalysis,
    TrafficEntry,
    AIAnalysis,
    AICacheEntry,
)

__all__ = [
    "Target",
    "Subdomain",
    "PortResult",
    "Technology",
    "JSFile",
    "JsAnalysis",
    "TrafficEntry",
    "AIAnalysis",
    "AICacheEntry",
]
