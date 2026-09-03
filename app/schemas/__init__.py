"""
Esquemas Pydantic para serialización y validación de peticiones/respuestas.
"""
from app.schemas.traffic import (
    TrafficIngestRequest,
    TrafficEntrySummaryResponse,
    TrafficEntryDetailResponse,
    TrafficListResponse,
)
from app.schemas.analysis import (
    ParameterDetectionSchema,
    RiskClassificationSchema,
    AIAnalysisResponse,
    AnalysisStatsResponse,
)

__all__ = [
    "TrafficIngestRequest",
    "TrafficEntrySummaryResponse",
    "TrafficEntryDetailResponse",
    "TrafficListResponse",
    "ParameterDetectionSchema",
    "RiskClassificationSchema",
    "AIAnalysisResponse",
    "AnalysisStatsResponse",
]
