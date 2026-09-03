"""
Esquemas Pydantic para el router de análisis de seguridad con Inteligencia Artificial.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class ParameterDetectionSchema(BaseModel):
    name: str
    location: str
    category: str
    risk_level: str
    notes: Optional[str] = None
    is_reflected: Optional[bool] = False


class RiskClassificationSchema(BaseModel):
    owasp_top_10: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    severity: str = "Info"
    confidence: str = "Medium"


class AIAnalysisResponse(BaseModel):
    id: int
    traffic_entry_id: int
    target_id: Optional[int]
    cache_hash: Optional[str]
    risk_category: str
    risk_classification: Dict[str, Any]
    parameters_detected: List[Dict[str, Any]]
    methodology_notes: Optional[str]
    remediation: Optional[str]
    reflected_parameters: List[str]
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    created_at: datetime

    class Config:
        from_attributes = True


class AnalysisStatsResponse(BaseModel):
    openrouter_stats: Dict[str, Any]
    cache_stats: Dict[str, Any]
    dedup_cache_size: int
