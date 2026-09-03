"""
Esquemas Pydantic para validación y serialización de tráfico HTTP.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class TrafficIngestRequest(BaseModel):
    """
    Carga útil esperada desde la extensión de Burp Suite para la ingesta de tráfico.
    """
    method: str = Field(..., example="POST", description="Método HTTP de la petición")
    url: str = Field(..., example="https://api.target.com/v1/auth/login", description="URL completa de la petición")
    request_headers: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Cabeceras enviadas en la petición")
    request_body: Optional[str] = Field(default="", description="Cuerpo de la petición HTTP")
    status_code: Optional[int] = Field(default=200, example=200, description="Código de estado de la respuesta HTTP")
    response_headers: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Cabeceras de la respuesta HTTP")
    response_body: Optional[str] = Field(default="", description="Cuerpo de la respuesta HTTP")
    target_id: Optional[int] = Field(default=None, description="ID del objetivo asociado en la plataforma")


class TrafficEntrySummaryResponse(BaseModel):
    """
    Resumen de una entrada de tráfico para vistas de lista y tablas.
    """
    id: int
    target_id: Optional[int]
    method: str
    url: str
    host: str
    path: str
    status_code: Optional[int]
    content_type: Optional[str]
    is_analyzable: bool
    is_analyzed: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TrafficEntryDetailResponse(BaseModel):
    """
    Detalle completo de una entrada de tráfico HTTP con parámetros extraídos y encabezados.
    """
    id: int
    target_id: Optional[int]
    method: str
    url: str
    host: str
    path: str
    query_params: Dict[str, Any]
    request_headers: Dict[str, Any]
    request_body: Optional[str]
    status_code: Optional[int]
    response_headers: Dict[str, Any]
    response_body: Optional[str]
    content_type: Optional[str]
    parameters_extracted: Dict[str, Any]
    dedup_key: Optional[str]
    is_analyzable: bool
    is_analyzed: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TrafficListResponse(BaseModel):
    """
    Respuesta paginada para listas de tráfico.
    """
    total: int
    page: int
    page_size: int
    items: List[TrafficEntrySummaryResponse]
