"""
Esquemas de Pydantic para validación de datos de entrada y serialización de respuestas API.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class TargetBase(BaseModel):
    """Esquema base para un objetivo."""
    domain: str = Field(..., description="Dominio u hostname objetivo (ej: example.com)", min_length=1, max_length=255)
    notes: Optional[str] = Field(default="", description="Notas o descripción del objetivo")


class TargetCreate(TargetBase):
    """Esquema para la creación de un nuevo objetivo."""
    pass


class SubdomainSchema(BaseModel):
    """Esquema de datos para un subdominio descubierto."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    subdomain: str
    ip: Optional[str] = None
    discovered_at: datetime


class PortResultSchema(BaseModel):
    """Esquema de datos para un puerto escaneado."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    port: int
    protocol: str
    state: str
    service: str
    banner: Optional[str] = ""
    scanned_at: datetime


class TechnologySchema(BaseModel):
    """Esquema de datos para una tecnología detectada."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    name: str
    version: Optional[str] = None
    category: str
    detected_at: datetime


class JsAnalysisSchema(BaseModel):
    """Esquema de datos para el análisis de un archivo JavaScript."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    url: str
    endpoints: list[str] = Field(default_factory=list)
    secrets: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    analyzed_at: datetime


class TargetResponse(TargetBase):
    """Esquema de respuesta básico para un objetivo."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class TargetDetailResponse(TargetResponse):
    """Esquema de respuesta detallado con todas las entidades relacionadas."""
    model_config = ConfigDict(from_attributes=True)

    subdomains: list[SubdomainSchema] = Field(default_factory=list)
    ports: list[PortResultSchema] = Field(default_factory=list)
    technologies: list[TechnologySchema] = Field(default_factory=list)
    js_analyses: list[JsAnalysisSchema] = Field(default_factory=list)


class ReconResultsResponse(BaseModel):
    """Resumen consolidado de todos los resultados de reconocimiento para un objetivo."""
    target_id: int
    domain: str
    total_subdomains: int
    total_open_ports: int
    total_technologies: int
    total_js_files: int
    subdomains: list[SubdomainSchema]
    ports: list[PortResultSchema]
    technologies: list[TechnologySchema]
    js_analyses: list[JsAnalysisSchema]


class TaskTriggerResponse(BaseModel):
    """Respuesta estándar al iniciar una tarea de reconocimiento en segundo plano."""
    status: str = Field(default="queued", description="Estado de la tarea iniciada")
    message: str = Field(..., description="Descripción del proceso iniciado")
    target_id: int = Field(..., description="Identificador del objetivo")
    scan_type: str = Field(..., description="Tipo de escaneo iniciado")


class PortScanRequest(BaseModel):
    """Parámetros opcionales para solicitar un escaneo de puertos."""
    ports: Optional[str] = Field(default="1-1000", description="Rango o lista de puertos (ej: '1-1000', '80,443,8080')")


class ErrorResponse(BaseModel):
    """Esquema para respuestas de error de la API."""
    detail: str = Field(..., description="Mensaje detallado del error")
