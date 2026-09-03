"""
Modelos ORM de SQLAlchemy 2.0 para la plataforma de reconocimiento y auditoría de seguridad.
Define las entidades de objetivos, subdominios, puertos, tecnologías, análisis de JS, tráfico HTTP,
análisis de IA y caché de respuestas LLM.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Target(Base):
    """
    Representa un objetivo de auditoría o alcance principal (dominio raíz o ámbito de evaluación).
    """
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, default="", nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )

    # Relaciones con cascada
    subdomains: Mapped[List["Subdomain"]] = relationship(
        "Subdomain",
        back_populates="target",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    port_results: Mapped[List["PortResult"]] = relationship(
        "PortResult",
        back_populates="target",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    technologies: Mapped[List["Technology"]] = relationship(
        "Technology",
        back_populates="target",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    js_files: Mapped[List["JSFile"]] = relationship(
        "JSFile",
        back_populates="target",
        cascade="all, delete-orphan",
        lazy="selectin"
    )
    traffic_entries: Mapped[List["TrafficEntry"]] = relationship(
        "TrafficEntry",
        back_populates="target",
        cascade="all, delete-orphan",
        lazy="selectin"
    )

    # Aliases de compatibilidad
    @property
    def ports(self) -> List["PortResult"]:
        return self.port_results

    @property
    def js_analyses(self) -> List["JSFile"]:
        return self.js_files

    def __repr__(self) -> str:
        return f"<Target id={self.id} domain='{self.domain}'>"


class Subdomain(Base):
    """
    Subdominios descubiertos pertenecientes a un objetivo.
    """
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    subdomain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Alias de compatibilidad
    @property
    def ip_address(self) -> Optional[str]:
        return self.ip

    @ip_address.setter
    def ip_address(self, value: Optional[str]) -> None:
        self.ip = value

    target: Mapped["Target"] = relationship("Target", back_populates="subdomains")

    __table_args__ = (
        Index("ix_subdomains_target_subdomain", "target_id", "subdomain", unique=True),
    )

    def __repr__(self) -> str:
        return f"<Subdomain id={self.id} subdomain='{self.subdomain}' ip='{self.ip}'>"


class PortResult(Base):
    """
    Puertos y servicios abiertos descubiertos durante el escaneo de puertos.
    """
    __tablename__ = "port_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    host: Mapped[str] = mapped_column(String(255), default="", nullable=False, index=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp", nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    service: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, default="", nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    target: Mapped["Target"] = relationship("Target", back_populates="port_results")

    __table_args__ = (
        Index("ix_port_results_host_port_proto", "host", "port", "protocol", unique=True),
    )

    def __repr__(self) -> str:
        return f"<PortResult id={self.id} port={self.port}/{self.protocol} service='{self.service}'>"


class Technology(Base):
    """
    Tecnologías, marcos de trabajo, servidores y bibliotecas identificadas en el objetivo.
    """
    __tablename__ = "technologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), default="General", nullable=True)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    target: Mapped["Target"] = relationship("Target", back_populates="technologies")

    def __repr__(self) -> str:
        return f"<Technology id={self.id} name='{self.name}' version='{self.version}'>"


class JSFile(Base):
    """
    Archivos JavaScript extraídos del objetivo con endpoints y secretos descubiertos.
    """
    __tablename__ = "js_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    endpoints: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    secrets: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    subdomains: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    target: Mapped["Target"] = relationship("Target", back_populates="js_files")

    def __repr__(self) -> str:
        return f"<JSFile id={self.id} url='{self.url[:50]}...'>"


# Alias para compatibilidad con código de recon
JsAnalysis = JSFile


class TrafficEntry(Base):
    """
    Registro de tráfico HTTP/HTTPS capturado desde Burp Suite para auditoría.
    """
    __tablename__ = "traffic_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    method: Mapped[str] = mapped_column(String(16), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(255), default="", nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(1024), default="/", nullable=False, index=True)
    query_params: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_headers: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    request_body: Mapped[Optional[str]] = mapped_column(Text, default="", nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_headers: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    response_body: Mapped[Optional[str]] = mapped_column(Text, default="", nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(255), default="", nullable=True)
    parameters_extracted: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    dedup_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    is_analyzable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_analyzed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    # Alias
    @property
    def captured_at(self) -> datetime:
        return self.created_at

    target: Mapped[Optional["Target"]] = relationship("Target", back_populates="traffic_entries")
    
    ai_analysis: Mapped[Optional["AIAnalysis"]] = relationship(
        "AIAnalysis",
        back_populates="traffic_entry",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<TrafficEntry id={self.id} method='{self.method}' status={self.status_code} url='{self.url[:40]}...'>"


class AIAnalysis(Base):
    """
    Resultado del análisis de seguridad y clasificación de riesgos asistido por LLM.
    """
    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    traffic_entry_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("traffic_entries.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True
    )
    target_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    cache_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_category: Mapped[str] = mapped_column(String(50), default="Info", nullable=False, index=True)
    risk_classification: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    parameters_detected: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    methodology_notes: Mapped[Optional[str]] = mapped_column(Text, default="", nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, default="", nullable=True)
    reflected_parameters: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    raw_response: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, default=dict, nullable=True)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    @property
    def analyzed_at(self) -> datetime:
        return self.created_at

    traffic_entry: Mapped["TrafficEntry"] = relationship("TrafficEntry", back_populates="ai_analysis")

    def __repr__(self) -> str:
        return f"<AIAnalysis id={self.id} traffic_id={self.traffic_entry_id} risk='{self.risk_category}'>"


class AICacheEntry(Base):
    """
    Caché persistente de análisis de seguridad de IA por firma hash estructural.
    """
    __tablename__ = "ai_cache_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cache_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    endpoint_pattern: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    analysis_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    def __repr__(self) -> str:
        return f"<AICacheEntry id={self.id} hash='{self.cache_hash[:8]}' hits={self.hit_count}>"
