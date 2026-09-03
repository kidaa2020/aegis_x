"""
Configuración central de la plataforma de auditoría de seguridad y reconocimiento.
Carga variables de entorno y define parámetros por defecto para base de datos y OpenRouter.
"""

from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """
    Configuración global de la aplicación.
    Permite sobreescribir valores mediante variables de entorno o archivo .env.
    """
    # Configuración general de la aplicación
    PROJECT_NAME: str = "Aegis_X - Kali Linux Security Audit"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_V1_STR: str = "/api"

    # Base de datos SQLite asíncrona
    DATABASE_URL: str = "sqlite+aiosqlite:///./aegis_x.db"

    # Configuración de OpenRouter / Modelos de IA
    OPENROUTER_API_KEY: str = Field(default="", description="Clave de API para OpenRouter")
    OPENROUTER_MODEL: str = Field(
        default="anthropic/claude-3.5-sonnet",
        description="Modelo de IA por defecto para análisis de seguridad"
    )
    OPENROUTER_BASE_URL: str = Field(
        default="https://openrouter.ai/api/v1",
        description="URL base de la API de OpenRouter"
    )
    OPENROUTER_MAX_TOKENS: int = Field(
        default=2048,
        description="Límite máximo de tokens por respuesta"
    )
    OPENROUTER_TEMPERATURE: float = Field(
        default=0.2,
        description="Temperatura para análisis determinista y estructurado"
    )
    OPENROUTER_TIMEOUT: int = Field(
        default=60,
        description="Tiempo de espera en segundos para solicitudes a OpenRouter"
    )

    # Configuración de Caché y Deduplicación
    CACHE_EXPIRY_SECONDS: int = 86400  # 24 horas
    MAX_RESPONSE_BODY_PREVIEW_LEN: int = 4000

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Instancia única de configuración
settings = Settings()
