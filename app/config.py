"""
Módulo de configuración global para Aegis_X.
Utiliza Pydantic Settings para cargar y validar variables de entorno con valores predeterminados.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configuración de la aplicación cargada desde variables de entorno y archivo .env.
    """

    APP_NAME: str = "aegis_x"
    DATABASE_URL: str = "sqlite+aiosqlite:///./aegis_x.db"
    
    # Integración con proveedor de IA (OpenRouter)
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "meta-llama/llama-3.3-70b-instruct:free"
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
    MAX_TOKENS_PER_REQUEST: int = 500
    AI_CACHE_ENABLED: bool = True

    # Integración con herramientas de captura de tráfico (Burp Suite, etc.)
    BURP_WEBHOOK_SECRET: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Obtiene la instancia singleton de las configuraciones de la aplicación.
    Utiliza lru_cache para evitar lecturas redundantes del entorno y archivo .env.
    
    Returns:
        Settings: Objeto con la configuración activa.
    """
    return Settings()
