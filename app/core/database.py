"""
Módulo de compatibilidad: re-exporta los componentes de app.database
para que los módulos que importen desde app.core.database funcionen correctamente.
"""

from app.database import (
    Base,
    engine,
    async_session_factory as async_session_maker,
    get_db,
    get_db_context,
    init_db,
)

__all__ = ["Base", "engine", "async_session_maker", "get_db", "get_db_context", "init_db"]
