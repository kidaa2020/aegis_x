"""
Configuración de base de datos asíncrona utilizando SQLAlchemy 2.0 y SQLite (aiosqlite).
Proporciona el motor asíncrono, el generador de sesiones y la función de inicialización.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
import logging
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

# Configuración de registro (logging)
logger = logging.getLogger(__name__)

# Ruta de almacenamiento de la base de datos SQLite
BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "aegis_x.db"
DATABASE_URL = f"sqlite+aiosqlite:///{DATABASE_PATH.as_posix()}"

# Creación del motor asíncrono
engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)

# Fabrica de sesiones asíncronas
async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):
    """
    Clase base declarativa para todos los modelos ORM de la plataforma.
    """
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependencia de FastAPI para obtener una sesión de base de datos asíncrona por petición.

    Yields:
        AsyncSession: Sesión de SQLAlchemy asíncrona.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as exc:
            await session.rollback()
            logger.error("Error en la transacción de la base de datos: %s", exc)
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Gestor de contexto asíncrono para ejecutar operaciones de base de datos fuera del ciclo de petición
    (por ejemplo, dentro de tareas en segundo plano / BackgroundTasks).

    Yields:
        AsyncSession: Sesión de SQLAlchemy asíncrona.
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as exc:
            await session.rollback()
            logger.error("Error en el contexto de base de datos para tarea en segundo plano: %s", exc)
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Crea todas las tablas definidas en los modelos si aún no existen en la base de datos.
    """
    async with engine.begin() as conn:
        logger.info("Inicializando esquemas y tablas de la base de datos...")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Base de datos inicializada exitosamente.")
