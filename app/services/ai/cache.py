"""
Servicio de caché para análisis de Inteligencia Artificial (AICache).
Permite calcular firmas de hash estructurales a partir de peticiones HTTP,
almacenar resultados de análisis y reutilizar respuestas previas para
reducir costos y latencia de llamadas a modelos LLM.
"""

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qs, unquote, urlparse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import AICacheEntry

logger = logging.getLogger(__name__)


def generate_hash(
    method: str,
    url: str,
    param_names: Optional[List[str]] = None,
    body: Optional[Union[str, Dict[str, Any]]] = None,
    headers: Optional[Dict[str, Any]] = None
) -> str:
    """
    Genera un hash SHA-256 consistente e independiente de los valores específicos de los parámetros.
    Dos peticiones que compartan el mismo método, ruta y conjunto de parámetros (aunque tengan valores distintos)
    generarán el MISMO hash de caché.

    Args:
        method: Método HTTP (GET, POST, PUT, etc.).
        url: URL completa o ruta de la petición.
        param_names: Lista opcional de nombres de parámetros precalculados.
        body: Cuerpo de la petición (JSON, form-urlencoded o diccionario).
        headers: Diccionario opcional de encabezados relevantes.

    Returns:
        str: Hash SHA-256 en formato hexadecimal de 64 caracteres.
    """
    method_normalized = (method or "GET").upper().strip()
    
    # 1. Normalizar URL/Path
    parsed = urlparse(url or "")
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"

    # 2. Extraer parámetros si no fueron provistos explícitamente
    extracted_params: set[str] = set()

    if param_names is not None:
        extracted_params.update(param_names)
    else:
        # Extraer de Query String
        if parsed.query:
            try:
                qs = parse_qs(parsed.query, keep_blank_values=True)
                for k in qs.keys():
                    extracted_params.add(unquote(k).strip())
            except Exception:
                pass

        # Extraer de Body (JSON o Form)
        if body:
            if isinstance(body, dict):
                for k in body.keys():
                    extracted_params.add(str(k).strip())
            elif isinstance(body, str):
                body_clean = body.strip()
                if body_clean.startswith("{") or body_clean.startswith("["):
                    try:
                        parsed_json = json.loads(body_clean)
                        if isinstance(parsed_json, dict):
                            for k in parsed_json.keys():
                                extracted_params.add(str(k).strip())
                    except Exception:
                        pass
                elif "=" in body_clean:
                    try:
                        form_qs = parse_qs(body_clean, keep_blank_values=True)
                        for k in form_qs.keys():
                            extracted_params.add(unquote(k).strip())
                    except Exception:
                        pass

    # 3. Ordenar nombres de parámetros de forma determinista
    sorted_params_str = ",".join(sorted(list(extracted_params)))

    # 4. Construir firma canónica
    canonical_signature = f"{method_normalized}:{netloc}:{path}:{sorted_params_str}"

    return hashlib.sha256(canonical_signature.encode("utf-8")).hexdigest()


class AICache:
    """
    Gestor de operaciones de caché en base de datos para análisis de IA.
    """

    def __init__(self, db_session: Optional[AsyncSession] = None) -> None:
        """
        Inicializa el servicio de caché.

        Args:
            db_session: Sesión opcional de base de datos SQLAlchemy asíncrona.
        """
        self.db = db_session

    @staticmethod
    def generate_hash(
        method: str,
        url: str,
        param_names: Optional[List[str]] = None,
        body: Optional[Union[str, Dict[str, Any]]] = None,
        headers: Optional[Dict[str, Any]] = None
    ) -> str:
        """Método estático de conveniencia para generar el hash de caché."""
        return generate_hash(
            method=method,
            url=url,
            param_names=param_names,
            body=body,
            headers=headers
        )

    async def get_entry(self, cache_hash: str) -> Optional[AICacheEntry]:
        """
        Busca una entrada en la base de datos a partir de su hash de caché.

        Args:
            cache_hash: Hash de la petición.

        Returns:
            Optional[AICacheEntry]: Entrada encontrada o None si es un miss.
        """
        if self.db is None:
            return None

        stmt = select(AICacheEntry).where(AICacheEntry.cache_hash == cache_hash)
        result = await self.db.execute(stmt)
        entry = result.scalar_one_or_none()

        if entry:
            entry.hit_count += 1
            await self.db.commit()
            await self.db.refresh(entry)

        return entry

    async def set_entry(
        self,
        cache_hash: str,
        endpoint_pattern: str,
        analysis_data: Dict[str, Any]
    ) -> Optional[AICacheEntry]:
        """
        Guarda un nuevo resultado de análisis de IA en la caché de base de datos.

        Args:
            cache_hash: Hash de la petición.
            endpoint_pattern: Patrón o ruta del endpoint asociado.
            analysis_data: Diccionario con los datos del análisis estructurado.

        Returns:
            Optional[AICacheEntry]: La entrada creada o actualizada.
        """
        if self.db is None:
            return None

        stmt = select(AICacheEntry).where(AICacheEntry.cache_hash == cache_hash)
        result = await self.db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.analysis_data = analysis_data
            existing.endpoint_pattern = endpoint_pattern
            existing.hit_count += 1
            await self.db.commit()
            await self.db.refresh(existing)
            return existing

        new_entry = AICacheEntry(
            cache_hash=cache_hash,
            endpoint_pattern=endpoint_pattern,
            analysis_data=analysis_data,
            hit_count=1
        )
        self.db.add(new_entry)
        await self.db.commit()
        await self.db.refresh(new_entry)
        return new_entry
