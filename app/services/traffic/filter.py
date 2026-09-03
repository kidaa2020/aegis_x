"""
Módulo de filtrado y deduplicación inteligente de tráfico HTTP.
Proporciona utilidades para descartar recursos estáticos irrelevantes,
extraer nombres de parámetros (omitiendo valores sensibles o dinámicos)
y generar firmas/hashes de estructura para evitar análisis redundantes.
"""

import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import parse_qs, unquote, urlparse

logger = logging.getLogger(__name__)

# Extensiones de archivos estáticos que no requieren análisis de seguridad de lógica de negocio o APIs
STATIC_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".css", ".js", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mkv", ".webm", ".wav", ".flac",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar", ".exe", ".dmg"
}

# Tipos MIME estáticos o multimedia
STATIC_CONTENT_TYPES: Set[str] = {
    "image/", "font/", "audio/", "video/",
    "text/css", "application/javascript", "text/javascript",
    "application/x-javascript", "application/font-woff",
    "application/x-font-ttf", "application/pdf", "application/zip"
}


def should_analyze(method: str, url: str, content_type: Optional[str] = None) -> bool:
    """
    Determina si una petición HTTP interceptada debe ser analizada por el motor de IA
    o almacenada para auditoría, descartando recursos estáticos.

    Args:
        method: Método HTTP (GET, POST, PUT, DELETE, etc.).
        url: URL completa de la petición.
        content_type: Encabezado Content-Type de la respuesta o petición (opcional).

    Returns:
        bool: True si el recurso es candidato a análisis de seguridad, False si es estático/irrelevante.
    """
    if not url:
        return False

    method_upper = (method or "GET").upper().strip()
    if method_upper in ("OPTIONS", "HEAD", "TRACE"):
        return False

    try:
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Eliminar fragmentos y normalizar
        clean_path = path.split("?")[0].split("#")[0]

        # Comprobar extensiones estáticas
        for ext in STATIC_EXTENSIONS:
            if clean_path.endswith(ext):
                return False

        # Comprobar Content-Type si está disponible
        if content_type:
            ct_lower = content_type.lower().strip()
            for static_ct in STATIC_CONTENT_TYPES:
                if static_ct in ct_lower:
                    # Permitir si explícitamente es json/xml/html aunque tenga otra etiqueta
                    if not any(dynamic in ct_lower for dynamic in ("application/json", "text/html", "application/xml", "text/xml")):
                        return False

        return True
    except Exception as e:
        logger.warning("Error al evaluar should_analyze para URL %s: %s", url, e)
        return True


def extract_param_names_from_query_string(query_or_url: str) -> List[str]:
    """
    Extrae una lista ordenada y única de los nombres de los parámetros de consulta (Query String).
    
    Args:
        query_or_url: Cadena de consulta 'param1=val1&param2=val2' o URL completa.

    Returns:
        List[str]: Lista ordenada alfabéticamente de nombres de parámetros únicos.
    """
    if not query_or_url:
        return []

    try:
        if "?" in query_or_url:
            query_str = urlparse(query_or_url).query
        else:
            query_str = query_or_url

        if not query_str:
            return []

        parsed_qs = parse_qs(query_str, keep_blank_values=True)
        param_names = [unquote(k).strip() for k in parsed_qs.keys() if k.strip()]
        return sorted(list(set(param_names)))
    except Exception as e:
        logger.warning("Error extrayendo parámetros de query string '%s': %s", query_or_url, e)
        return []


def extract_param_names_from_json_body(body: Union[str, Dict[str, Any], List[Any]]) -> List[str]:
    """
    Extrae una lista ordenada y única de las claves/parámetros en el cuerpo JSON.
    Soporta estructuras anidadas (notación de puntos) y colecciones.

    Args:
        body: Cadena JSON serializada o diccionario/lista deserializada.

    Returns:
        List[str]: Lista ordenada alfabéticamente de claves de parámetros.
    """
    if not body:
        return []

    data: Any = body
    if isinstance(body, str):
        body_str = body.strip()
        if not body_str or not (body_str.startswith("{") or body_str.startswith("[")):
            return []
        try:
            data = json.loads(body_str)
        except Exception:
            return []

    keys: Set[str] = set()

    def _collect_keys(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_str = str(k).strip()
                full_key = f"{prefix}.{k_str}" if prefix else k_str
                keys.add(full_key)
                if isinstance(v, (dict, list)):
                    _collect_keys(v, full_key)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    _collect_keys(item, prefix)

    _collect_keys(data)
    return sorted(list(keys))


def extract_param_names(
    url: str = "",
    request_body: Optional[str] = None,
    content_type: Optional[str] = None
) -> List[str]:
    """
    Extrae de forma combinada los nombres de parámetros de Query y de Body.

    Args:
        url: URL de la petición.
        request_body: Cuerpo crudo de la petición.
        content_type: Encabezado Content-Type.

    Returns:
        List[str]: Lista unificada y ordenada de todos los nombres de parámetros presentes.
    """
    all_params: Set[str] = set()

    # Extraer parámetros de Query
    if url:
        query_params = extract_param_names_from_query_string(url)
        all_params.update(query_params)

    # Extraer parámetros de Body
    if request_body:
        c_type = (content_type or "").lower()
        if "application/json" in c_type or request_body.strip().startswith(("{", "[")):
            json_params = extract_param_names_from_json_body(request_body)
            all_params.update(json_params)
        elif "form" in c_type or ("=" in request_body and "&" in request_body):
            form_params = extract_param_names_from_query_string(request_body)
            all_params.update(form_params)

    return sorted(list(all_params))


def deduplicate_key(
    method: str,
    url: str,
    param_names: Optional[List[str]] = None,
    body: Optional[str] = None
) -> str:
    """
    Genera un hash SHA-256 estructural que representa el endpoint y sus parámetros.
    Dos peticiones al mismo endpoint con los mismos nombres de parámetros pero distintos valores
    producirán la MISMA clave de deduplicación.

    Args:
        method: Método HTTP (GET, POST, etc.).
        url: URL completa de la petición.
        param_names: Lista opcional de nombres de parámetros precalculados.
        body: Cuerpo de la petición (usado para extraer parámetros si param_names no se provee).

    Returns:
        str: Cadena hexadecimal de 64 caracteres (SHA-256).
    """
    method_clean = (method or "GET").upper().strip()
    
    # Parsear ruta base sin query string ni fragmentos
    parsed = urlparse(url or "")
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"

    if param_names is None:
        param_names = extract_param_names(url=url, request_body=body)
    
    sorted_params = sorted(list(set(param_names)))
    params_signature = ",".join(sorted_params)

    structural_signature = f"{method_clean}|{netloc}|{path}|{params_signature}"
    return hashlib.sha256(structural_signature.encode("utf-8")).hexdigest()


class DeduplicationCache:
    """
    Caché en memoria para el seguimiento de peticiones duplicadas en tiempo real.
    Permite detectar si una estructura de petición ya ha sido observada y procesada.
    """

    def __init__(self, max_size: int = 10000) -> None:
        """
        Inicializa la caché de deduplicación.

        Args:
            max_size: Número máximo de firmas a retener en memoria antes de limpieza.
        """
        self._cache: Set[str] = set()
        self._max_size = max_size

    def is_duplicate(self, key: str) -> bool:
        """
        Comprueba si la clave ya existe en la caché.

        Args:
            key: Clave de deduplicación (hash SHA-256).

        Returns:
            bool: True si la clave ya está registrada, False en caso contrario.
        """
        return key in self._cache

    def add(self, key: str) -> None:
        """
        Registra una clave en la caché de deduplicación.

        Args:
            key: Clave de deduplicación.
        """
        if len(self._cache) >= self._max_size:
            self._cache.clear()
        self._cache.add(key)

    def check_and_add(self, key: str) -> bool:
        """
        Comprueba si una clave es duplicada y, si no lo es, la añade atómicamente a la caché.

        Args:
            key: Clave de deduplicación.

        Returns:
            bool: True si ya era un duplicado, False si es nueva y fue añadida.
        """
        if key in self._cache:
            return True
        self.add(key)
        return False

    def clear(self) -> None:
        """Limpia todas las claves almacenadas."""
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


class TrafficFilter:
    """
    Servicio de alto nivel para filtrado y deduplicación de tráfico HTTP.
    """

    def __init__(self) -> None:
        self.dedup_cache = DeduplicationCache()

    def should_analyze(self, method: str, url: str, content_type: Optional[str] = None) -> bool:
        return should_analyze(method=method, url=url, content_type=content_type)

    def extract_param_names_from_query_string(self, query_or_url: str) -> List[str]:
        return extract_param_names_from_query_string(query_or_url)

    def extract_param_names_from_json_body(self, body: Union[str, Dict[str, Any], List[Any]]) -> List[str]:
        return extract_param_names_from_json_body(body)

    def deduplicate_key(
        self,
        method: str,
        url: str,
        param_names: Optional[List[str]] = None,
        body: Optional[str] = None
    ) -> str:
        return deduplicate_key(method=method, url=url, param_names=param_names, body=body)

    def is_duplicate(self, key: str) -> bool:
        return self.dedup_cache.is_duplicate(key)

    def check_and_add(self, key: str) -> bool:
        return self.dedup_cache.check_and_add(key)
