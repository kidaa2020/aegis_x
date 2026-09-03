"""
Servicio asíncrono para el análisis estático de archivos JavaScript.
Extrae endpoints de API, rutas relativas, cadenas sensibles o claves de configuración
y nombres de subdominios referenciados en el código frontend.
"""

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse
from typing import Any
import aiohttp

logger = logging.getLogger(__name__)

# Límites de seguridad y rendimiento
MAX_JS_FILES = 20
MAX_FILE_BYTES = 500 * 1024  # 500 KB por archivo

# Patrones Regex para descubrimiento de Endpoints y Rutas
REGEX_ENDPOINTS = [
    re.compile(r"""(?:[\"'])(/api/(?:v[0-9]+/)?(?:[a-zA-Z0-9_\-\.\/]+))(?:[\"'])"""),
    re.compile(r"""(?:[\"'])(/v[0-9]+/(?:[a-zA-Z0-9_\-\.\/]+))(?:[\"'])"""),
    re.compile(r"""(?:[\"'])(/graphql(?:[a-zA-Z0-9_\-\.\/]*))(?:[\"'])"""),
    re.compile(r"""fetch\(\s*[\"']([a-zA-Z0-9_\-\.\/\:\?\#\=\&]+)[\"']"""),
    re.compile(r"""axios(?:\.get|\.post|\.put|\.delete|\.patch)?\(\s*[\"']([a-zA-Z0-9_\-\.\/\:\?\#\=\&]+)[\"']"""),
    re.compile(r"""\$\.ajax\(\{\s*url:\s*[\"']([a-zA-Z0-9_\-\.\/\:\?\#\=\&]+)[\"']"""),
    re.compile(r"""open\(\s*[\"'](?:GET|POST|PUT|DELETE)[\"']\s*,\s*[\"']([a-zA-Z0-9_\-\.\/\:\?\#\=\&]+)[\"']"""),
]

# Patrones Regex para rutas relativas comunes en aplicaciones web
REGEX_RELATIVE_PATHS = [
    re.compile(r"""(?:[\"'])(/(?:admin|auth|login|dashboard|user|users|profile|settings|upload|download|static|assets|media)/[a-zA-Z0-9_\-\.\/]+)(?:[\"'])"""),
]

# Patrones Regex para detección de cadenas sensibles y secretos potenciales
REGEX_SECRETS = [
    re.compile(r"""(?:api_?key|apikey|app_?key)\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,64})[\"']""", re.IGNORECASE),
    re.compile(r"""(?:access_?token|auth_?token|bearer_?token|token)\s*[:=]\s*[\"']([a-zA-Z0-9_\-\.]{16,128})[\"']""", re.IGNORECASE),
    re.compile(r"""(?:secret_?key|client_?secret|api_?secret)\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,64})[\"']""", re.IGNORECASE),
    re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s]{6,64})[\"']""", re.IGNORECASE),
    re.compile(r"""(AKIA[0-9A-Z]{16})"""),  # AWS Access Key ID
    re.compile(r"""(ghp_[0-9a-zA-Z]{36})"""),  # GitHub Personal Access Token
    re.compile(r"""(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)"""),  # Token JWT
    re.compile(r"""(AIza[0-9A-Za-z\-_]{35})"""),  # Google API Key
    re.compile(r"""(sk_live_[0-9a-zA-Z]{24})"""),  # Stripe Secret Key
]


def _normalize_target_url(raw_url: str) -> str:
    """Asegura el esquema http o https en la URL."""
    clean = raw_url.strip()
    if not clean.startswith(("http://", "https://")):
        return f"https://{clean}"
    return clean


def _extract_base_domain(url: str) -> str:
    """Extrae el dominio base o hostname de una URL."""
    parsed = urlparse(_normalize_target_url(url))
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


async def _fetch_and_analyze_js(
    session: aiohttp.ClientSession,
    js_url: str,
    base_domain: str,
) -> dict[str, Any]:
    """
    Descarga el contenido de un archivo JS y aplica las reglas de análisis estático.

    Args:
        session: Sesión aiohttp activa.
        js_url: URL absoluta del archivo JavaScript.
        base_domain: Dominio base para filtrar subdominios relacionados.

    Returns:
        dict: Resultado con endpoints, secretos y subdominios encontrados.
    """
    endpoints_set: set[str] = set()
    secrets_set: set[str] = set()
    subdomains_set: set[str] = set()

    try:
        async with session.get(js_url, ssl=False) as response:
            if response.status != 200:
                return {
                    "url": js_url,
                    "endpoints": [],
                    "secrets": [],
                    "sensitive_strings": [],
                    "subdomains": [],
                    "referenced_hosts": [],
                }

            # Leer contenido limitando tamaño máximo
            content_bytes = await response.content.read(MAX_FILE_BYTES)
            text_content = content_bytes.decode("utf-8", errors="ignore")

            # 1. Búsqueda de Endpoints y Rutas de API
            for pattern in REGEX_ENDPOINTS:
                for match in pattern.finditer(text_content):
                    endpoint = match.group(1).strip()
                    if len(endpoint) > 2 and not endpoint.endswith((".png", ".jpg", ".svg", ".css")):
                        endpoints_set.add(endpoint)

            for pattern in REGEX_RELATIVE_PATHS:
                for match in pattern.finditer(text_content):
                    path_found = match.group(1).strip()
                    endpoints_set.add(path_found)

            # 2. Búsqueda de Cadenas Sensibles y Secretos
            for pattern in REGEX_SECRETS:
                for match in pattern.finditer(text_content):
                    secret_found = match.group(1).strip()
                    # Ignorar valores genéricos o de ejemplo
                    if secret_found.lower() not in {"null", "undefined", "true", "false", "default", "none"}:
                        secrets_set.add(secret_found)

            # 3. Búsqueda de Subdominios y Hosts referenciados
            if base_domain:
                escaped_domain = re.escape(base_domain)
                regex_sub = re.compile(
                    rf"""https?://([a-zA-Z0-9_\-\.]+\.{escaped_domain})""",
                    re.IGNORECASE,
                )
                for match in regex_sub.finditer(text_content):
                    discovered_host = match.group(1).lower().strip()
                    if discovered_host:
                        subdomains_set.add(discovered_host)

    except Exception as exc:
        logger.debug("Error analizando archivo JS %s: %s", js_url, exc)

    endpoint_list = sorted(endpoints_set)
    secret_list = sorted(secrets_set)
    subdomain_list = sorted(subdomains_set)

    return {
        "url": js_url,
        "endpoints": endpoint_list,
        "secrets": secret_list,
        "sensitive_strings": secret_list,
        "subdomains": subdomain_list,
        "referenced_hosts": subdomain_list,
    }


async def analyze_js_files(url: str, timeout_seconds: int = 30) -> list[dict[str, Any]]:
    """
    Función principal para auditar los archivos JavaScript vinculados en una página web.

    Args:
        url: URL del sitio web objetivo.
        timeout_seconds: Tiempo límite para la recolección y análisis.

    Returns:
        list[dict]: Lista de resultados por cada archivo JS analizado:
                    [{'url': str, 'endpoints': list[str], 'secrets': list[str], 'subdomains': list[str]}, ...]
    """
    target_url = _normalize_target_url(url)
    base_domain = _extract_base_domain(target_url)

    logger.info("Iniciando análisis de archivos JS en: %s", target_url)
    js_urls: list[str] = []

    client_timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        async with aiohttp.ClientSession(timeout=client_timeout, headers=headers) as session:
            # 1. Obtener el HTML principal de la página
            try:
                async with session.get(target_url, ssl=False) as response:
                    html_content = await response.text(errors="ignore")
            except Exception as exc:
                logger.warning("No se pudo obtener la página HTML principal %s: %s", target_url, exc)
                return []

            # 2. Extraer todas las etiquetas <script src="...">
            src_matches = re.findall(
                r"""<script\s+[^>]*src=[\"']([^\"']+\.js(?:[\?#][^\"']*)?)[\"']""",
                html_content,
                re.IGNORECASE,
            )

            seen_urls: set[str] = set()
            for src in src_matches:
                absolute_url = urljoin(target_url, src.strip())
                if absolute_url not in seen_urls:
                    seen_urls.add(absolute_url)
                    js_urls.append(absolute_url)
                if len(js_urls) >= MAX_JS_FILES:
                    break

            if not js_urls:
                logger.info("No se encontraron scripts JS externos en %s", target_url)
                return []

            # 3. Analizar de forma concurrente los archivos JS encontrados
            tasks = [_fetch_and_analyze_js(session, js_url, base_domain) for js_url in js_urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            valid_results: list[dict[str, Any]] = []
            for item in results:
                if isinstance(item, dict):
                    valid_results.append(item)

            return valid_results

    except Exception as exc:
        logger.error("Fallo general en analyze_js_files para %s: %s", target_url, exc)
        return []
