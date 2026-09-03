"""
Servicio asíncrono para la identificación y fingerprinting de tecnologías web.
Inspecciona cabeceras HTTP, etiquetas meta, cookies de sesión y scripts cargados
para determinar servidores web, frameworks, CMS, librerías JS, CDN y analítica.
"""

import logging
import re
from typing import Any, Optional
import aiohttp

logger = logging.getLogger(__name__)

# Diccionario centralizado de firmas tecnológicas y patrones de coincidencia
SIGNATURES: dict[str, list[dict[str, Any]]] = {
    "headers": [
        {
            "header": "Server",
            "pattern": r"nginx(?:/([0-9.]+))?",
            "name": "Nginx",
            "category": "Web Server",
            "version_group": 1,
        },
        {
            "header": "Server",
            "pattern": r"Apache(?:/([0-9.]+))?",
            "name": "Apache HTTP Server",
            "category": "Web Server",
            "version_group": 1,
        },
        {
            "header": "Server",
            "pattern": r"Microsoft-IIS(?:/([0-9.]+))?",
            "name": "Microsoft IIS",
            "category": "Web Server",
            "version_group": 1,
        },
        {
            "header": "Server",
            "pattern": r"cloudflare",
            "name": "Cloudflare",
            "category": "CDN",
            "version_group": None,
        },
        {
            "header": "Server",
            "pattern": r"LiteSpeed",
            "name": "LiteSpeed",
            "category": "Web Server",
            "version_group": None,
        },
        {
            "header": "Server",
            "pattern": r"Caddy(?:/([0-9.]+))?",
            "name": "Caddy",
            "category": "Web Server",
            "version_group": 1,
        },
        {
            "header": "X-Powered-By",
            "pattern": r"PHP(?:/([0-9.]+))?",
            "name": "PHP",
            "category": "Framework",
            "version_group": 1,
        },
        {
            "header": "X-Powered-By",
            "pattern": r"ASP\.NET",
            "name": "ASP.NET",
            "category": "Framework",
            "version_group": None,
        },
        {
            "header": "X-Powered-By",
            "pattern": r"Express",
            "name": "Express.js",
            "category": "Framework",
            "version_group": None,
        },
        {
            "header": "X-Powered-By",
            "pattern": r"Next\.js(?:/([0-9.]+))?",
            "name": "Next.js",
            "category": "Framework",
            "version_group": 1,
        },
        {
            "header": "X-Generator",
            "pattern": r"Drupal(?:\s+([0-9.]+))?",
            "name": "Drupal",
            "category": "CMS",
            "version_group": 1,
        },
        {
            "header": "X-AspNet-Version",
            "pattern": r"([0-9.]+)",
            "name": "ASP.NET",
            "category": "Framework",
            "version_group": 1,
        },
    ],
    "cookies": [
        {
            "pattern": r"^JSESSIONID$",
            "name": "Java Servlet (Tomcat/Jetty)",
            "category": "Framework",
        },
        {
            "pattern": r"^PHPSESSID$",
            "name": "PHP",
            "category": "Framework",
        },
        {
            "pattern": r"^ASP\.NET_SessionId$",
            "name": "ASP.NET",
            "category": "Framework",
        },
        {
            "pattern": r"^csrftoken$",
            "name": "Django",
            "category": "Framework",
        },
        {
            "pattern": r"^(?:_session_id|_rails_session)$",
            "name": "Ruby on Rails",
            "category": "Framework",
        },
        {
            "pattern": r"^laravel_session$",
            "name": "Laravel",
            "category": "Framework",
        },
        {
            "pattern": r"^(?:connect\.sid|express:sess)$",
            "name": "Express.js",
            "category": "Framework",
        },
        {
            "pattern": r"^wp-settings-",
            "name": "WordPress",
            "category": "CMS",
        },
        {
            "pattern": r"^_cfuvid$|^__cf_bm$",
            "name": "Cloudflare",
            "category": "CDN",
        },
    ],
    "meta": [
        {
            "name_attr": "generator",
            "pattern": r"WordPress(?:\s+([0-9.]+))?",
            "name": "WordPress",
            "category": "CMS",
            "version_group": 1,
        },
        {
            "name_attr": "generator",
            "pattern": r"Joomla!(?:\s+([0-9.]+))?",
            "name": "Joomla",
            "category": "CMS",
            "version_group": 1,
        },
        {
            "name_attr": "generator",
            "pattern": r"Drupal(?:\s+([0-9.]+))?",
            "name": "Drupal",
            "category": "CMS",
            "version_group": 1,
        },
        {
            "name_attr": "generator",
            "pattern": r"Gatsby(?:-([0-9.]+))?",
            "name": "Gatsby",
            "category": "Framework",
            "version_group": 1,
        },
    ],
    "scripts": [
        {
            "pattern": r"jquery[.-]([0-9.]+)(?:\.min)?\.js",
            "name": "jQuery",
            "category": "JS Library",
            "version_group": 1,
        },
        {
            "pattern": r"jquery(?:\.min)?\.js",
            "name": "jQuery",
            "category": "JS Library",
            "version_group": None,
        },
        {
            "pattern": r"bootstrap(?:[.-]([0-9.]+))?(?:\.bundle)?(?:\.min)?\.js",
            "name": "Bootstrap",
            "category": "Framework",
            "version_group": 1,
        },
        {
            "pattern": r"react(?:-dom)?(?:\.production|\.development)?(?:[.-]([0-9.]+))?\.js",
            "name": "React",
            "category": "JS Library",
            "version_group": 1,
        },
        {
            "pattern": r"vue(?:\.runtime)?(?:[.-]([0-9.]+))?(?:\.min)?\.js",
            "name": "Vue.js",
            "category": "JS Library",
            "version_group": 1,
        },
        {
            "pattern": r"angular(?:[.-]([0-9.]+))?(?:\.min)?\.js",
            "name": "AngularJS",
            "category": "Framework",
            "version_group": 1,
        },
        {
            "pattern": r"/_next/static/",
            "name": "Next.js",
            "category": "Framework",
            "version_group": None,
        },
        {
            "pattern": r"/_nuxt/",
            "name": "Nuxt.js",
            "category": "Framework",
            "version_group": None,
        },
        {
            "pattern": r"/wp-content/|/wp-includes/",
            "name": "WordPress",
            "category": "CMS",
            "version_group": None,
        },
        {
            "pattern": r"google-analytics\.com/analytics\.js|googletagmanager\.com/gtag/js|googletagmanager\.com/gtm\.js",
            "name": "Google Analytics / Tag Manager",
            "category": "Analytics",
            "version_group": None,
        },
        {
            "pattern": r"static\.cloudflareinsights\.com",
            "name": "Cloudflare Web Analytics",
            "category": "Analytics",
            "version_group": None,
        },
        {
            "pattern": r"alpine(?:\.min)?\.js",
            "name": "Alpine.js",
            "category": "JS Library",
            "version_group": None,
        },
        {
            "pattern": r"cdn\.tailwindcss\.com|tailwind(?:\.min)?\.css",
            "name": "Tailwind CSS",
            "category": "Framework",
            "version_group": None,
        },
    ],
}


def _normalize_url(raw_url: str) -> str:
    """Asegura que la URL posea esquema http o https."""
    clean = raw_url.strip()
    if not clean.startswith(("http://", "https://")):
        return f"https://{clean}"
    return clean


async def detect_technologies(url: str, timeout_seconds: int = 15) -> list[dict[str, Any]]:
    """
    Realiza una petición HTTP asíncrona hacia la URL indicada y analiza las cabeceras,
    código HTML, cookies y recursos referenciados para clasificar el stack tecnológico.

    Args:
        url: URL del objetivo (ej: 'https://example.com' o 'example.com').
        timeout_seconds: Tiempo límite para la conexión HTTP en segundos.

    Returns:
        list[dict]: Lista de tecnologías encontradas en formato:
                    [{'name': str, 'version': str | None, 'category': str}, ...]
    """
    target_url = _normalize_url(url)
    detected: dict[str, dict[str, Any]] = {}

    def add_finding(name: str, category: str, version: Optional[str] = None) -> None:
        key = f"{name}::{category}"
        if key in detected:
            # Si no tenía versión previa y encontramos una, la actualizamos
            if not detected[key]["version"] and version:
                detected[key]["version"] = version
        else:
            detected[key] = {
                "name": name,
                "version": version,
                "category": category,
            }

    client_timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.get(
                target_url,
                headers=headers,
                allow_redirects=True,
                ssl=False,
            ) as response:
                resp_headers = response.headers
                html_body = await response.text(errors="ignore")
                cookies = response.cookies

                # 1. Análisis de Cabeceras HTTP
                for sig in SIGNATURES["headers"]:
                    hdr_name = sig["header"]
                    if hdr_name in resp_headers:
                        hdr_value = resp_headers[hdr_name]
                        match = re.search(sig["pattern"], hdr_value, re.IGNORECASE)
                        if match:
                            version = None
                            vg = sig.get("version_group")
                            if vg is not None and len(match.groups()) >= vg:
                                version = match.group(vg)
                            add_finding(sig["name"], sig["category"], version)

                # 2. Análisis de Cookies de Sesión
                for cookie_name in cookies.keys():
                    for sig in SIGNATURES["cookies"]:
                        if re.search(sig["pattern"], cookie_name, re.IGNORECASE):
                            add_finding(sig["name"], sig["category"])

                # 3. Análisis de Etiquetas Meta en HTML
                meta_tags = re.findall(
                    r"<meta\s+[^>]*name=[\"']([^\"']+)[\"'][^>]*content=[\"']([^\"']+)[\"']",
                    html_body,
                    re.IGNORECASE,
                )
                # También buscar con orden inverso de atributos content y name
                meta_tags += [
                    (n, c) for c, n in re.findall(
                        r"<meta\s+[^>]*content=[\"']([^\"']+)[\"'][^>]*name=[\"']([^\"']+)[\"']",
                        html_body,
                        re.IGNORECASE,
                    )
                ]

                for name_attr, content_attr in meta_tags:
                    for sig in SIGNATURES["meta"]:
                        if name_attr.lower() == sig["name_attr"].lower():
                            match = re.search(sig["pattern"], content_attr, re.IGNORECASE)
                            if match:
                                version = None
                                vg = sig.get("version_group")
                                if vg is not None and len(match.groups()) >= vg:
                                    version = match.group(vg)
                                add_finding(sig["name"], sig["category"], version)

                # 4. Análisis de URLs de scripts cargados (<script src="...">)
                script_srcs = re.findall(
                    r"<script\s+[^>]*src=[\"']([^\"']+)[\"']",
                    html_body,
                    re.IGNORECASE,
                )

                for src in script_srcs:
                    for sig in SIGNATURES["scripts"]:
                        match = re.search(sig["pattern"], src, re.IGNORECASE)
                        if match:
                            version = None
                            vg = sig.get("version_group")
                            if vg is not None and len(match.groups()) >= vg:
                                version = match.group(vg)
                            add_finding(sig["name"], sig["category"], version)

    except aiohttp.ClientError as exc:
        logger.warning("Error de conexión aiohttp detectando tecnologías en %s: %s", target_url, exc)
    except TimeoutError:
        logger.warning("Tiempo de espera agotado al conectar con %s", target_url)
    except Exception as exc:
        logger.error("Error inesperado en detect_technologies para %s: %s", target_url, exc)

    return list(detected.values())
