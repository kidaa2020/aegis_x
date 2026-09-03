"""
Servicio asíncrono de descubrimiento e inventario de subdominios.
Permite enumerar la superficie externa de dominios utilizando herramientas de línea de comandos (subfinder)
con mecanismo de respaldo basado en resolución DNS estándar con socket y dnspython.
"""

import asyncio
import logging
import shutil
import socket
from typing import Optional

logger = logging.getLogger(__name__)

# Lista de prefijos comunes para fuerza bruta DNS en caso de fallback
COMMON_SUBDOMAIN_PREFIXES = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
    "admin", "app", "cdn", "cloud", "direct", "ftp", "intranet", "git"
]


async def _resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resuelve una dirección IP para un nombre de host de forma asíncrona y sin bloquear el loop de eventos.

    Args:
        hostname: Nombre de host o subdominio a resolver.

    Returns:
        str | None: Dirección IP encontrada o None si la resolución falla.
    """
    loop = asyncio.get_running_loop()
    try:
        # Ejecuta socket.getaddrinfo en un hilo separado para evitar bloqueos
        addr_info = await loop.run_in_executor(
            None,
            socket.getaddrinfo,
            hostname,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        if addr_info and len(addr_info) > 0:
            return addr_info[0][4][0]
    except (socket.gaierror, socket.herror, TimeoutError):
        return None
    except Exception as exc:
        logger.debug("Error resolviendo IP para %s: %s", hostname, exc)
        return None
    return None


async def _enumerate_with_subfinder(domain: str, timeout: int = 120) -> list[dict[str, Optional[str]]]:
    """
    Ejecuta la herramienta subfinder de forma asíncrona mediante subproceso.

    Args:
        domain: Dominio base objetivo.
        timeout: Tiempo máximo de ejecución en segundos.

    Returns:
        list[dict]: Lista de diccionarios con las llaves 'subdomain' e 'ip'.
    """
    logger.info("Iniciando descubrimiento con 'subfinder' para: %s", domain)
    discovered_subdomains: set[str] = set()

    try:
        process = await asyncio.create_subprocess_exec(
            "subfinder",
            "-d",
            domain,
            "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning("Tiempo de espera agotado (%ds) ejecutando subfinder para %s", timeout, domain)
            try:
                process.kill()
            except Exception:
                pass
            return []

        if process.returncode != 0:
            error_msg = stderr_data.decode("utf-8", errors="ignore").strip()
            logger.warning("Subfinder finalizó con código %d. Detalle: %s", process.returncode, error_msg)

        lines = stdout_data.decode("utf-8", errors="ignore").splitlines()
        for line in lines:
            sub = line.strip().lower()
            if sub and "." in sub:
                discovered_subdomains.add(sub)

    except Exception as exc:
        logger.error("Fallo inesperado al ejecutar subfinder: %s", exc)
        return []

    # Resolver direcciones IP para cada subdominio encontrado
    results: list[dict[str, Optional[str]]] = []
    resolve_tasks = []

    sub_list = sorted(discovered_subdomains)
    for sub in sub_list:
        resolve_tasks.append(_resolve_hostname(sub))

    if resolve_tasks:
        ips = await asyncio.gather(*resolve_tasks, return_exceptions=True)
        for sub, ip_res in zip(sub_list, ips):
            ip_val = ip_res if isinstance(ip_res, str) else None
            results.append({"subdomain": sub, "ip": ip_val})

    return results


async def _enumerate_with_dns_fallback(domain: str) -> list[dict[str, Optional[str]]]:
    """
    Mecanismo de respaldo para descubrimiento de subdominios mediante resolución directa de prefijos comunes.

    Args:
        domain: Dominio base objetivo.

    Returns:
        list[dict]: Lista de subdominios detectados y sus respectivas direcciones IP.
    """
    logger.info("Ejecutando descubrimiento DNS básico de respaldo para: %s", domain)
    results: list[dict[str, Optional[str]]] = []

    # Incluir el dominio raíz
    root_ip = await _resolve_hostname(domain)
    if root_ip:
        results.append({"subdomain": domain, "ip": root_ip})

    async def check_prefix(prefix: str) -> Optional[dict[str, Optional[str]]]:
        candidate = f"{prefix}.{domain}"
        ip = await _resolve_hostname(candidate)
        if ip:
            return {"subdomain": candidate, "ip": ip}
        return None

    tasks = [check_prefix(prefix) for prefix in COMMON_SUBDOMAIN_PREFIXES]
    discovered = await asyncio.gather(*tasks, return_exceptions=True)

    for item in discovered:
        if isinstance(item, dict):
            results.append(item)

    return results


async def enumerate_subdomains(domain: str) -> list[dict[str, Optional[str]]]:
    """
    Función principal de servicio para enumerar subdominios de un objetivo.
    Prioriza 'subfinder' si está instalado en el sistema, y recurre a resolución DNS si no está disponible.

    Args:
        domain: Nombre del dominio a auditar (ej: 'example.com').

    Returns:
        list[dict]: Lista estructurada [{'subdomain': str, 'ip': str | None}, ...]
    """
    domain_clean = domain.strip().lower()
    if not domain_clean:
        return []

    has_subfinder = shutil.which("subfinder") is not None

    if has_subfinder:
        results = await _enumerate_with_subfinder(domain_clean)
        if results:
            return results
        logger.info("Subfinder no devolvió resultados o falló. Utilizando método de respaldo.")

    # Si subfinder no está instalado o no devolvió resultados
    return await _enumerate_with_dns_fallback(domain_clean)
