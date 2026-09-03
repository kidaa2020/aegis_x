"""
Servicio asíncrono para el escaneo de puertos y descubrimiento de servicios de red.
Utiliza Nmap con detección de versiones (-sV) y procesamiento de salida XML estructurada.
"""

import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from typing import Any

logger = logging.getLogger(__name__)


def _parse_nmap_xml(xml_content: str) -> list[dict[str, Any]]:
    """
    Parsea la salida XML generada por Nmap y extrae la información relevante de los puertos abiertos.

    Args:
        xml_content: Cadena en formato XML producida por nmap -oX -.

    Returns:
        list[dict]: Lista de puertos encontrados con su estado, servicio y versión.
    """
    results: list[dict[str, Any]] = []
    if not xml_content.strip():
        return results

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as exc:
        logger.error("Error al procesar el XML de nmap: %s", exc)
        return results

    # Recorrer todos los hosts detectados en el reporte XML
    for host in root.findall("host"):
        # Verificar estado del host
        status_el = host.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            protocol = port_el.get("protocol", "tcp")
            try:
                port_num = int(port_el.get("portid", "0"))
            except ValueError:
                continue

            state_el = port_el.find("state")
            state = state_el.get("state", "unknown") if state_el is not None else "unknown"

            # Nos interesan principalmente los puertos abiertos
            if state != "open":
                continue

            service_el = port_el.find("service")
            service_name = "unknown"
            product = ""
            version = ""
            extrainfo = ""

            if service_el is not None:
                service_name = service_el.get("name", "unknown")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                extrainfo = service_el.get("extrainfo", "")

            # Construcción del banner o descripción de versión completa
            banner_parts = [part for part in [product, version, extrainfo] if part]
            banner_str = " ".join(banner_parts).strip()
            if not banner_str and service_name != "unknown":
                banner_str = service_name

            results.append({
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "version": banner_str,
                "banner": banner_str,
            })

    return results


async def scan_ports(host: str, ports: str = "1-1000", timeout: int = 300) -> list[dict[str, Any]]:
    """
    Ejecuta un escaneo de puertos sobre el host especificado usando Nmap y detección de versiones (-sV).

    Args:
        host: Dirección IP o nombre de host a escanear.
        ports: Rango de puertos o lista separada por comas (ej: '1-1000', '80,443,8080').
        timeout: Tiempo máximo de espera en segundos para la ejecución de Nmap (por defecto 300s).

    Returns:
        list[dict]: Lista de diccionarios estructurados:
                    [{'port': int, 'protocol': str, 'state': str, 'service': str, 'version': str}, ...]
    """
    clean_host = host.strip()
    if not clean_host:
        return []

    # Verificar si nmap está instalado en el sistema operativo
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        logger.warning("La herramienta 'nmap' no está instalada o no se encuentra en el PATH del sistema.")
        return []

    logger.info("Iniciando escaneo de puertos con nmap en %s (Puertos: %s)", clean_host, ports)

    # Argumentos para nmap:
    # -Pn: Tratar host como activo (evita fallos por bloqueo de ping ICMP)
    # -sV: Detección de versiones de servicio
    # -T4: Temporización agresiva para mayor velocidad
    # -p: Rango de puertos
    # -oX -: Generar XML directo a stdout
    cmd = [
        "nmap",
        "-Pn",
        "-sV",
        "-T4",
        "-p",
        ports,
        "-oX",
        "-",
        clean_host,
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_data, stderr_data = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.error("Tiempo de espera agotado (%ds) en escaneo de puertos para %s", timeout, clean_host)
            try:
                process.kill()
            except Exception:
                pass
            return []

        if process.returncode != 0:
            error_output = stderr_data.decode("utf-8", errors="ignore").strip()
            logger.warning("Nmap finalizó con código de salida %d: %s", process.returncode, error_output)

        xml_output = stdout_data.decode("utf-8", errors="ignore")
        return _parse_nmap_xml(xml_output)

    except FileNotFoundError:
        logger.warning("No se pudo ejecutar el comando nmap. Archivo no encontrado.")
        return []
    except Exception as exc:
        logger.error("Error inesperado durante la ejecución de scan_ports para %s: %s", clean_host, exc)
        return []
