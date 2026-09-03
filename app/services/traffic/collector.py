"""
Servicio de recolección y procesamiento de tráfico HTTP proveniente de Burp Suite / Proxies de auditoría.
Normaliza los datos recibidos, extrae parámetros clasificados y persiste las entradas en la base de datos.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.traffic import TrafficEntry
from app.services.traffic.filter import should_analyze, extract_param_names, deduplicate_key
from app.core.database import async_session_maker

logger = logging.getLogger(__name__)


class TrafficCollector:
    """
    Recolector y clasificador de tráfico HTTP interceptado.
    Recibe las peticiones y respuestas transmitidas por la extensión de Burp Suite,
    extrae sus parámetros (query, body, headers, cookies) y los almacena en base de datos.
    """

    def __init__(self) -> None:
        pass

    def extract_and_categorize_parameters(
        self,
        url: str,
        request_headers: Optional[Dict[str, Any]] = None,
        request_body: Optional[str] = None,
        content_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Extrae y categoriza todos los vectores de entrada presentes en la solicitud HTTP:
        - Parámetros de consulta (Query Parameters)
        - Parámetros en el cuerpo de la petición (JSON, Form-URL-Encoded, Multipart)
        - Cabeceras relevantes para seguridad (Autenticación, IP Forwarding, etc.)
        - Cookies de sesión y aplicación

        :param url: URL completa de la petición
        :param request_headers: Diccionario de encabezados HTTP
        :param request_body: Cadena con el cuerpo de la petición
        :param content_type: Tipo de contenido de la solicitud
        :return: Diccionario estructurado con parámetros categorizados y lista global de nombres
        """
        parsed_url = urlparse(url)
        query_dict: Dict[str, List[str]] = {}
        body_dict: Dict[str, Any] = {}
        headers_dict: Dict[str, str] = {}
        cookies_dict: Dict[str, str] = {}
        all_param_names: List[str] = []

        # 1. Extracción de Query Parameters
        if parsed_url.query:
            raw_qs = parse_qs(parsed_url.query, keep_blank_values=True)
            for k, v in raw_qs.items():
                clean_key = unquote(k)
                query_dict[clean_key] = [unquote(val) for val in v]
                if clean_key not in all_param_names:
                    all_param_names.append(clean_key)

        # 2. Extracción de Parámetros del Cuerpo (Body)
        if request_body:
            c_type = (content_type or "").lower()
            
            # Intento de parseo JSON
            if "application/json" in c_type or request_body.strip().startswith(("{", "[")):
                try:
                    json_data = json.loads(request_body)
                    if isinstance(json_data, dict):
                        body_dict = json_data
                        for k in json_data.keys():
                            if k not in all_param_names:
                                all_param_names.append(str(k))
                    elif isinstance(json_data, list):
                        body_dict = {"_json_array": json_data}
                except Exception:
                    body_dict = {"_raw": request_body[:500]}

            # Intento de parseo Form-URL-Encoded
            elif "application/x-www-form-urlencoded" in c_type or ("=" in request_body and "&" in request_body):
                try:
                    form_qs = parse_qs(request_body, keep_blank_values=True)
                    for k, v in form_qs.items():
                        clean_k = unquote(k)
                        body_dict[clean_k] = [unquote(val) for val in v]
                        if clean_k not in all_param_names:
                            all_param_names.append(clean_k)
                except Exception:
                    body_dict = {"_raw": request_body[:500]}
            else:
                body_dict = {"_raw": request_body[:500]}

        # 3. Extracción de Cabeceras Relevantes y Cookies
        if request_headers and isinstance(request_headers, dict):
            # Encabezados de interés en pruebas de penetración
            sensitive_header_keys = {
                "authorization", "x-forwarded-for", "x-real-ip", "x-custom-ip-authorization",
                "x-originating-ip", "x-remote-ip", "x-client-ip", "x-host", "x-forwarded-host",
                "user-agent", "referer", "origin", "x-requested-with", "x-api-key", "token"
            }
            for header_k, header_v in request_headers.items():
                lower_k = header_k.lower()
                if lower_k in sensitive_header_keys or lower_k.startswith("x-"):
                    headers_dict[header_k] = str(header_v)
                
                # Extracción específica de cookies
                if lower_k == "cookie" and isinstance(header_v, str):
                    cookie_parts = header_v.split(";")
                    for part in cookie_parts:
                        if "=" in part:
                            c_name, c_val = part.split("=", 1)
                            cookies_dict[c_name.strip()] = c_val.strip()
                            cookie_name = c_name.strip()
                            if cookie_name not in all_param_names:
                                all_param_names.append(f"cookie:{cookie_name}")

        return {
            "query": query_dict,
            "body": body_dict,
            "headers": headers_dict,
            "cookies": cookies_dict,
            "all_param_names": sorted(list(set(all_param_names)))
        }

    async def process_entry(self, data: Dict[str, Any], db: Optional[AsyncSession] = None) -> TrafficEntry:
        """
        Procesa una entrada de tráfico HTTP cruda recibida de Burp Suite, valida su estructura,
        extrae los parámetros, aplica filtros heurísticos y la persiste en la base de datos.

        :param data: Diccionario con la carga útil enviada por la extensión de Burp.
        :param db: Sesión asíncrona de base de datos opcional (crea una si no se proporciona).
        :return: Instancia persistida del modelo TrafficEntry.
        """
        method = (data.get("method") or "GET").upper().strip()
        url = (data.get("url") or "").strip()
        if not url:
            raise ValueError("El campo 'url' es obligatorio para procesar el tráfico.")

        # Descomposición de la URL
        parsed_url = urlparse(url)
        host = parsed_url.netloc or parsed_url.hostname or "unknown"
        path = parsed_url.path or "/"

        request_headers = data.get("request_headers") or {}
        request_body = data.get("request_body") or ""
        status_code = data.get("status_code")
        if status_code is not None:
            try:
                status_code = int(status_code)
            except (ValueError, TypeError):
                status_code = None

        response_headers = data.get("response_headers") or {}
        response_body = data.get("response_body") or ""
        target_id = data.get("target_id")

        # Detección del tipo de contenido
        content_type = ""
        if isinstance(response_headers, dict):
            for hk, hv in response_headers.items():
                if hk.lower() == "content-type":
                    content_type = str(hv)
                    break
        if not content_type and isinstance(request_headers, dict):
            for hk, hv in request_headers.items():
                if hk.lower() == "content-type":
                    content_type = str(hv)
                    break

        # Extracción y categorización de parámetros
        categorized_params = self.extract_and_categorize_parameters(
            url=url,
            request_headers=request_headers,
            request_body=request_body,
            content_type=content_type
        )
        
        # Filtro de pertinencia para análisis
        is_analyzable = should_analyze(method=method, url=url, content_type=content_type)

        # Generación de clave de deduplicación
        dedup_hash = deduplicate_key(
            method=method,
            url=url,
            param_names=categorized_params["all_param_names"]
        )

        entry = TrafficEntry(
            target_id=target_id,
            method=method,
            url=url,
            host=host,
            path=path,
            query_params=categorized_params["query"],
            request_headers=request_headers,
            request_body=request_body,
            status_code=status_code,
            response_headers=response_headers,
            response_body=response_body,
            content_type=content_type,
            parameters_extracted=categorized_params,
            dedup_key=dedup_hash,
            is_analyzable=is_analyzable,
            is_analyzed=False
        )

        # Persistencia en base de datos
        if db is not None:
            db.add(entry)
            await db.commit()
            await db.refresh(entry)
            logger.info(f"Entrada de tráfico guardada correctamente con ID {entry.id} para {method} {url}")
            return entry
        else:
            async with async_session_maker() as session:
                session.add(entry)
                await session.commit()
                await session.refresh(entry)
                logger.info(f"Entrada de tráfico guardada en sesión independiente con ID {entry.id}")
                return entry


# Instancia singleton del recolector
collector = TrafficCollector()
