"""
Orquestador principal de análisis de seguridad con Inteligencia Artificial.
Coordina el filtrado previo, la consulta y almacenamiento en caché, la detección de reflexión de parámetros
y la ejecución de auditorías mediante OpenRouter con parsing estructurado y persistencia en base de datos.
"""

import json
import logging
import re
from typing import List, Dict, Any, Optional
from urllib.parse import unquote
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.traffic import TrafficEntry
from app.models.analysis import AIAnalysis
from app.services.traffic.filter import should_analyze, extract_param_names
from app.services.ai.cache import AICache, get_ai_cache
from app.services.ai.openrouter import OpenRouterClient, get_client, OpenRouterError
from app.services.ai.prompts import build_traffic_analysis_prompt
from app.core.database import async_session_maker

logger = logging.getLogger(__name__)


class SecurityAnalyzer:
    """
    Motor de análisis de seguridad asistido por IA para transacciones HTTP y vectores de ataque web.
    """

    def __init__(
        self,
        client: Optional[OpenRouterClient] = None,
        cache: Optional[AICache] = None
    ) -> None:
        self.client: OpenRouterClient = client or get_client()
        self.cache: AICache = cache or get_ai_cache()

    def detect_reflection(
        self,
        params: Optional[Dict[str, Any]],
        response_body: Optional[str]
    ) -> List[str]:
        """
        Inspecciona el cuerpo de la respuesta HTTP para determinar si los valores de los parámetros
        enviados en la petición se reflejan directamente (indicador clave para XSS, SSTI, Injection).

        :param params: Diccionario de parámetros categorizados (query, body, headers)
        :param response_body: Contenido textual del cuerpo de respuesta HTTP
        :return: Lista de nombres de parámetros cuyos valores se encuentran reflejados en la respuesta.
        """
        if not params or not response_body or not isinstance(response_body, str):
            return []

        reflected: List[str] = []
        body_lower = response_body.lower()

        # Recorrer parámetros en query, body y headers
        for category in ["query", "body", "headers", "cookies"]:
            category_params = params.get(category, {})
            if isinstance(category_params, dict):
                for param_name, param_val in category_params.items():
                    values_to_check: List[str] = []
                    if isinstance(param_val, list):
                        values_to_check.extend([str(v) for v in param_val])
                    elif isinstance(param_val, (str, int, float)) and not isinstance(param_val, bool):
                        values_to_check.append(str(param_val))

                    for val in values_to_check:
                        clean_val = unquote(val).strip()
                        # Filtrar cadenas triviales o demasiado cortas (< 3 caracteres) para evitar falsos positivos
                        if len(clean_val) >= 3 and clean_val.lower() in body_lower:
                            if param_name not in reflected:
                                reflected.append(param_name)
                            break

        return reflected

    def _parse_ai_json(self, raw_text: str) -> Dict[str, Any]:
        """
        Limpia y extrae de forma robusta la estructura JSON generada por el modelo de IA,
        eliminando bloques de código markdown (```json ... ```) y texto periférico.
        """
        clean_text = raw_text.strip()

        # Eliminar bloques markdown ```json ... ```
        if "```" in clean_text:
            match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean_text, re.IGNORECASE)
            if match:
                clean_text = match.group(1).strip()

        try:
            return json.loads(clean_text)
        except json.JSONDecodeError:
            # Intento de extracción de llaves delimitadoras {}
            start_idx = clean_text.find("{")
            end_idx = clean_text.rfind("}")
            if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                try:
                    return json.loads(clean_text[start_idx:end_idx + 1])
                except json.JSONDecodeError:
                    pass

            logger.error(f"Fallo al parsear JSON devuelto por IA: {raw_text[:300]}")
            return {
                "risk_category": "Info",
                "risk_classification": {
                    "owasp_top_10": [],
                    "cwe_ids": [],
                    "severity": "Info",
                    "confidence": "Low"
                },
                "parameters_detected": [],
                "methodology_notes": "No fue posible parsear automáticamente la respuesta del modelo.",
                "remediation": raw_text[:500]
            }

    async def analyze_traffic_entry(
        self,
        entry: TrafficEntry,
        db: Optional[AsyncSession] = None,
        force_refresh: bool = False
    ) -> Optional[AIAnalysis]:
        """
        Ejecuta el flujo completo de análisis de seguridad sobre una entrada de tráfico:
        1. Comprueba si el endpoint es analizable (filtrado heurístico).
        2. Extrae parámetros y calcula la clave/firma de deduplicación estructural.
        3. Consulta la caché para evitar llamadas redundantes a la API.
        4. Detecta reflejo de parámetros en la respuesta.
        5. Construye el prompt y realiza la llamada asíncrona a OpenRouter.
        6. Parsea y valida el resultado JSON.
        7. Almacena el resultado en caché y en la base de datos.

        :param entry: Objeto TrafficEntry a auditar
        :param db: Sesión de base de datos opcional
        :param force_refresh: Si es True, ignora la caché y fuerza una nueva consulta a la IA
        :return: Instancia de AIAnalysis generada o persistida, o None si no es analizable.
        """
        # 1. Comprobación de filtrado
        if not should_analyze(method=entry.method, url=entry.url, content_type=entry.content_type):
            logger.info(f"Entrada ID {entry.id} descartada para análisis IA por filtro heurístico.")
            return None

        # 2. Extracción de parámetros y generación de firma para caché
        extracted_params = entry.parameters_extracted or {}
        all_param_names = extracted_params.get("all_param_names", [])
        if not all_param_names:
            all_param_names = extract_param_names(
                url=entry.url,
                body=entry.request_body,
                content_type=entry.content_type
            )

        cache_struct = {
            "method": entry.method,
            "path": entry.path,
            "param_names": all_param_names
        }
        cache_hash = self.cache.generate_hash(cache_struct)

        # 3. Comprobación en caché
        cached_data = None if force_refresh else await self.cache.get_cached(cache_hash, db=db)
        prompt_tokens = 0
        completion_tokens = 0
        raw_response_dict: Dict[str, Any] = {}

        if cached_data:
            logger.info(f"Utilizando resultado en caché para entrada ID {entry.id} (Hash: {cache_hash[:8]})")
            analysis_dict = cached_data
            raw_response_dict = {"source": "cache", "data": cached_data}
        else:
            # 4. Detección de reflejo de parámetros en el cuerpo de la respuesta
            reflected_params = self.detect_reflection(extracted_params, entry.response_body or "")

            # 5. Construcción del prompt
            request_data = {
                "method": entry.method,
                "url": entry.url,
                "status_code": entry.status_code,
                "params": extracted_params,
                "headers_summary": extracted_params.get("headers", {}),
                "reflected_params": reflected_params,
                "response_body_preview": (entry.response_body or "")[:2000]
            }
            messages = build_traffic_analysis_prompt(request_data)

            # 6. Llamada a OpenRouter
            try:
                ai_response = await self.client.chat(messages, response_format={"type": "json_object"})
                usage = ai_response.get("usage", {})
                prompt_tokens = usage.get("prompt_tokens", 0)
                completion_tokens = usage.get("completion_tokens", 0)
                
                choices = ai_response.get("choices", [])
                if choices:
                    content_text = choices[0].get("message", {}).get("content", "{}")
                else:
                    content_text = "{}"

                analysis_dict = self._parse_ai_json(content_text)
                raw_response_dict = ai_response

                # 7. Almacenar en caché
                endpoint_pattern = f"{entry.method} {entry.path}"
                await self.cache.store(cache_hash, analysis_dict, endpoint_pattern=endpoint_pattern, db=db)

            except OpenRouterError as exc:
                logger.error(f"Error de OpenRouter al analizar entrada {entry.id}: {exc}")
                raise

        # Marcado de parámetros reflejados en el resultado
        reflected_list = self.detect_reflection(extracted_params, entry.response_body or "")

        # 8. Construcción de la entidad AIAnalysis
        analysis = AIAnalysis(
            traffic_entry_id=entry.id,
            target_id=entry.target_id,
            cache_hash=cache_hash,
            risk_category=analysis_dict.get("risk_category", "Info"),
            risk_classification=analysis_dict.get("risk_classification", {}),
            parameters_detected=analysis_dict.get("parameters_detected", []),
            methodology_notes=analysis_dict.get("methodology_notes", ""),
            remediation=analysis_dict.get("remediation", ""),
            reflected_parameters=reflected_list,
            raw_response=raw_response_dict,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens
        )

        # 9. Guardar en base de datos y marcar TrafficEntry como analizado
        if db is not None:
            db.add(analysis)
            entry.is_analyzed = True
            await db.commit()
            await db.refresh(analysis)
            logger.info(f"Análisis IA guardado exitosamente con ID {analysis.id} para tráfico {entry.id}")
            return analysis
        else:
            async with async_session_maker() as session:
                session.add(analysis)
                # Actualizar el flag en la entrada
                from sqlalchemy import update
                await session.execute(
                    update(TrafficEntry).where(TrafficEntry.id == entry.id).values(is_analyzed=True)
                )
                await session.commit()
                await session.refresh(analysis)
                return analysis

    async def analyze_batch(
        self,
        entries: List[TrafficEntry],
        db: Optional[AsyncSession] = None
    ) -> List[AIAnalysis]:
        """
        Analiza un lote de entradas de tráfico HTTP secuencialmente, reutilizando la caché y acumulando resultados.

        :param entries: Lista de entradas TrafficEntry
        :param db: Sesión asíncrona de base de datos
        :return: Lista de objetos AIAnalysis generados
        """
        results: List[AIAnalysis] = []
        for entry in entries:
            try:
                res = await self.analyze_traffic_entry(entry, db=db)
                if res is not None:
                    results.append(res)
            except Exception as exc:
                logger.error(f"Error analizando entrada {entry.id} en lote: {exc}")
        return results


# Instancia singleton del analizador
_analyzer_instance: Optional[SecurityAnalyzer] = None


def get_analyzer() -> SecurityAnalyzer:
    """Función de acceso al analizador de seguridad singleton."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = SecurityAnalyzer()
    return _analyzer_instance
