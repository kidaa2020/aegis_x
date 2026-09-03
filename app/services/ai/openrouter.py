"""
Cliente asíncrono para la API de OpenRouter.
Gestiona la comunicación con modelos de lenguaje avanzados, rastrea el consumo de tokens,
implementa reintentos y maneja excepciones de autenticación y límites de tasa (Rate Limit).
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import aiohttp

from app.core.config import settings

logger = logging.getLogger(__name__)


class OpenRouterError(Exception):
    """Excepción base para errores relacionados con la API de OpenRouter."""
    pass


class OpenRouterAuthError(OpenRouterError):
    """Excepción para errores de autenticación (HTTP 401)."""
    pass


class OpenRouterRateLimitError(OpenRouterError):
    """Excepción para límites de tasa excedidos (HTTP 429)."""
    pass


class OpenRouterAPIError(OpenRouterError):
    """Excepción para fallos del servidor o respuestas no exitosas del modelo."""
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        self.message = message
        super().__init__(f"OpenRouter API Error [{status_code}]: {message}")


class OpenRouterClient:
    """
    Cliente HTTP asíncrono para interactuar con la pasarela de inferencia OpenRouter.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        max_tokens: Optional[int] = None,
        timeout: Optional[int] = None
    ) -> None:
        self.api_key: str = api_key or settings.OPENROUTER_API_KEY
        self.model: str = model or settings.OPENROUTER_MODEL
        self.base_url: str = (base_url or settings.OPENROUTER_BASE_URL).rstrip("/")
        self.max_tokens: int = max_tokens or settings.OPENROUTER_MAX_TOKENS
        self.timeout: int = timeout or settings.OPENROUTER_TIMEOUT

        # Métricas de consumo acumuladas
        self._total_prompt_tokens: int = 0
        self._total_completion_tokens: int = 0
        self._total_requests: int = 0
        self._failed_requests: int = 0

    @property
    def endpoint_url(self) -> str:
        """URL completa del endpoint de chat completions."""
        return f"{self.base_url}/chat/completions"

    def _get_headers(self) -> Dict[str, str]:
        """Construye las cabeceras HTTP necesarias para OpenRouter."""
        headers = {
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/recon-platform/kali-audit",
            "X-Title": "Kali Recon Security Audit Platform",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def chat(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        model: Optional[str] = None,
        response_format: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Envía una solicitud de chat completions al modelo de IA configurado en OpenRouter.

        :param messages: Lista de mensajes estructurados (role: system/user/assistant, content: str)
        :param max_tokens: Límite de tokens para la respuesta (opcional)
        :param temperature: Grado de aleatoriedad (0.0 más determinista)
        :param model: Sobrescribir el modelo por defecto para esta petición
        :param response_format: Especificación de formato (e.g. {"type": "json_object"})
        :return: Diccionario con la respuesta completa del modelo y metadatos de uso.
        """
        if not self.api_key:
            logger.warning("OPENROUTER_API_KEY no está configurada. Operando en modo simulado o restringido.")

        target_model = model or self.model
        payload: Dict[str, Any] = {
            "model": target_model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature if temperature is not None else settings.OPENROUTER_TEMPERATURE,
        }

        if response_format:
            payload["response_format"] = response_format

        headers = self._get_headers()
        client_timeout = aiohttp.ClientTimeout(total=self.timeout)

        self._total_requests += 1

        try:
            async with aiohttp.ClientSession(timeout=client_timeout) as session:
                async with session.post(self.endpoint_url, headers=headers, json=payload) as response:
                    status = response.status
                    text_resp = await response.text()

                    # 1. Manejo de autenticación inválida
                    if status == 401:
                        self._failed_requests += 1
                        logger.error(f"Error de autenticación 401 en OpenRouter: {text_resp}")
                        raise OpenRouterAuthError("Clave de API de OpenRouter inválida o ausente (401 Unauthorized).")

                    # 2. Manejo de límite de peticiones (Rate Limit)
                    elif status == 429:
                        self._failed_requests += 1
                        logger.warning(f"Límite de tasa (Rate Limit) alcanzado en OpenRouter (429): {text_resp}")
                        raise OpenRouterRateLimitError("Límite de peticiones excedido en OpenRouter (429 Too Many Requests).")

                    # 3. Manejo de otros errores HTTP
                    elif status != 200:
                        self._failed_requests += 1
                        logger.error(f"Error HTTP {status} recibido de OpenRouter: {text_resp}")
                        raise OpenRouterAPIError(status_code=status, message=text_resp)

                    # 4. Procesamiento exitoso de la respuesta JSON
                    data: Dict[str, Any] = await response.json()
                    
                    # Registro y actualización de métricas de tokens
                    usage = data.get("usage", {})
                    p_tokens = usage.get("prompt_tokens", 0)
                    c_tokens = usage.get("completion_tokens", 0)
                    self._total_prompt_tokens += p_tokens
                    self._total_completion_tokens += c_tokens

                    logger.info(
                        f"Solicitud completada en OpenRouter. Modelo: {target_model} | "
                        f"Prompt tokens: {p_tokens} | Completion tokens: {c_tokens}"
                    )
                    return data

        except aiohttp.ClientConnectorError as exc:
            self._failed_requests += 1
            logger.error(f"Error de conexión con OpenRouter ({self.endpoint_url}): {exc}")
            raise OpenRouterError(f"No fue posible conectar con el servidor de OpenRouter: {exc}")
        except asyncio.TimeoutError:
            self._failed_requests += 1
            logger.error(f"Tiempo de espera agotado ({self.timeout}s) en la llamada a OpenRouter.")
            raise OpenRouterError(f"Tiempo de espera agotado al consultar OpenRouter tras {self.timeout} segundos.")
        except (OpenRouterError, OpenRouterAuthError, OpenRouterRateLimitError, OpenRouterAPIError):
            raise
        except Exception as exc:
            self._failed_requests += 1
            logger.error(f"Excepción no esperada al invocar OpenRouter: {exc}", exc_info=True)
            raise OpenRouterError(f"Error interno durante la llamada a OpenRouter: {exc}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Retorna las estadísticas acumuladas de consumo de tokens y solicitudes.
        """
        total_tok = self._total_prompt_tokens + self._total_completion_tokens
        return {
            "model": self.model,
            "total_requests": self._total_requests,
            "failed_requests": self._failed_requests,
            "prompt_tokens": self._total_prompt_tokens,
            "completion_tokens": self._total_completion_tokens,
            "total_tokens": total_tok,
        }

    def reset_stats(self) -> None:
        """Reinicia los contadores de métricas."""
        self._total_prompt_tokens = 0
        self._total_completion_tokens = 0
        self._total_requests = 0
        self._failed_requests = 0


# Instancia única (Singleton)
_openrouter_client_instance: Optional[OpenRouterClient] = None


def get_client() -> OpenRouterClient:
    """
    Función de acceso Singleton al cliente de OpenRouter.
    """
    global _openrouter_client_instance
    if _openrouter_client_instance is None:
        _openrouter_client_instance = OpenRouterClient()
    return _openrouter_client_instance
