"""
Router de FastAPI para orquestación y consulta de análisis de seguridad con IA.
Endpoints bajo el prefijo /api/analysis para análisis bajo demanda, procesamiento por lotes,
consulta de resultados de auditoría y estadísticas de tokens/caché.
"""

import logging
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.traffic import TrafficEntry
from app.models.analysis import AIAnalysis
from app.schemas.analysis import AIAnalysisResponse, AnalysisStatsResponse
from app.services.ai.analyzer import get_analyzer, SecurityAnalyzer
from app.services.ai.openrouter import get_client, OpenRouterError, OpenRouterAuthError, OpenRouterRateLimitError
from app.services.ai.cache import get_ai_cache
from app.services.traffic.filter import dedup_cache
from app.services.websocket import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analysis", tags=["Análisis de Seguridad IA"])


@router.post(
    "/analyze/{entry_id}",
    response_model=AIAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Ejecutar análisis de seguridad bajo demanda para una petición HTTP"
)
async def analyze_entry(
    entry_id: int,
    force_refresh: bool = Query(False, description="Forzar reanálisis omitiendo la caché"),
    db: AsyncSession = Depends(get_db)
) -> AIAnalysisResponse:
    """
    Ejecuta el análisis de vulnerabilidades y riesgos con Inteligencia Artificial
    para una entrada de tráfico específica (botón de análisis bajo demanda).
    Emite el resultado en tiempo real a los clientes WebSocket conectados.
    """
    # 1. Recuperar la entrada de tráfico
    query = select(TrafficEntry).where(TrafficEntry.id == entry_id)
    result = await db.execute(query)
    entry = result.scalar_one_or_none()

    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró ninguna entrada de tráfico con ID {entry_id}."
        )

    analyzer: SecurityAnalyzer = get_analyzer()

    try:
        analysis = await analyzer.analyze_traffic_entry(
            entry=entry,
            db=db,
            force_refresh=force_refresh
        )

        if not analysis:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La entrada de tráfico no cumple los criterios heurísticos para análisis (recurso estático o no analizable)."
            )

        # Transmitir el resultado en vivo vía WebSocket
        ws_data = {
            "id": analysis.id,
            "traffic_entry_id": analysis.traffic_entry_id,
            "target_id": analysis.target_id,
            "risk_category": analysis.risk_category,
            "risk_classification": analysis.risk_classification,
            "parameters_detected": analysis.parameters_detected,
            "reflected_parameters": analysis.reflected_parameters,
            "total_tokens": analysis.total_tokens,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None
        }
        await ws_manager.broadcast_analysis(ws_data)

        return analysis

    except OpenRouterAuthError as auth_err:
        logger.error(f"Error de autenticación con OpenRouter: {auth_err}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Error de autenticación con la API de OpenRouter. Verifique OPENROUTER_API_KEY."
        )
    except OpenRouterRateLimitError as rate_err:
        logger.warning(f"Límite de tasa excedido en OpenRouter: {rate_err}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Límite de tasa excedido en OpenRouter. Intente nuevamente en unos instantes."
        )
    except OpenRouterError as or_err:
        logger.error(f"Error en servicio de IA: {or_err}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Fallo en la comunicación con el proveedor de IA: {or_err}"
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error inesperado durante el análisis de la entrada {entry_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno durante el análisis de seguridad: {exc}"
        )


@router.post(
    "/analyze-batch/{target_id}",
    response_model=List[AIAnalysisResponse],
    summary="Analizar todo el tráfico pendiente de un objetivo"
)
async def analyze_batch(
    target_id: int,
    limit: int = Query(25, ge=1, le=100, description="Cantidad máxima de peticiones a analizar en este lote"),
    db: AsyncSession = Depends(get_db)
) -> List[AIAnalysisResponse]:
    """
    Identifica todas las entradas de tráfico pendientes de análisis pertenecientes a un objetivo (target_id),
    las procesa por orden cronológico y almacena los resultados de auditoría generados por la IA.
    """
    # Buscar entradas analizables que aún no han sido procesadas
    query = (
        select(TrafficEntry)
        .where(
            TrafficEntry.target_id == target_id,
            TrafficEntry.is_analyzable == True,
            TrafficEntry.is_analyzed == False
        )
        .order_by(TrafficEntry.created_at.asc())
        .limit(limit)
    )
    result = await db.execute(query)
    entries = result.scalars().all()

    if not entries:
        return []

    analyzer = get_analyzer()
    analyses_generated: List[AIAnalysis] = []

    for entry in entries:
        try:
            analysis = await analyzer.analyze_traffic_entry(entry=entry, db=db)
            if analysis:
                analyses_generated.append(analysis)
                # Notificación individual por WebSocket
                await ws_manager.broadcast_analysis({
                    "id": analysis.id,
                    "traffic_entry_id": analysis.traffic_entry_id,
                    "target_id": analysis.target_id,
                    "risk_category": analysis.risk_category,
                    "parameters_detected": analysis.parameters_detected,
                    "total_tokens": analysis.total_tokens
                })
        except Exception as exc:
            logger.error(f"Fallo al analizar entrada {entry.id} en ejecución por lotes: {exc}")

    return analyses_generated


@router.get(
    "/results/{target_id}",
    response_model=List[AIAnalysisResponse],
    summary="Obtener todos los resultados de análisis de un objetivo"
)
async def get_results_by_target(
    target_id: int,
    risk_category: Optional[str] = Query(None, description="Filtrar por categoría de riesgo (Critical, High, Medium, Low, Info)"),
    db: AsyncSession = Depends(get_db)
) -> List[AIAnalysisResponse]:
    """
    Retorna la lista histórica de todos los análisis de seguridad generados para un objetivo,
    ordenados por fecha más reciente, con opción de filtro por severidad.
    """
    filters = [AIAnalysis.target_id == target_id]
    if risk_category:
        filters.append(AIAnalysis.risk_category == risk_category.capitalize().strip())

    query = (
        select(AIAnalysis)
        .where(*filters)
        .order_by(desc(AIAnalysis.created_at))
    )
    result = await db.execute(query)
    return result.scalars().all()


@router.get(
    "/result/{analysis_id}",
    response_model=AIAnalysisResponse,
    summary="Obtener el detalle de un resultado de análisis específico"
)
async def get_single_result(
    analysis_id: int,
    db: AsyncSession = Depends(get_db)
) -> AIAnalysisResponse:
    """
    Recupera el informe pormenorizado de un análisis de seguridad por su identificador único,
    incluyendo clasificación OWASP, remediación técnica y notas metodológicas de verificación.
    """
    query = select(AIAnalysis).where(AIAnalysis.id == analysis_id)
    result = await db.execute(query)
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró ningún análisis con ID {analysis_id}."
        )

    return analysis


@router.get(
    "/stats",
    response_model=AnalysisStatsResponse,
    summary="Estadísticas de consumo de tokens y rendimiento de caché"
)
async def get_analysis_stats() -> AnalysisStatsResponse:
    """
    Retorna las métricas globales del subsistema de Inteligencia Artificial:
    - Consumo acumulado de tokens (prompt, completion y total)
    - Peticiones exitosas y fallidas hacia OpenRouter
    - Aciertos y tasa de efectividad de la caché de análisis
    - Tamaño del registro de firmas deduplicadas en memoria
    """
    or_client = get_client()
    cache = get_ai_cache()

    return AnalysisStatsResponse(
        openrouter_stats=or_client.get_stats(),
        cache_stats=cache.get_stats(),
        dedup_cache_size=dedup_cache.size()
    )
