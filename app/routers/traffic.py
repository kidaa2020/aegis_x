"""
Router de FastAPI para ingesta y consulta de tráfico HTTP interceptado.
Endpoints bajo el prefijo /api/traffic para comunicación con la extensión de Burp Suite
y el dashboard de auditoría.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.traffic import TrafficEntry
from app.schemas.traffic import (
    TrafficIngestRequest,
    TrafficEntryDetailResponse,
    TrafficEntrySummaryResponse,
    TrafficListResponse,
)
from app.services.traffic.collector import collector
from app.services.traffic.filter import should_analyze
from app.services.websocket import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/traffic", tags=["Tráfico HTTP"])


@router.post(
    "/ingest",
    response_model=TrafficEntryDetailResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingesta de tráfico HTTP desde Burp Suite"
)
async def ingest_traffic(
    payload: TrafficIngestRequest,
    db: AsyncSession = Depends(get_db)
) -> TrafficEntryDetailResponse:
    """
    Recibe una transacción HTTP (petición/respuesta) enviada desde la extensión de Burp Suite,
    extrae y clasifica sus parámetros, aplica filtros heurísticos y la almacena en la base de datos.
    Posteriormente emite una notificación en tiempo real a través del WebSocket.
    """
    try:
        data_dict = payload.model_dump()
        entry = await collector.process_entry(data=data_dict, db=db)

        # Transmisión en tiempo real vía WebSocket a la interfaz de usuario
        ws_payload = {
            "id": entry.id,
            "target_id": entry.target_id,
            "method": entry.method,
            "url": entry.url,
            "host": entry.host,
            "path": entry.path,
            "status_code": entry.status_code,
            "content_type": entry.content_type,
            "is_analyzable": entry.is_analyzable,
            "is_analyzed": entry.is_analyzed,
            "created_at": entry.created_at.isoformat() if entry.created_at else None
        }
        await ws_manager.broadcast_traffic(ws_payload)

        return entry
    except ValueError as val_err:
        logger.warning(f"Error de validación en la ingesta de tráfico: {val_err}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        logger.error(f"Error interno durante la ingesta de tráfico: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error interno procesando la captura de tráfico: {exc}"
        )


@router.get(
    "/entries/{target_id}",
    response_model=TrafficListResponse,
    summary="Listar tráfico HTTP de un objetivo específico"
)
async def list_traffic_entries(
    target_id: int,
    page: int = Query(1, ge=1, description="Número de página"),
    page_size: int = Query(50, ge=1, le=200, description="Tamaño de la página"),
    method: Optional[str] = Query(None, description="Filtrar por método HTTP (GET, POST, etc.)"),
    status_code: Optional[int] = Query(None, description="Filtrar por código de estado HTTP"),
    search: Optional[str] = Query(None, description="Búsqueda por texto en URL o ruta"),
    only_analyzable: Optional[bool] = Query(None, description="Filtrar solo entradas analizables"),
    is_analyzed: Optional[bool] = Query(None, description="Filtrar por estado de análisis IA"),
    db: AsyncSession = Depends(get_db)
) -> TrafficListResponse:
    """
    Obtiene una lista paginada del tráfico interceptado perteneciente a un objetivo (target_id),
    con opciones de filtrado avanzado por método, código de respuesta, ruta y estado de análisis.
    """
    try:
        # Construcción dinámica de filtros
        filters = [TrafficEntry.target_id == target_id]

        if method:
            filters.append(TrafficEntry.method == method.upper().strip())
        if status_code is not None:
            filters.append(TrafficEntry.status_code == status_code)
        if search:
            filters.append(TrafficEntry.url.ilike(f"%{search.strip()}%"))
        if only_analyzable is not None:
            filters.append(TrafficEntry.is_analyzable == only_analyzable)
        if is_analyzed is not None:
            filters.append(TrafficEntry.is_analyzed == is_analyzed)

        # Conteo total de elementos que coinciden con los filtros
        count_query = select(func.count(TrafficEntry.id)).where(*filters)
        total_res = await db.execute(count_query)
        total_items = total_res.scalar_one() or 0

        # Consulta paginada ordenada por fecha descendente
        offset = (page - 1) * page_size
        items_query = (
            select(TrafficEntry)
            .where(*filters)
            .order_by(desc(TrafficEntry.created_at))
            .offset(offset)
            .limit(page_size)
        )
        items_res = await db.execute(items_query)
        items = items_res.scalars().all()

        return TrafficListResponse(
            total=total_items,
            page=page,
            page_size=page_size,
            items=[TrafficEntrySummaryResponse.model_validate(item) for item in items]
        )
    except Exception as exc:
        logger.error(f"Error al listar tráfico para el objetivo {target_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al consultar el tráfico del objetivo: {exc}"
        )


@router.get(
    "/entry/{entry_id}",
    response_model=TrafficEntryDetailResponse,
    summary="Obtener el detalle completo de una petición HTTP"
)
async def get_traffic_entry(
    entry_id: int,
    db: AsyncSession = Depends(get_db)
) -> TrafficEntryDetailResponse:
    """
    Recupera la información exhaustiva de una transacción HTTP específica,
    incluyendo cabeceras completas de petición/respuesta, cuerpos y parámetros clasificados.
    """
    query = select(TrafficEntry).where(TrafficEntry.id == entry_id)
    result = await db.execute(query)
    entry = result.scalar_one_or_none()

    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró ninguna entrada de tráfico con ID {entry_id}."
        )

    return entry
