"""
Enrutador de API para la ejecución de módulos de reconocimiento y auditoría de seguridad.
Prefijo de ruta: /api/recon
Permite lanzar tareas en segundo plano (BackgroundTasks), almacenar resultados en la base de datos
y notificar el estado y hallazgos en tiempo real a través de WebSockets.
"""

import logging
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db, get_db_context
from app.models import JsAnalysis, PortResult, Subdomain, Target, Technology
from app.schemas import PortScanRequest, ReconResultsResponse, TaskTriggerResponse
from app.services.recon.js_analyzer import analyze_js_files
from app.services.recon.ports import scan_ports
from app.services.recon.subdomains import enumerate_subdomains
from app.services.recon.tech_detect import detect_technologies
from app.websocket import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/recon", tags=["Reconocimiento"])


# ============================================================================
# TAREAS EN SEGUNDO PLANO (BACKGROUND TASKS)
# ============================================================================

async def _task_enumerate_subdomains(target_id: int, domain: str) -> None:
    """
    Tarea en segundo plano para descubrir subdominios y persistirlos en la base de datos.
    """
    logger.info("Iniciando tarea de subdominios para Target #%d (%s)", target_id, domain)
    await ws_manager.broadcast_target_event(
        target_id=target_id,
        scan_type="subdomains",
        status="in_progress",
        message=f"Iniciando descubrimiento de subdominios para {domain}",
    )

    try:
        discovered = await enumerate_subdomains(domain)

        async with get_db_context() as session:
            # Eliminar registros previos para refrescar resultados del objetivo
            stmt_delete = select(Subdomain).where(Subdomain.target_id == target_id)
            existing = await session.scalars(stmt_delete)
            for old_item in existing.all():
                await session.delete(old_item)

            # Insertar nuevos subdominios encontrados
            for item in discovered:
                sub_record = Subdomain(
                    target_id=target_id,
                    subdomain=item["subdomain"],
                    ip=item.get("ip"),
                )
                session.add(sub_record)

            await session.commit()

        logger.info("Descubrimiento de subdominios completado para %s: %d hallados", domain, len(discovered))
        await ws_manager.broadcast_target_event(
            target_id=target_id,
            scan_type="subdomains",
            status="completed",
            data={"count": len(discovered), "results": discovered},
            message=f"Enumeración finalizada. Se encontraron {len(discovered)} subdominios.",
        )

    except Exception as exc:
        logger.error("Error en tarea de subdominios para Target #%d: %s", target_id, exc)
        await ws_manager.broadcast_target_event(
            target_id=target_id,
            scan_type="subdomains",
            status="failed",
            message=f"Error durante la enumeración de subdominios: {str(exc)}",
        )


async def _task_scan_ports(target_id: int, host: str, ports_range: str) -> None:
    """
    Tarea en segundo plano para escanear puertos y servicios con Nmap.
    """
    logger.info("Iniciando escaneo de puertos para Target #%d (%s) en rango %s", target_id, host, ports_range)
    await ws_manager.broadcast_target_event(
        target_id=target_id,
        scan_type="ports",
        status="in_progress",
        message=f"Iniciando escaneo de puertos en {host} (Rango: {ports_range})",
    )

    try:
        results = await scan_ports(host, ports=ports_range)

        async with get_db_context() as session:
            # Eliminar puertos previos del objetivo
            stmt_delete = select(PortResult).where(PortResult.target_id == target_id)
            existing = await session.scalars(stmt_delete)
            for old_item in existing.all():
                await session.delete(old_item)

            for port_data in results:
                port_record = PortResult(
                    target_id=target_id,
                    port=port_data["port"],
                    protocol=port_data.get("protocol", "tcp"),
                    state=port_data.get("state", "open"),
                    service=port_data.get("service", "unknown"),
                    banner=port_data.get("banner", "") or port_data.get("version", ""),
                )
                session.add(port_record)

            await session.commit()

        logger.info("Escaneo de puertos completado para %s: %d puertos abiertos", host, len(results))
        await ws_manager.broadcast_target_event(
            target_id=target_id,
            scan_type="ports",
            status="completed",
            data={"count": len(results), "results": results},
            message=f"Escaneo de puertos finalizado. Se detectaron {len(results)} servicios activos.",
        )

    except Exception as exc:
        logger.error("Error en tarea de escaneo de puertos para Target #%d: %s", target_id, exc)
        await ws_manager.broadcast_target_event(
            target_id=target_id,
            scan_type="ports",
            status="failed",
            message=f"Error durante el escaneo de puertos: {str(exc)}",
        )


async def _task_detect_technologies(target_id: int, domain: str) -> None:
    """
    Tarea en segundo plano para fingerprinting y detección de tecnologías web.
    """
    logger.info("Iniciando detección de tecnologías para Target #%d (%s)", target_id, domain)
    await ws_manager.broadcast_target_event(
        target_id=target_id,
        scan_type="technologies",
        status="in_progress",
        message=f"Identificando stack tecnológico en {domain}",
    )

    try:
        results = await detect_technologies(domain)

        async with get_db_context() as session:
            # Limpiar tecnologías previas
            stmt_delete = select(Technology).where(Technology.target_id == target_id)
            existing = await session.scalars(stmt_delete)
            for old_item in existing.all():
                await session.delete(old_item)

            for tech_data in results:
                tech_record = Technology(
                    target_id=target_id,
                    name=tech_data["name"],
                    version=tech_data.get("version"),
                    category=tech_data.get("category", "General"),
                )
                session.add(tech_record)

            await session.commit()

        logger.info("Detección de tecnologías completada para %s: %d identificadas", domain, len(results))
        await ws_manager.broadcast_target_event(
            target_id=target_id,
            scan_type="technologies",
            status="completed",
            data={"count": len(results), "results": results},
            message=f"Detección tecnológica completada. Se identificaron {len(results)} tecnologías.",
        )

    except Exception as exc:
        logger.error("Error en tarea de tecnologías para Target #%d: %s", target_id, exc)
        await ws_manager.broadcast_target_event(
            target_id=target_id,
            scan_type="technologies",
            status="failed",
            message=f"Error durante la detección de tecnologías: {str(exc)}",
        )


async def _task_analyze_js(target_id: int, domain: str) -> None:
    """
    Tarea en segundo plano para análisis estático de archivos JavaScript.
    """
    logger.info("Iniciando análisis de JavaScript para Target #%d (%s)", target_id, domain)
    await ws_manager.broadcast_target_event(
        target_id=target_id,
        scan_type="js_analysis",
        status="in_progress",
        message=f"Analizando archivos JavaScript en {domain}",
    )

    try:
        results = await analyze_js_files(domain)

        async with get_db_context() as session:
            # Limpiar análisis previos
            stmt_delete = select(JsAnalysis).where(JsAnalysis.target_id == target_id)
            existing = await session.scalars(stmt_delete)
            for old_item in existing.all():
                await session.delete(old_item)

            for js_data in results:
                js_record = JsAnalysis(
                    target_id=target_id,
                    url=js_data["url"],
                    endpoints=js_data.get("endpoints", []),
                    secrets=js_data.get("secrets", []) or js_data.get("sensitive_strings", []),
                    subdomains=js_data.get("subdomains", []) or js_data.get("referenced_hosts", []),
                )
                session.add(js_record)

            await session.commit()

        logger.info("Análisis de JavaScript completado para %s: %d scripts procesados", domain, len(results))
        await ws_manager.broadcast_target_event(
            target_id=target_id,
            scan_type="js_analysis",
            status="completed",
            data={"count": len(results), "results": results},
            message=f"Análisis JS completado. Se procesaron {len(results)} archivos JavaScript.",
        )

    except Exception as exc:
        logger.error("Error en tarea de análisis JS para Target #%d: %s", target_id, exc)
        await ws_manager.broadcast_target_event(
            target_id=target_id,
            scan_type="js_analysis",
            status="failed",
            message=f"Error durante el análisis de JavaScript: {str(exc)}",
        )


# ============================================================================
# ENDPOINTS DE API
# ============================================================================

@router.post(
    "/subdomains/{target_id}",
    response_model=TaskTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Iniciar enumeración de subdominios",
)
async def trigger_subdomains_scan(
    target_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> TaskTriggerResponse:
    """
    Lanza el proceso asíncrono de enumeración de subdominios para un objetivo específico.
    """
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Objetivo con ID {target_id} no encontrado.",
        )

    background_tasks.add_task(_task_enumerate_subdomains, target.id, target.domain)

    return TaskTriggerResponse(
        status="queued",
        message=f"Enumeración de subdominios encolada para {target.domain}",
        target_id=target.id,
        scan_type="subdomains",
    )


@router.post(
    "/ports/{target_id}",
    response_model=TaskTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Iniciar escaneo de puertos",
)
async def trigger_ports_scan(
    target_id: int,
    background_tasks: BackgroundTasks,
    payload: Optional[PortScanRequest] = None,
    db: AsyncSession = Depends(get_db),
) -> TaskTriggerResponse:
    """
    Lanza el escaneo de puertos y detección de versiones de servicio para un objetivo.
    """
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Objetivo con ID {target_id} no encontrado.",
        )

    ports_range = payload.ports if (payload and payload.ports) else "1-1000"
    background_tasks.add_task(_task_scan_ports, target.id, target.domain, ports_range)

    return TaskTriggerResponse(
        status="queued",
        message=f"Escaneo de puertos ({ports_range}) encolado para {target.domain}",
        target_id=target.id,
        scan_type="ports",
    )


@router.post(
    "/technologies/{target_id}",
    response_model=TaskTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Iniciar detección de tecnologías web",
)
async def trigger_tech_detect(
    target_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> TaskTriggerResponse:
    """
    Lanza la identificación de tecnologías, frameworks y servidores web del objetivo.
    """
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Objetivo con ID {target_id} no encontrado.",
        )

    background_tasks.add_task(_task_detect_technologies, target.id, target.domain)

    return TaskTriggerResponse(
        status="queued",
        message=f"Detección tecnológica encolada para {target.domain}",
        target_id=target.id,
        scan_type="technologies",
    )


@router.post(
    "/js-analysis/{target_id}",
    response_model=TaskTriggerResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Iniciar análisis de archivos JavaScript",
)
async def trigger_js_analysis(
    target_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> TaskTriggerResponse:
    """
    Lanza el análisis estático de scripts JavaScript para extraer rutas, API endpoints y secretos.
    """
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Objetivo con ID {target_id} no encontrado.",
        )

    background_tasks.add_task(_task_analyze_js, target.id, target.domain)

    return TaskTriggerResponse(
        status="queued",
        message=f"Análisis de JavaScript encolado para {target.domain}",
        target_id=target.id,
        scan_type="js_analysis",
    )


@router.get(
    "/results/{target_id}",
    response_model=ReconResultsResponse,
    summary="Consultar todos los resultados de reconocimiento",
)
async def get_target_recon_results(
    target_id: int,
    db: AsyncSession = Depends(get_db),
) -> ReconResultsResponse:
    """
    Recupera y consolida todos los hallazgos de reconocimiento asociados a un objetivo.
    """
    stmt = (
        select(Target)
        .options(
            selectinload(Target.subdomains),
            selectinload(Target.ports),
            selectinload(Target.technologies),
            selectinload(Target.js_analyses),
        )
        .where(Target.id == target_id)
    )
    result = await db.execute(stmt)
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Objetivo con ID {target_id} no encontrado.",
        )

    return ReconResultsResponse(
        target_id=target.id,
        domain=target.domain,
        total_subdomains=len(target.subdomains),
        total_open_ports=len(target.ports),
        total_technologies=len(target.technologies),
        total_js_files=len(target.js_analyses),
        subdomains=target.subdomains,
        ports=target.ports,
        technologies=target.technologies,
        js_analyses=target.js_analyses,
    )
