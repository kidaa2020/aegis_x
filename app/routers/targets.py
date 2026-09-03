"""
Enrutador de API para la gestión de objetivos (Targets).
Prefijo de ruta: /api/targets
Proporciona endpoints CRUD para crear, listar, consultar detalles y eliminar objetivos de auditoría.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Target
from app.schemas import TargetCreate, TargetDetailResponse, TargetResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/targets", tags=["Objetivos"])


@router.get(
    "/",
    response_model=list[TargetResponse],
    summary="Listar todos los objetivos",
)
async def list_targets(
    db: AsyncSession = Depends(get_db),
) -> list[TargetResponse]:
    """
    Retorna la lista completa de objetivos registrados en la plataforma.
    """
    stmt = select(Target).order_by(Target.created_at.desc())
    result = await db.scalars(stmt)
    targets = result.all()
    return list(targets)


@router.post(
    "/",
    response_model=TargetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un nuevo objetivo",
)
async def create_target(
    payload: TargetCreate,
    db: AsyncSession = Depends(get_db),
) -> TargetResponse:
    """
    Crea y registra un nuevo dominio objetivo para posteriores auditorías de seguridad.
    """
    clean_domain = payload.domain.strip().lower()
    if not clean_domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de dominio no puede estar vacío.",
        )

    # Crear la instancia del modelo ORM
    new_target = Target(
        domain=clean_domain,
        notes=payload.notes.strip() if payload.notes else "",
    )
    db.add(new_target)
    await db.commit()
    await db.refresh(new_target)

    logger.info("Nuevo objetivo registrado: %s (ID: %d)", new_target.domain, new_target.id)
    return new_target


@router.get(
    "/{target_id}",
    response_model=TargetDetailResponse,
    summary="Obtener detalle de un objetivo",
)
async def get_target_detail(
    target_id: int,
    db: AsyncSession = Depends(get_db),
) -> TargetDetailResponse:
    """
    Recupera los datos de un objetivo específico incluyendo todos sus datos relacionados
    (subdominios, puertos, tecnologías y análisis JS).
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

    return target


@router.delete(
    "/{target_id}",
    status_code=status.HTTP_200_OK,
    summary="Eliminar un objetivo",
)
async def delete_target(
    target_id: int,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """
    Elimina un objetivo y todos sus registros asociados mediante borrado en cascada.
    """
    target = await db.get(Target, target_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Objetivo con ID {target_id} no encontrado.",
        )

    domain_name = target.domain
    await db.delete(target)
    await db.commit()

    logger.info("Objetivo eliminado: %s (ID: %d) con todos sus datos asociados.", domain_name, target_id)
    return {
        "status": "success",
        "message": f"Objetivo '{domain_name}' y todos sus datos vinculados fueron eliminados exitosamente.",
    }
