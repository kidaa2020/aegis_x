"""
Pruebas unitarias para el sistema de caché de análisis de Inteligencia Artificial (AICache).
Valida la consistencia de los hashes de caché, la independencia respecto a los valores
de los parámetros y la correcta discriminación ante firmas estructurales disímiles.
"""

from unittest.mock import AsyncMock, MagicMock
import pytest
from app.services.ai.cache import generate_hash, AICache


def test_generate_hash_consistent() -> None:
    """
    Verifica que la función generate_hash produzca de manera determinista y repetible
    el mismo hash SHA-256 cuando se invoca múltiples veces con los mismos parámetros de entrada.
    """
    method = "GET"
    url = "https://app.target.com/api/v1/users?role=admin&status=active&page=1"
    
    hash_1 = generate_hash(method=method, url=url)
    hash_2 = generate_hash(method=method, url=url)
    hash_3 = generate_hash(method=method, url=url)

    assert isinstance(hash_1, str)
    assert len(hash_1) == 64, "El hash debe ser un SHA-256 de 64 caracteres hexadecimales"
    assert hash_1 == hash_2 == hash_3, "Llamadas repetidas con los mismos parámetros deben generar el mismo hash"

    # Verificación con llamada a través de la clase AICache
    hash_class = AICache.generate_hash(method=method, url=url)
    assert hash_class == hash_1


def test_generate_hash_ignores_values() -> None:
    """
    Verifica que el hash de caché sea agnóstico a los valores de los parámetros.
    Dos solicitudes al mismo endpoint con los mismos nombres de parámetros pero con
    valores completamente distintos o en orden alternado deben producir el MISMO hash.
    """
    # 1. Pruebas con Query Parameters
    url_req_a = "https://api.domain.com/v2/products?search=shoes&limit=10&page=1"
    url_req_b = "https://api.domain.com/v2/products?page=99&search=jackets&limit=500"

    hash_query_a = generate_hash(method="GET", url=url_req_a)
    hash_query_b = generate_hash(method="GET", url=url_req_b)

    assert hash_query_a == hash_query_b, (
        "El hash de caché debe ser idéntico independientemente del valor o el orden de los query parameters"
    )

    # 2. Pruebas con Cuerpo JSON (Body)
    body_payload_1 = '{"username": "john_doe", "email": "john@test.com", "role_id": 1}'
    body_payload_2 = '{"email": "attacker@evil.com", "role_id": 99, "username": "admin_super"}'

    hash_body_1 = generate_hash(method="POST", url="https://api.domain.com/auth/register", body=body_payload_1)
    hash_body_2 = generate_hash(method="POST", url="https://api.domain.com/auth/register", body=body_payload_2)

    assert hash_body_1 == hash_body_2, (
        "El hash de caché debe ser idéntico para cuerpos JSON con los mismos nombres de claves"
    )

    # 3. Pruebas con param_names explícitos
    hash_explicit_1 = generate_hash(method="POST", url="/login", param_names=["pass", "user"])
    hash_explicit_2 = generate_hash(method="POST", url="/login", param_names=["user", "pass"])

    assert hash_explicit_1 == hash_explicit_2


def test_generate_hash_different_params() -> None:
    """
    Verifica que solicitudes con conjuntos diferentes de parámetros, rutas diferentes o
    métodos HTTP distintos generen hashes de caché COMPLETAMENTE DISTINTOS.
    """
    base_url = "https://target.corp/api/data"

    # Diferencia por método HTTP
    hash_get = generate_hash(method="GET", url=base_url)
    hash_post = generate_hash(method="POST", url=base_url)
    assert hash_get != hash_post, "Métodos HTTP distintos deben producir hashes diferentes"

    # Diferencia por ruta (endpoint)
    hash_data = generate_hash(method="GET", url="https://target.corp/api/data")
    hash_users = generate_hash(method="GET", url="https://target.corp/api/users")
    assert hash_data != hash_users, "Rutas distintas deben producir hashes diferentes"

    # Diferencia por subconjunto o superconjunto de parámetros
    hash_subset = generate_hash(method="GET", url=f"{base_url}?user_id=10")
    hash_superset = generate_hash(method="GET", url=f"{base_url}?user_id=10&include_metadata=true")
    assert hash_subset != hash_superset, "Parámetros adicionales deben cambiar el hash de caché"


@pytest.mark.asyncio
async def test_ai_cache_service_mocked_db() -> None:
    """
    Verifica las operaciones del servicio AICache (get_entry y set_entry)
    utilizando un mock de la sesión de base de datos sin requerir una conexión SQLite real.
    """
    mock_db = AsyncMock()
    cache_service = AICache(db_session=mock_db)

    cache_hash = generate_hash(method="GET", url="https://api.target.com/info")
    analysis_payload = {
        "risk_category": "Medium",
        "risk_classification": {"OWASP": "A01:2021-Broken Access Control"},
        "remediation": "Validate authorization headers"
    }

    # Simular set_entry sin entrada previa (inserción nueva)
    mock_result_empty = MagicMock()
    mock_result_empty.scalar_one_or_none.return_value = None
    mock_db.execute.return_value = mock_result_empty

    entry_created = await cache_service.set_entry(
        cache_hash=cache_hash,
        endpoint_pattern="/info",
        analysis_data=analysis_payload
    )

    assert mock_db.add.called
    assert mock_db.commit.called
    assert entry_created is not None
    assert entry_created.cache_hash == cache_hash
    assert entry_created.analysis_data == analysis_payload

    # Simular get_entry con entrada existente (cache hit)
    mock_existing_entry = MagicMock()
    mock_existing_entry.cache_hash = cache_hash
    mock_existing_entry.hit_count = 1

    mock_result_found = MagicMock()
    mock_result_found.scalar_one_or_none.return_value = mock_existing_entry
    mock_db.execute.return_value = mock_result_found

    entry_fetched = await cache_service.get_entry(cache_hash)
    assert entry_fetched is not None
    assert entry_fetched.cache_hash == cache_hash
    assert entry_fetched.hit_count == 2
