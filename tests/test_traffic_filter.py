"""
Pruebas unitarias para el servicio de filtrado y deduplicación de tráfico HTTP (traffic_filter).
Verifica el descarte de recursos estáticos, la extracción de parámetros (query y json)
y la correcta identificación de estructuras duplicadas mediante hashes canónicos.
"""

import pytest
from app.services.traffic.filter import (
    should_analyze,
    extract_param_names_from_query_string,
    extract_param_names_from_json_body,
    extract_param_names,
    deduplicate_key,
    DeduplicationCache,
    TrafficFilter
)


def test_should_analyze_ignores_static_files() -> None:
    """
    Verifica que should_analyze descarte extensiones estáticas comunes
    (imágenes, estilos CSS, scripts estáticos, fuentes, documentos) independientemente
    de parámetros de consulta (query strings) o mayúsculas/minúsculas.
    """
    static_urls = [
        "https://example.com/assets/bundle.js",
        "https://example.com/static/style.css?v=2.1.0",
        "https://example.com/images/logo.png",
        "https://example.com/avatar.JPG",
        "https://example.com/icons/favicon.ico",
        "https://example.com/fonts/roboto.woff2",
        "https://example.com/vector/icon.svg#layer1",
        "https://example.com/assets/app.js.map",
        "https://example.com/fonts/glyphicons.ttf",
        "https://example.com/media/intro.mp4",
        "https://example.com/docs/manual.pdf",
    ]

    for url in static_urls:
        assert should_analyze(method="GET", url=url) is False, f"La URL estática {url} no debió ser analizada"

    # Verificación por Content-Type estático
    assert should_analyze(method="GET", url="https://example.com/asset-download", content_type="image/png") is False
    assert should_analyze(method="GET", url="https://example.com/theme", content_type="text/css") is False
    assert should_analyze(method="OPTIONS", url="https://example.com/api/v1/users") is False


def test_should_analyze_allows_api_endpoints() -> None:
    """
    Verifica que should_analyze acepte y marque como analizables endpoints de API,
    vistas dinámicas, formularios y endpoints con contenido JSON/HTML/XML.
    """
    api_urls = [
        ("GET", "https://example.com/api/v1/users", "application/json"),
        ("POST", "https://example.com/api/auth/login", "application/json"),
        ("PUT", "https://example.com/api/v1/profile/123", "application/json"),
        ("DELETE", "https://example.com/api/v1/items/456", "application/json"),
        ("GET", "https://example.com/dashboard/settings", "text/html"),
        ("POST", "https://example.com/graphql", "application/json"),
        ("GET", "https://example.com/search?q=security&page=1", "text/html"),
        ("POST", "https://example.com/checkout/pay", "application/x-www-form-urlencoded"),
    ]

    for method, url, content_type in api_urls:
        assert should_analyze(method=method, url=url, content_type=content_type) is True, (
            f"El endpoint dinámico {method} {url} debió ser admitido para análisis"
        )


def test_deduplicate_key_same_structure() -> None:
    """
    Verifica que dos solicitudes con el mismo método, la misma ruta y los mismos nombres de parámetros
    (pero con distintos valores de parámetros) generen exactamente la MISMA clave de deduplicación.
    """
    # Caso 1: Mismo endpoint y mismos query params con valores diferentes y en distinto orden
    url_a = "https://example.com/api/v1/search?category=books&page=1&limit=20"
    url_b = "https://example.com/api/v1/search?limit=50&category=electronics&page=3"

    key_a = deduplicate_key(method="GET", url=url_a)
    key_b = deduplicate_key(method="GET", url=url_b)

    assert key_a == key_b, "Solicitudes con la misma estructura deben generar la misma clave de deduplicación"

    # Caso 2: Peticiones POST con los mismos campos JSON pero distintos valores
    body_1 = '{"user_id": 101, "role": "admin", "active": true}'
    body_2 = '{"role": "viewer", "active": false, "user_id": 999}'

    key_post_1 = deduplicate_key(method="POST", url="https://example.com/api/users", body=body_1)
    key_post_2 = deduplicate_key(method="POST", url="https://example.com/api/users", body=body_2)

    assert key_post_1 == key_post_2, "Cuerpos JSON con los mismos nombres de claves deben compartir clave"


def test_deduplicate_key_different_structure() -> None:
    """
    Verifica que peticiones con métodos diferentes, rutas distintas o conjuntos de parámetros
    diferentes produzcan claves de deduplicación DIFERENTES.
    """
    url_base = "https://example.com/api/items"

    # Métodos distintos
    key_get = deduplicate_key(method="GET", url=url_base)
    key_post = deduplicate_key(method="POST", url=url_base)
    assert key_get != key_post, "GET y POST deben tener claves distintas"

    # Rutas distintas
    key_route1 = deduplicate_key(method="GET", url="https://example.com/api/items")
    key_route2 = deduplicate_key(method="GET", url="https://example.com/api/orders")
    assert key_route1 != key_route2, "Rutas distintas deben tener claves distintas"

    # Parámetros distintos
    key_params1 = deduplicate_key(method="GET", url="https://example.com/api/search?q=test")
    key_params2 = deduplicate_key(method="GET", url="https://example.com/api/search?q=test&filter=active")
    assert key_params1 != key_params2, "Diferentes parámetros deben generar claves distintas"


def test_extract_param_names_from_query_string() -> None:
    """
    Verifica la extracción precisa, normalización y ordenamiento alfabético de los nombres
    de parámetros de una Query String.
    """
    # Query string aislada
    qs = "sort=desc&filter=active&page=2&filter=inactive"
    params = extract_param_names_from_query_string(qs)
    assert params == ["filter", "page", "sort"]

    # URL completa con query string y valores codificados
    url = "https://target.local/api/search?query=hello%20world&limit=10&offset=0&token=xyz123"
    params_url = extract_param_names_from_query_string(url)
    assert params_url == ["limit", "offset", "query", "token"]

    # Cadena vacía o sin parámetros
    assert extract_param_names_from_query_string("") == []
    assert extract_param_names_from_query_string("https://target.local/api/status") == []


def test_extract_param_names_from_json_body() -> None:
    """
    Verifica la extracción de claves desde cuerpos JSON, incluyendo objetos planos,
    estructuras anidadas y listas.
    """
    # JSON plano
    json_flat = '{"username": "admin", "password": "secretPassword!", "remember": true}'
    flat_params = extract_param_names_from_json_body(json_flat)
    assert flat_params == ["password", "remember", "username"]

    # JSON anidado (soporte para claves compuestas)
    json_nested = {
        "user": {
            "name": "Alice",
            "profile": {
                "age": 30
            }
        },
        "role_id": 5
    }
    nested_params = extract_param_names_from_json_body(json_nested)
    assert "role_id" in nested_params
    assert "user" in nested_params
    assert "user.name" in nested_params
    assert "user.profile.age" in nested_params

    # Entrada no JSON o inválida
    assert extract_param_names_from_json_body("") == []
    assert extract_param_names_from_json_body("invalid plain string not json") == []


def test_deduplication_cache_detects_duplicates() -> None:
    """
    Verifica que DeduplicationCache detecte correctamente firmas ya observadas,
    permita nuevas claves y mantenga la coherencia en consultas repetidas.
    """
    cache = DeduplicationCache(max_size=100)
    filter_service = TrafficFilter()

    key_1 = deduplicate_key(method="GET", url="https://example.com/api/test?id=1")
    key_2 = deduplicate_key(method="GET", url="https://example.com/api/test?id=2") # Misma estructura
    key_3 = deduplicate_key(method="POST", url="https://example.com/api/test")      # Otra estructura

    # key_1 y key_2 son idénticas estructuralmente
    assert key_1 == key_2

    # Inicialmente no es duplicado
    assert cache.is_duplicate(key_1) is False
    assert cache.check_and_add(key_1) is False # Se agregó exitosamente

    # La segunda comprobación de la misma clave debe marcarse como duplicado
    assert cache.is_duplicate(key_1) is True
    assert cache.is_duplicate(key_2) is True
    assert cache.check_and_add(key_2) is True  # Ya existía

    # key_3 es nueva y no debe ser detectada como duplicado aún
    assert cache.is_duplicate(key_3) is False
    assert cache.check_and_add(key_3) is False

    # Probar a través del servicio de alto nivel TrafficFilter
    assert filter_service.is_duplicate(key_1) is False
    assert filter_service.check_and_add(key_1) is False
    assert filter_service.check_and_add(key_2) is True
