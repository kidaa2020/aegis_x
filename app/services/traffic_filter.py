"""
Módulo alias para compatibilidad y exportación directa de TrafficFilter y utilidades de filtrado.
"""

from app.services.traffic.filter import (
    STATIC_EXTENSIONS,
    STATIC_CONTENT_TYPES,
    should_analyze,
    extract_param_names_from_query_string,
    extract_param_names_from_json_body,
    extract_param_names,
    deduplicate_key,
    DeduplicationCache,
    TrafficFilter
)

__all__ = [
    "STATIC_EXTENSIONS",
    "STATIC_CONTENT_TYPES",
    "should_analyze",
    "extract_param_names_from_query_string",
    "extract_param_names_from_json_body",
    "extract_param_names",
    "deduplicate_key",
    "DeduplicationCache",
    "TrafficFilter",
]
