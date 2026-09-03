"""
Plantillas de prompts estructurados para el motor de análisis de seguridad con IA.
Optimiza la concisión para minimizar el consumo de tokens y asegurar salidas estrictamente en JSON.
"""

import json
from typing import List, Dict, Any, Optional


def build_traffic_analysis_prompt(request_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Construye los mensajes para el análisis de seguridad de una transacción HTTP (petición/respuesta).
    
    :param request_data: Diccionario con la información formateada de la petición y respuesta HTTP.
    :return: Lista de mensajes (system y user) listos para la API de Chat Completions.
    """
    system_prompt = (
        "You are a web application security analyst. Analyze the following HTTP request/response "
        "and identify potential security risks. Focus on: 1) Parameter classification by OWASP categories, "
        "2) Risk assessment for each input field, 3) Recommended verification methodology, "
        "4) Defensive remediation. Respond in JSON format."
    )

    # Preparación de datos resumidos para evitar saturación de tokens
    method = request_data.get("method", "GET")
    url = request_data.get("url", "")
    params = request_data.get("params", {})
    headers_summary = request_data.get("headers_summary", {})
    status_code = request_data.get("status_code", 200)
    reflected_params = request_data.get("reflected_params", [])
    response_body_preview = request_data.get("response_body_preview", "")

    # Esquema JSON solicitado
    json_schema_guide = {
        "risk_category": "Critical | High | Medium | Low | Info | Safe",
        "risk_classification": {
            "owasp_top_10": ["e.g. A01:2021-Broken Access Control", "A03:2021-Injection"],
            "cwe_ids": ["CWE-89", "CWE-79"],
            "severity": "Critical | High | Medium | Low | Info",
            "confidence": "High | Medium | Low"
        },
        "parameters_detected": [
            {
                "name": "param_name",
                "location": "query | body | header | cookie",
                "category": "SQLi | XSS | SSRF | IDOR | Command Injection | Path Traversal | Auth | Business Logic | Other",
                "risk_level": "Critical | High | Medium | Low | Safe",
                "notes": "Brief technical analysis of this parameter vector",
                "is_reflected": False
            }
        ],
        "methodology_notes": "Step-by-step verification and manual audit guide for penetration testers.",
        "remediation": "Concrete defensive code fixes and hardening recommendations."
    }

    user_content = f"""HTTP TRANSACTION DETAILS:
- Method: {method}
- Target URL: {url}
- HTTP Status Code: {status_code}
- Extracted Parameters: {json.dumps(params, ensure_ascii=False)}
- Security Relevant Headers: {json.dumps(headers_summary, ensure_ascii=False)}
- Reflected Parameters Detected: {json.dumps(reflected_params, ensure_ascii=False)}
- Response Body Snippet:
```
{response_body_preview[:1500]}
```

OUTPUT REQUIREMENTS:
Return ONLY valid JSON matching this schema:
{json.dumps(json_schema_guide, indent=2)}"""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]


def build_js_analysis_prompt(js_findings: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Construye el prompt para auditar código JavaScript estático, extrayendo endpoints ocultos,
    claves de API, credenciales hardcodeadas y lógica sensible en el frontend.

    :param js_findings: Diccionario con URL del script JS, rutas descubiertas y extractos de código.
    :return: Lista de mensajes estructurados para el modelo de IA.
    """
    system_prompt = (
        "You are a web application security analyst specializing in JavaScript static analysis "
        "and client-side attack surface discovery. Analyze the provided JavaScript content, "
        "extracted endpoints, and potential secrets. Respond in JSON format."
    )

    source_url = js_findings.get("url", "unknown.js")
    extracted_endpoints = js_findings.get("endpoints", [])
    extracted_secrets = js_findings.get("potential_secrets", [])
    code_snippets = js_findings.get("code_snippets", [])

    schema_guide = {
        "discovered_endpoints": [
            {
                "path": "/api/v1/internal/admin",
                "method_hint": "POST",
                "sensitivity": "High | Medium | Low",
                "notes": "Internal management API found in JS bundle"
            }
        ],
        "discovered_secrets": [
            {
                "type": "API Key | JWT | Cloud Credential | Token | None",
                "evidence": "masked_snippet",
                "severity": "Critical | High | Medium | Low",
                "notes": "Potential hardcoded credential"
            }
        ],
        "sensitive_parameters": ["api_key", "secret_token", "admin_mode"],
        "client_side_risks": ["DOM XSS", "Sensitive data exposure in localStorage", "Insecure postMessage"],
        "risk_level": "Critical | High | Medium | Low | Safe",
        "remediation_notes": "Defensive guidance to remediate client-side exposures."
    }

    user_content = f"""JAVASCRIPT STATIC AUDIT DATA:
- Source JS File: {source_url}
- Candidate Endpoints / Routes Extracted: {json.dumps(extracted_endpoints, ensure_ascii=False)}
- Heuristic Secret Matches: {json.dumps(extracted_secrets, ensure_ascii=False)}
- Relevant Code Snippets:
```javascript
{str(code_snippets)[:2000]}
```

OUTPUT REQUIREMENTS:
Return ONLY a valid JSON object strictly complying with this structure:
{json.dumps(schema_guide, indent=2)}"""

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content}
    ]
