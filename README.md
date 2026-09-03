# Aegis_X - Plataforma de Auditoría Web Inteligente

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-CDN-38B2AC.svg)](https://tailwindcss.com/)

**Aegis_X** es una suite profesional y centralizada de reconocimiento y auditoría de seguridad web diseñada específicamente para entornos de pentesting (como Kali Linux). Integra herramientas clásicas de escaneo de superficie con captura de tráfico HTTP/HTTPS en tiempo real desde **Burp Suite** y un motor de clasificación y análisis de vulnerabilidades asistido por **Modelos de Lenguaje (LLMs / IA)** vía **OpenRouter**.

---

## 📸 Capturas de Pantalla (Screenshots)

### 1. Panel de Control y Métricas Globales
```
+-------------------------------------------------------------------------------+
|  Aegis_X | Targets | Reconocimiento | Tráfico | Análisis IA | Docs (OpenAPI)  |
+-------------------------------------------------------------------------------+
|  [ Objetivos: 12 ]   [ Subdominios: 148 ]   [ Tráfico: 1,820 ]   [ Hallazgos: 34 ] |
|                                                                               |
|  [ Resumen de Vulnerabilidades OWASP ]       [ Gráfico de Severidad de Riesgos ]  |
|  - A01 Broken Access Control (8)             - Crítico (2)                    |
|  - A03 Injection / SQLi (5)                  - Alto (7)                       |
|  - A07 Auth Failures (11)                    - Medio (14)                     |
+-------------------------------------------------------------------------------+
```

---

## ✨ Características Principales

- 🎯 **Gestión Integral de Objetivos (Targets)**: Creación, configuración de alcances (in-scope) y notas de auditoría.
- 🌐 **Reconocimiento Automatizado de Superficie**:
  - Descubrimiento de subdominios activo/pasivo mediante `subfinder`.
  - Detección de puertos y servicios abiertos con `nmap`.
  - Análisis estático de archivos JavaScript (`js_files`) para extracción de endpoints y secretos expuestos.
- 🔌 **Integración Burp Suite en Tiempo Real**:
  - Extensión en Jython (`burp_extension/recon_bridge.py`) que reenvía peticiones y respuestas directamente al dashboard sin latencia.
- ⚡ **Filtrado y Deduplicación Inteligente**:
  - Descarte automático de archivos estáticos (`.css`, `.js`, imágenes, fuentes, etc.).
  - Normalización y cálculo de hashes estructurales para evitar analizar peticiones redundantes.
- 🤖 **Motor de Auditoría con Inteligencia Artificial (OpenRouter API)**:
  - Clasificación OWASP Top 10 y mapeo CWE en parámetros sospechosos.
  - Generación de guías metodológicas paso a paso para pruebas de auditoría manuales y remediación técnica.
- 💾 **Caché Inteligente de IA**:
  - Hashes canónicos independientes de valores que reducen hasta un 80% el consumo de tokens y llamadas a la API.
- 📡 **WebSockets en Tiempo Real**: Notificaciones instantáneas de eventos de escaneo y nuevos hallazgos.
- 💻 **Interfaz Moderna y Responsiva**: Construida con FastAPI, Jinja2 y Tailwind CSS (dark mode).

---

## 📦 Requisitos del Sistema

- **Sistema Operativo**: Kali Linux (recomendado), Debian/Ubuntu, macOS o Windows.
- **Python**: Versión 3.11 o superior.
- **Herramientas del Sistema** (opcionales pero recomendadas para escaneo activo):
  - `nmap` (para escaneo de puertos y detección de versiones).
  - `subfinder` (para enumeración de subdominios).
- **Burp Suite**: Community o Professional Edition con soporte para Jython standalone JAR (2.7.x).

---

## 🚀 Guía de Instalación y Despliegue

### 1. Clonar el Repositorio
```bash
git clone https://github.com/tu-usuario/aegis_x.git
cd aegis_x
```

### 2. Crear y Activar un Entorno Virtual
```bash
python3 -m venv venv
# En Linux / Kali / macOS:
source venv/bin/activate
# En Windows (PowerShell):
.\venv\Scripts\Activate.ps1
```

### 3. Instalar Dependencias
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configurar Variables de Entorno
Crea un archivo `.env` en la raíz del proyecto a partir del siguiente ejemplo:
```env
APP_NAME=aegis_x
DATABASE_URL=sqlite+aiosqlite:///./aegis_x.db
OPENROUTER_API_KEY=sk-or-v1-tu-clave-aqui
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct:free
AI_CACHE_ENABLED=true
```

### 5. Iniciar la Plataforma
```bash
# Opción 1: Mediante el ejecutable run.py
python run.py

# Opción 2: Mediante uvicorn directamente
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Accede al panel web en tu navegador: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**  
Documentación interactiva de la API: **[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)**

---

## 🔑 Configuración de OpenRouter (Motor de IA)

Para habilitar el análisis inteligente de parámetros y categorización defensiva:

1. Obtén una clave de API en [OpenRouter.ai](https://openrouter.ai/).
2. Exporta la variable en tu terminal o agrégala al archivo `.env`:
   ```bash
   export OPENROUTER_API_KEY="sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
   ```
3. (Opcional) Selecciona el modelo que mejor se adapte a tus necesidades (por ejemplo, `meta-llama/llama-3.3-70b-instruct:free`).

---

## 🔌 Integración con Burp Suite

Aegis_X incluye un puente (bridge) para interceptar el tráfico de Burp Suite:

1. **Descargar Jython Standalone JAR**:
   - Descarga `jython-standalone-2.7.3.jar` desde [Jython.org](https://www.jython.org/download.html).
2. **Configurar en Burp Suite**:
   - Ve a **Extensions > Extension Settings (Options) > Python Environment**.
   - Selecciona la ruta al archivo JAR descargado.
3. **Cargar la Extensión**:
   - Ve a **Extensions > Installed > Add**.
   - Extension type: `Python`.
   - Extension file: Selecciona `burp_extension/recon_bridge.py`.
   - Haz clic en **Next**.
4. ¡Listo! Todo el tráfico interceptado en Burp Suite se registrará automáticamente en tu sesión de Aegis_X.

> Para más detalles, consulta la documentación en [burp_extension/README.md](burp_extension/README.md).

---

## 🧪 Ejecución de Pruebas Automatizadas

```bash
# Ejecutar todas las pruebas
pytest -v

# Ejecutar pruebas de filtrado de tráfico
pytest tests/test_traffic_filter.py -v

# Ejecutar pruebas del sistema de caché de IA
pytest tests/test_ai_cache.py -v
```

---

## 📖 Guía Rápida de Uso

1. **Crear un Objetivo**: Ingresa el dominio raíz (ej. `example.com`) en la sección de Objetivos.
2. **Lanzar Reconocimiento**: Inicia el escaneo pasivo de subdominios y el mapeo de puertos con nmap.
3. **Navegar a través de Burp Suite**: Navega por la aplicación web objetivo usando Burp Proxy. El tráfico aparecerá en tiempo real en la pestaña **Tráfico**.
4. **Ejecutar Auditoría con IA**: Haz clic en "Analizar con IA" en cualquier petición o ejecuta un análisis en lote para recibir clasificaciones OWASP y directrices de mitigación.

---

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT**.
