"""
Punto de entrada principal de la aplicación FastAPI para Aegis_X.
Configura ciclo de vida asíncrono, base de datos SQLite, enrutadores API,
vistas web Jinja2, archivos estáticos, WebSockets y CORS.
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.database import init_db
from app.routers import analysis, recon, targets, traffic, websocket

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
)
logger = logging.getLogger("aegis_x")

# Rutas del proyecto
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Inicializa las tablas de la base de datos al arrancar el servicio.
    """
    logger.info("Iniciando Aegis_X - Motor de Reconocimiento y Auditoría Web...")
    await init_db()
    logger.info("Base de datos lista. Plataforma Aegis_X operativa.")
    yield
    logger.info("Deteniendo Aegis_X...")


app = FastAPI(
    title="Aegis_X - Security Audit & Recon Suite",
    description="Plataforma de reconocimiento de superficie de ataque, auditoría de activos e integración con Burp Suite y LLMs.",
    version="1.0.0",
    lifespan=lifespan,
)

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montaje de archivos estáticos y plantillas Jinja2
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Registro de enrutadores API y WebSocket
app.include_router(targets.router)
app.include_router(recon.router)
app.include_router(traffic.router)
app.include_router(analysis.router)
app.include_router(websocket.router)


# ============================================================================
# RUTAS DE INTERFAZ WEB (HTML DASHBOARD)
# ============================================================================

@app.get("/", response_class=HTMLResponse, tags=["Frontend"])
async def dashboard_page(request: Request):
    """Renderiza el panel principal de control."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/recon", response_class=HTMLResponse, tags=["Frontend"])
@app.get("/recon/{target_id}", response_class=HTMLResponse, tags=["Frontend"])
async def recon_page(request: Request, target_id: int = None):
    """Renderiza la vista de reconocimiento y superficie de ataque."""
    return templates.TemplateResponse("recon.html", {"request": request, "target_id": target_id})


@app.get("/traffic", response_class=HTMLResponse, tags=["Frontend"])
async def traffic_page(request: Request):
    """Renderiza la consola de tráfico HTTP en vivo (capturado desde Burp Suite)."""
    return templates.TemplateResponse("traffic.html", {"request": request})


@app.get("/analysis", response_class=HTMLResponse, tags=["Frontend"])
async def analysis_page(request: Request):
    """Renderiza la vista de resultados de auditoría y análisis de IA."""
    return templates.TemplateResponse("analysis.html", {"request": request})


@app.get("/api/health", tags=["Sistema"])
async def health_check() -> dict:
    """Verificación de salud del servicio."""
    return {"status": "ok", "service": "aegis_x", "version": "1.0.0"}
