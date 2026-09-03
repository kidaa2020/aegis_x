"""
Punto de entrada principal para la plataforma de auditoría de seguridad y reconocimiento.
Inicia el servidor ASGI Uvicorn ejecutando la aplicación FastAPI en 0.0.0.0:8000.
"""

import logging
import sys
import uvicorn

# Configuración básica de registro (logging) para el arranque de la aplicación
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("aegis_x.runner")


def main() -> None:
    """
    Función principal de inicio del servicio.
    Configura y lanza el servidor Uvicorn con soporte de recarga en caliente para desarrollo.
    """
    host: str = "0.0.0.0"
    port: int = 8000
    app_module: str = "app.main:app"

    logger.info("Iniciando Aegis_X en http://%s:%d", host, port)
    
    try:
        uvicorn.run(
            app=app_module,
            host=host,
            port=port,
            reload=True,
            log_level="info",
            access_log=True
        )
    except KeyboardInterrupt:
        logger.info("Servidor detenido por el usuario.")
    except Exception as exc:
        logger.critical("Error crítico durante la ejecución del servidor: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
