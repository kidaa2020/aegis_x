# -*- coding: utf-8 -*-
"""
Aegis_X Bridge - Burp Suite Extension
=====================================
Extensión para Burp Suite desarrollada en Jython (compatible con Python 2.7)
que captura el tráfico HTTP/HTTPS procesado por Burp (Proxy, Repeater, Scanner, etc.)
y lo reenvía automáticamente a la API local de Aegis_X para su análisis,
filtrado, deduplicación e inspección asistida por IA.

Instalación en Burp Suite:
---------------------------
1. Descargar el JAR standalone de Jython (versión 2.7.x) desde:
   https://www.jython.org/download.html
2. En Burp Suite, ir a: Extender (o Extensions) > Options > Python Environment.
3. En "Location of Jython standalone JAR file", seleccionar el archivo JAR descargado.
4. Ir a: Extender (o Extensions) > Installed (o Extensions) > Add.
5. Configurar:
   - Extension type: Python
   - Extension file: Seleccionar este archivo (recon_bridge.py)
6. Hacer clic en "Next" y verificar que la consola muestre el mensaje de inicialización exitosa.
"""

import json
import re
import sys
import traceback
from burp import IBurpExtender, IHttpListener
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter, PrintWriter
from java.net import HttpURLConnection, URL


class BurpExtender(IBurpExtender, IHttpListener):
    """
    Clase principal de la extensión Aegis_X Bridge.
    Implementa IBurpExtender para el registro en Burp Suite e
    IHttpListener para interceptar peticiones y respuestas HTTP.
    """

    # Identificador de objetivo por defecto en Aegis_X
    TARGET_ID = 1

    # URL del endpoint de ingesta en el backend FastAPI
    INGEST_URL = "http://127.0.0.1:8000/api/traffic/ingest"

    # Límite máximo para el cuerpo de la respuesta (10 KB = 10240 bytes/caracteres)
    MAX_RESPONSE_BODY_LENGTH = 10240

    # Extensiones de archivos estáticos que deben ser ignoradas
    STATIC_EXTENSIONS = (
        ".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".ico",
        ".woff", ".woff2", ".svg", ".map", ".ttf", ".eot", ".mp4",
        ".mp3", ".webm", ".avi", ".pdf", ".zip", ".tar", ".gz"
    )

    def registerExtenderCallbacks(self, callbacks):
        """
        Punto de entrada obligatorio para la extensión en Burp Suite.
        Configura los helpers, la consola de salida y registra el listener HTTP.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Configurar nombre visible de la extensión
        callbacks.setExtensionName("Aegis_X Bridge")

        # Configurar streams de salida estándar y de errores para la pestaña de la extensión
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # Registrar el listener HTTP para interceptar tráfico
        callbacks.registerHttpListener(self)

        self._stdout.println("=" * 60)
        self._stdout.println("[+] Aegis_X Bridge cargado con exito.")
        self._stdout.println("[+] Backend Ingest URL: " + self.INGEST_URL)
        self._stdout.println("[+] Target ID actual: " + str(self.TARGET_ID))
        self._stdout.println("[+] Filtrado de estaticos activo (.css, .js, .png, etc.)")
        self._stdout.println("=" * 60)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Callback invocado por Burp Suite para cada mensaje HTTP procesado.
        
        Parámetros:
        - toolFlag: Identificador de la herramienta de Burp que generó el evento (Proxy, Repeater, etc.)
        - messageIsRequest: True si el mensaje es una petición, False si es una respuesta.
        - messageInfo: Objeto IHttpRequestResponse con los datos del tráfico.
        """
        # Solo procesar en la fase de RESPUESTA (messageIsRequest == False)
        # Esto garantiza que tengamos disponibles tanto la petición completa como la respuesta.
        if messageIsRequest:
            return

        try:
            # 1. Obtener bytes de la petición y respuesta
            request_bytes = messageInfo.getRequest()
            response_bytes = messageInfo.getResponse()

            if request_bytes is None:
                return

            # 2. Analizar la petición HTTP
            request_info = self._helpers.analyzeRequest(messageInfo)
            url_obj = request_info.getUrl()
            url_str = str(url_obj) if url_obj is not None else ""

            if not url_str:
                return

            # 3. Filtrar archivos estáticos para optimizar tráfico e IA
            if self._is_static_resource(url_str):
                return

            method = str(request_info.getMethod())
            req_headers_list = list(request_info.getHeaders())
            req_headers_dict = self._parse_headers(req_headers_list)

            # Extraer cuerpo de la petición
            req_body_offset = request_info.getBodyOffset()
            req_body_bytes = request_bytes[req_body_offset:]
            req_body = self._helpers.bytesToString(req_body_bytes)

            # 4. Analizar la respuesta HTTP (si está presente)
            status_code = 0
            res_headers_dict = {}
            res_body = ""

            if response_bytes is not None:
                response_info = self._helpers.analyzeResponse(response_bytes)
                status_code = int(response_info.getStatusCode())
                res_headers_list = list(response_info.getHeaders())
                res_headers_dict = self._parse_headers(res_headers_list)

                # Extraer cuerpo de la respuesta con truncado a 10KB
                res_body_offset = response_info.getBodyOffset()
                res_body_bytes = response_bytes[res_body_offset:]
                res_body_full = self._helpers.bytesToString(res_body_bytes)

                if len(res_body_full) > self.MAX_RESPONSE_BODY_LENGTH:
                    res_body = res_body_full[:self.MAX_RESPONSE_BODY_LENGTH]
                else:
                    res_body = res_body_full

            # 5. Obtener nombre de la herramienta de Burp (Proxy, Repeater, Scanner, etc.)
            tool_name = self._callbacks.getToolName(toolFlag)

            # 6. Construir payload JSON para el backend
            payload = {
                "target_id": self.TARGET_ID,
                "tool": tool_name,
                "method": method,
                "url": url_str,
                "request_headers": req_headers_dict,
                "request_body": req_body,
                "status_code": status_code,
                "response_headers": res_headers_dict,
                "response_body": res_body
            }

            # 7. Enviar datos al backend FastAPI
            self._send_payload(payload)

        except Exception as e:
            # Manejo de excepciones defensivo para no interferir con el funcionamiento de Burp
            self._stderr.println("[-] Error procesando mensaje HTTP en Aegis_X Bridge:")
            self._stderr.println(str(e))
            traceback.print_exc(file=self._stderr)

    def _is_static_resource(self, url_str):
        """
        Verifica si una URL apunta a un recurso estático que no requiere auditoría de seguridad.
        Limpia cadenas de consulta (query strings) y hashes antes de comparar la extensión.
        """
        try:
            # Eliminar fragmentos y parámetros de consulta
            clean_url = url_str.split("?")[0].split("#")[0].lower()
            for ext in self.STATIC_EXTENSIONS:
                if clean_url.endswith(ext):
                    return True
            return False
        except Exception:
            return False

    def _parse_headers(self, headers_list):
        """
        Convierte la lista de cabeceras de Burp en un diccionario estructurado clave-valor.
        La primera línea (status line / request line) se descarta o almacena según corresponda.
        """
        headers_dict = {}
        if not headers_list or len(headers_list) <= 1:
            return headers_dict

        # El índice 0 es 'GET / HTTP/1.1' o 'HTTP/1.1 200 OK'
        for line in headers_list[1:]:
            line_str = str(line)
            if ":" in line_str:
                parts = line_str.split(":", 1)
                k = parts[0].strip()
                v = parts[1].strip()
                headers_dict[k] = v
        return headers_dict

    def _send_payload(self, payload_dict):
        """
        Envía el payload JSON al endpoint de ingesta utilizando java.net.HttpURLConnection.
        Incluye manejo de timeouts y captura de errores sin bloquear la ejecución de Burp.
        """
        connection = None
        writer = None
        reader = None
        try:
            json_str = json.dumps(payload_dict)
            url = URL(self.INGEST_URL)
            connection = url.openConnection()
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            connection.setRequestProperty("Accept", "application/json")
            connection.setConnectTimeout(2000)   # 2 segundos de timeout de conexión
            connection.setReadTimeout(3000)      # 3 segundos de timeout de lectura
            connection.setDoOutput(True)
            connection.setDoInput(True)

            # Escribir payload JSON en el OutputStream
            writer = OutputStreamWriter(connection.getOutputStream(), "UTF-8")
            writer.write(json_str)
            writer.flush()
            writer.close()
            writer = None

            # Leer respuesta del servidor
            response_code = connection.getResponseCode()
            if response_code in (200, 201, 202):
                # Éxito: lectura silenciosa del cuerpo
                reader = BufferedReader(InputStreamReader(connection.getInputStream(), "UTF-8"))
                while reader.readLine() is not None:
                    pass
                reader.close()
                reader = None
            else:
                self._stderr.println("[-] Backend devolvio codigo HTTP: " + str(response_code))

        except Exception as e:
            # Si el backend no está disponible, registrar mensaje amigable sin saturar la consola
            self._stderr.println("[-] No se pudo enviar trafico a Aegis_X (" + self.INGEST_URL + "): " + str(e))
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.disconnect()
                except Exception:
                    pass
