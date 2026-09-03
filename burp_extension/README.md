# Aegis_X Bridge - Extensión para Burp Suite

Esta extensión permite conectar **Burp Suite** (Community o Professional) con **Aegis_X**, enviando automáticamente todo el tráfico HTTP/HTTPS analizado e interactuado en Burp (Proxy, Repeater, Intruder, Scanner) al backend de auditoría inteligente en tiempo real.

---

## 📋 Requisitos Previos

1. **Burp Suite** (v2020.x o superior).
2. **Jython Standalone JAR** (versión 2.7.2 o 2.7.3 recomendada).
   - Descarga directa: [https://www.jython.org/download.html](https://www.jython.org/download.html)
   - Archivo requerido: `jython-standalone-2.7.3.jar` (o versión equivalente).
3. **Aegis_X Backend** en ejecución (`http://127.0.0.1:8000`).

---

## 🚀 Instalación Paso a Paso

### 1. Configurar el Entorno Python (Jython) en Burp Suite
1. Abre **Burp Suite**.
2. Dirígete a la pestaña **Extensions** (en versiones anteriores llamada **Extender**).
3. Haz clic en la sub-pestaña **Extension Settings** (o **Options**).
4. Desplázate hacia abajo hasta la sección **Python Environment**.
5. En el campo **Location of Jython standalone JAR file**, haz clic en **Select file** y selecciona el archivo `jython-standalone-2.7.3.jar` que descargaste previamente.

### 2. Cargar la Extensión `recon_bridge.py`
1. Dentro de la pestaña **Extensions**, ve a la sub-pestaña **Installed** (o **Extensions**).
2. Haz clic en el botón **Add**.
3. En la ventana emergente:
   - **Extension type**: Selecciona `Python`.
   - **Extension file**: Selecciona `burp_extension/recon_bridge.py`.
4. Haz clic en **Next**.
5. Verifica en la sección **Output** que aparezca el mensaje de confirmación:
   ```text
   ============================================================
   [+] Aegis_X Bridge cargado con exito.
   [+] Backend Ingest URL: http://127.0.0.1:8000/api/traffic/ingest
   [+] Target ID actual: 1
   [+] Filtrado de estaticos activo (.css, .js, .png, etc.)
   ============================================================
   ```
6. Haz clic en **Close**. ¡La extensión ya está activa y escuchando el tráfico!

---

## ⚙️ Configuración

### Cambiar el `target_id`
Por defecto, las peticiones interceptadas se asociarán al objetivo (`Target`) con ID `1` en la base de datos de Aegis_X.

Para asociar el tráfico a otro objetivo:
1. Abre el archivo `burp_extension/recon_bridge.py` en tu editor de texto.
2. Modifica la variable `TARGET_ID` en la clase `BurpExtender`:
   ```python
   # Identificador de objetivo por defecto en Aegis_X
   TARGET_ID = 2  # Cambia por el ID deseado
   ```
3. En Burp Suite, ve a **Extensions > Installed**, desmarca y vuelve a marcar la casilla de verificación **Loaded** junto a **Aegis_X Bridge** para recargar la extensión.

### Cambiar la URL de Ingesta
Si el servidor Aegis_X corre en otro puerto o máquina:
```python
INGEST_URL = "http://192.168.1.50:8000/api/traffic/ingest"
```

---

## 🔍 Características y Optimización

- **Captura Dual**: Extrae de forma sincronizada tanto la petición original (método, URL, cabeceras, body) como la respuesta del servidor (código de estado, cabeceras, respuesta truncada).
- **Filtrado Inteligente de Estáticos**: Descarta automáticamente peticiones hacia imágenes (`.png`, `.jpg`, `.ico`), fuentes (`.woff`, `.ttf`), hojas de estilo (`.css`), scripts empaquetados (`.js`) o mapas (`.map`) para evitar ruido y consumo innecesario de tokens de IA.
- **Truncado de Respuestas**: Limita el cuerpo de las respuestas a 10 KB para optimizar el rendimiento y la base de datos.
- **Tolerancia a Fallos**: Si el servidor Aegis_X se detiene o se reinicia, la extensión captura el error silenciosamente sin bloquear ni ralentizar la navegación en Burp Suite.

---

## 🛠️ Solución de Problemas (Troubleshooting)

### Error: `No module named burp` o extensión no carga
- **Causa**: No se ha configurado correctamente el JAR standalone de Jython.
- **Solución**: Asegúrate de haber descargado la versión `standalone` (ej. `jython-standalone-2.7.3.jar`) y no el instalador estándar. Verifica la ruta en **Extensions > Options > Python Environment**.

### Advertencia: `[-] No se pudo enviar trafico a Aegis_X: Connection refused`
- **Causa**: El backend de Aegis_X no está en ejecución o el puerto `8000` está bloqueado.
- **Solución**: Inicia el servidor backend ejecutando `python run.py` y comprueba que `http://127.0.0.1:8000` responde correctamente.

### Tráfico no aparece en el Dashboard
- Comprueba que la URL objetivo no sea un archivo estático filtrado.
- Verifica en la pestaña **Extensions > Installed > Aegis_X Bridge > Errors** si se han registrado excepciones.
- Asegúrate de que el `TARGET_ID` configurado exista en la base de datos de Aegis_X.
