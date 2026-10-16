import re
import os
import requests
import subprocess
from datetime import datetime
import logging
import json

class SiemEngine:
    def __init__(self, log_path, audit_log_path="logs/siem_engine.log"):
        self.log_path = log_path
        # Compilamos la expresión regular una sola vez al iniciar el motor por eficiencia.
        # Este patrón busca exactamente el formato de una IPv4 (Ej: 192.168.1.1)
        self.ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")

        # Configuración del sistema de Logging del motor
        os.makedirs(os.path.dirname(audit_log_path), exist_ok=True)
        logging.basicConfig(
            filename=audit_log_path,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.logger = logging.getLogger("SiemEngine")
        self.logger.info("Threat Response Engine inicializado.")
        
    def extract_malicious_ips(self):
        """
        Módulo de Ingestión: Escanea el archivo de logs en busca de intentos 
        fallidos de conexión y extrae las IPs atacantes sin duplicados.
        """
        # Usamos un 'set' (conjunto) en lugar de una lista para que las IPs 
        # no se repitan automáticamente.
        malicious_ips = set()
        
        try:
            with open(self.log_path, 'r') as file:
                for line in file:
                    # Filtramos por las palabras clave típicas de fallos en SSH
                    if "Failed password" in line or "Invalid user" in line:
                        # Si es un fallo, extraemos la IP usando nuestra Regex
                        match = self.ip_pattern.search(line)
                        if match:
                            malicious_ips.add(match.group())
            self.logger.info(f"Ingestión completada: {len(malicious_ips)} IPs únicas identificadas.")               
        except FileNotFoundError:
            self.logger.error(f"No se encontró el archivo de logs: {self.log_path}")
            print(f"[ERROR CRÍTICO] No se encontró el archivo de logs en: {self.log_path}")
            
        return malicious_ips

    def analyze_threat_intelligence(self, ips):
        """
        Módulo de Inteligencia: Consulta una API externa REST para geolocalizar 
        y obtener información del proveedor (ISP) de las IPs sospechosas.
        """
        threat_data = {}
        
        for ip in ips:
            try:
                # Petición GET a la API con la IP insertada dinámicamente en la URL
                response = requests.get(f"http://ip-api.com/json/{ip}")
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("status") == "success":
                        country = data.get("country", "Desconocido")
                        isp = data.get("isp", "Desconocido")
                        
                        # Guardamos la inteligencia recolectada en un diccionario
                        threat_data[ip] = {
                            "country": country,
                            "isp": isp,
                            "action": "pending" 
                        }
                        self.logger.info(f"Intel obtenida para {ip}: País={country}, ISP={isp}")
                        print(f"    INTEL OBTENIDA -> IP: {ip} | País: {country} | ISP: {isp}")
                    else:
                        print(f"    La API no tiene datos para la IP: {ip}")
                else:
                    print(f"    [ERROR] Fallo en la API para {ip}. Código: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                # Control de excepciones por si falla la red (DNS, timeouts, etc.)
                self.logger.error(f"Fallo de red consultando IP {ip}: {e}")
                print(f"    [ERROR CRÍTICO de Red] No se pudo consultar la IP {ip}: {e}")
                
        return threat_data

    def apply_mitigation(self, threat_data, dry_run=True):
        """
        Módulo de Mitigación: Utiliza subprocesos de OS para generar y ejecutar 
        reglas de bloqueo en el Firewall de Linux (iptables).
        """
        for ip, info in threat_data.items():
            # Comando estándar de iptables para bloquear tráfico entrante
            command = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            
            if dry_run:
                # Simulación segura sin alterar la red ni requerir permisos root
                info["action"] = "blocked_simulated"
                self.logger.info(f"Mitigación SIMULADA para IP {ip}: {' '.join(command)}")
                print(f"    [SIMULACIÓN FIREWALL] Comando a ejecutar: {' '.join(command)}")
            else:
                try:
                    result = subprocess.run(command, capture_output=True, text=True, check=True)
                    info["action"] = "blocked_active"
                    self.logger.info(f"IP {ip} ya existente en iptables. Omitida.")
                    print(f"    [ÉXITO FIREWALL] IP {ip} bloqueada en iptables.")
                except subprocess.CalledProcessError as e:
                    info["action"] = "failed"
                    self.logger.error(f"Error aplicando iptables para {ip}: {e.stderr.strip()}")
                    print(f"    [ERROR FIREWALL] Error al bloquear la IP {ip}: {e.stderr.strip()}")
                except FileNotFoundError:
                    info["action"] = "failed_os_unsupported"
                    self.logger.warning("iptables no disponible en este SO.")
                    print(f"    [ERROR OS] 'iptables' no está disponible en este sistema operativo.")
                    
        return threat_data

    def export_audit_report(self, threat_data, output_dir="reports"):
        """Módulo de Auditoría: Exporta un informe estructurado en formato JSON."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(output_dir, f"threat_report_{timestamp}.json")
        
        report_content = {
            "engine_metadata": {
                "execution_timestamp": datetime.now().isoformat(),
                "source_log": self.log_path,
                "total_threats_processed": len(threat_data)
            },
            "incidents": threat_data
        }
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_content, f, indent=4, ensure_ascii=False)
            self.logger.info(f"Informe de auditoría JSON generado en: {report_path}")
            print(f"\n[+] Reporte de auditoría generado exitosamente en:\n    -> {report_path}")
        except IOError as e:
            self.logger.error(f"Error escribiendo reporte JSON: {e}")
            print(f"[ERROR] No se pudo escribir el informe de auditoría: {e}")
    
if __name__ == "__main__":
    
    log_file = "logs/auth_sample.log"
    
    print("Iniciando Threat Response Engine...")
    engine = SiemEngine(log_file)
    
    # Fase 1: Ingestión
    print("Ejecutando Módulo de Ingestión...")
    suspicious_ips = engine.extract_malicious_ips()
    print(f"Análisis completado. Se encontraron {len(suspicious_ips)} IPs sospechosas")

    # Fase 2: Inteligencia
    if suspicious_ips:
        print("\nEjecutando Módulo de Inteligencia...")
        intel_results = engine.analyze_threat_intelligence(suspicious_ips)
        
        # Fase 3: Mitigación
        print("\nEjecutando Módulo de Mitigación...")
        mitigated_results = engine.apply_mitigation(intel_results, dry_run=True)

        # Fase 4: Auditoría
        print("\nEjecutando Módulo de Auditoría...")
        engine.export_audit_report(mitigated_results)
    else:
        print("No hay amenazas activas. Sistema seguro.")

    