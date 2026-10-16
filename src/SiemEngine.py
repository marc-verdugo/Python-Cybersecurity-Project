import re
import os
import requests
import subprocess

class SiemEngine:
    def __init__(self, log_path):
        self.log_path = log_path
        # Compilamos la expresión regular una sola vez al iniciar el motor por eficiencia.
        # Este patrón busca exactamente el formato de una IPv4 (Ej: 192.168.1.1)
        self.ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        
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
                            
        except FileNotFoundError:
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
                        print(f"    INTEL OBTENIDA -> IP: {ip} | País: {country} | ISP: {isp}")
                    else:
                        print(f"    La API no tiene datos para la IP: {ip}")
                else:
                    print(f"    [ERROR] Fallo en la API para {ip}. Código: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                # Control de excepciones por si falla la red (DNS, timeouts, etc.)
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
                print(f"    [SIMULACIÓN FIREWALL] Comando a ejecutar: {' '.join(command)}")
            else:
                try:
                    result = subprocess.run(command, capture_output=True, text=True, check=True)
                    info["action"] = "blocked_active"
                    print(f"    [ÉXITO FIREWALL] IP {ip} bloqueada en iptables.")
                except subprocess.CalledProcessError as e:
                    info["action"] = "failed"
                    print(f"    [ERROR FIREWALL] Error al bloquear la IP {ip}: {e.stderr.strip()}")
                except FileNotFoundError:
                    info["action"] = "failed_os_unsupported"
                    print(f"    [ERROR OS] 'iptables' no está disponible en este sistema operativo.")
                    
        return threat_data
    
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
    else:
        print("No hay amenazas activas. Sistema seguro.")

    