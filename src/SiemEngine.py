import re
import os

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

if __name__ == "__main__":
    
    log_file = "logs/auth_sample.log"
    
    print("Iniciando Threat Response Engine...")
    engine = SiemEngine(log_file)
    
    # Fase 1: Ingestión
    print("Ejecutando Módulo de Ingestión...")
    suspicious_ips = engine.extract_malicious_ips()
    
    print(f"Análisis completado. Se encontraron {len(suspicious_ips)} IPs sospechosas únicas:")
    for ip in suspicious_ips:
        print(f"    -> {ip}")