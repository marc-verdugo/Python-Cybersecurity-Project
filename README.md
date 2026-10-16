## Python Cybersecurity Project

# Threat Response Engine (Mini-SIEM)

A lightweight Security Information and Event Management (SIEM) engine designed for Linux environments. 
It parses system logs, identifies brute-force attempts, cross-references malicious IPs with Threat Intelligence APIs, and automates firewall mitigation.

## Architecture
- **Ingestion Module:** Parses `/var/log/auth.log` using Regular Expressions to identify failed authentication attempts.
- **Intelligence Module:** Queries external REST APIs (ip-api.com) to extract the country and ISP data for suspicious IPs.
- **Mitigation Module:** Uses `iptables` commands (`DROP`), featuring a `dry_run` mode for safe execution and cross-platform testing (Windows / Linux).



