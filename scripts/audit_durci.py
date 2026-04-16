#!/usr/bin/env python3
"""
Projet AEGIS — TechSud
Script d'audit automatisé du système (VERSION AMÉLIORÉE)
IPSSI BTC1 — Groupe 4

Améliorations :
- Gestion robuste des erreurs
- Analyse de sécurité approfondie
- Système de score (0-100)
- Rapports JSON/HTML
- Logging structuré
"""

import subprocess
import json
import datetime
import socket
import os
import sys
import pwd
import grp
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any
from enum import Enum
from dataclasses import dataclass, asdict
from collections import defaultdict

# ============================================================================
# ENUMS & TYPES
# ============================================================================

class SeverityLevel(Enum):
    CRITIQUE = 0
    ÉLEVÉ = 1
    MOYEN = 2
    FAIBLE = 3
    INFO = 4

@dataclass
class SecurityFinding:
    check_name: str
    result: bool
    severity: SeverityLevel
    message: str
    remediation: str = ""
    evidence: str = ""

# ============================================================================
# LOGGER PERSONNALISÉ
# ============================================================================

class SecurityLogger:
    def __init__(self, log_file: str = "audit_aegis.log"):
        self.log_file = log_file
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def info(self, msg: str):
        self.logger.info(msg)
    
    def warning(self, msg: str):
        self.logger.warning(msg)
    
    def error(self, msg: str):
        self.logger.error(msg)
    
    def critical(self, msg: str):
        self.logger.critical(msg)

# ============================================================================
# UTILITAIRES
# ============================================================================

class CommandRunner:
    """Exécute les commandes système de manière sécurisée"""
    
    def __init__(self, timeout: int = 10, logger: SecurityLogger = None):
        self.timeout = timeout
        self.logger = logger or SecurityLogger()
    
    def run(self, cmd: List[str], check: bool = False) -> Tuple[bool, str, str]:
        """
        Exécute une commande système
        Returns: (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
            return (result.returncode == 0, result.stdout, result.stderr)
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout lors de l'exécution : {' '.join(cmd)}")
            return (False, "", "Timeout")
        except FileNotFoundError:
            self.logger.warning(f"Commande non trouvée : {cmd[0]}")
            return (False, "", "Command not found")
        except Exception as e:
            self.logger.error(f"Erreur lors de l'exécution : {str(e)}")
            return (False, "", str(e))

# ============================================================================
# VÉRIFICATIONS DE SÉCURITÉ
# ============================================================================

class SecurityAuditor:
    def __init__(self, logger: SecurityLogger = None):
        self.logger = logger or SecurityLogger()
        self.runner = CommandRunner(logger=self.logger)
        self.findings: List[SecurityFinding] = []
        self.score = 100
    
    # ---- RÉSEAU & PORTS ----
    
    def check_open_ports(self) -> Dict[str, Any]:
        """Analyse les ports ouverts"""
        success, stdout, stderr = self.runner.run(['ss', '-tulnp'])
        
        ports = []
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                ports.append({
                    "protocole": parts[0],
                    "etat": parts[1],
                    "adresse": parts[4],
                })
        
        return {
            "ports_ouverts": ports,
            "nombre": len(ports)
        }
    
    def check_listening_services(self) -> Dict[str, Any]:
        """Détecte les services réseau anormaux"""
        success, stdout, stderr = self.runner.run(['netstat', '-tulnp'])
        
        suspicious = []
        for line in stdout.splitlines()[2:]:
            if any(x in line for x in ['0.0.0.0', '127.0.0.1']):
                suspicious.append(line.strip())
        
        finding = SecurityFinding(
            check_name="suspicious_listening_services",
            result=len(suspicious) == 0,
            severity=SeverityLevel.MOYEN,
            message=f"Services réseau détectés : {len(suspicious)}",
            evidence="\n".join(suspicious[:5])
        )
        self.findings.append(finding)
        
        return {"services_réseau": suspicious}
    
    # ---- SSH ----
    
    def check_ssh_hardening(self) -> Dict[str, Any]:
        """Vérifie le renforcement SSH"""
        sshd_config = "/etc/ssh/sshd_config"
        checks = {}
        
        if not os.path.exists(sshd_config):
            self.logger.error("sshd_config non trouvé")
            return {"ssh_accessible": False}
        
        try:
            with open(sshd_config, 'r') as f:
                ssh_content = f.read()
        except PermissionError:
            self.logger.error("Pas d'accès à sshd_config")
            return {"ssh_accessible": False}
        
        # Vérifications individuelles
        checks_list = [
            ("PermitRootLogin no", "ssh_no_root", SeverityLevel.CRITIQUE),
            ("PasswordAuthentication no", "ssh_no_password", SeverityLevel.ÉLEVÉ),
            ("PubkeyAuthentication yes", "ssh_pubkey_auth", SeverityLevel.ÉLEVÉ),
            ("Protocol 2", "ssh_protocol_v2", SeverityLevel.ÉLEVÉ),
            ("X11Forwarding no", "ssh_no_x11", SeverityLevel.MOYEN),
            ("PermitEmptyPasswords no", "ssh_no_empty", SeverityLevel.CRITIQUE),
        ]
        
        for config_line, check_name, severity in checks_list:
            found = config_line in ssh_content
            checks[check_name] = found
            
            finding = SecurityFinding(
                check_name=check_name,
                result=found,
                severity=severity,
                message=f"Configuration SSH : {config_line}",
                remediation=f"Ajouter/vérifier la ligne : {config_line}"
            )
            self.findings.append(finding)
            
            if not found:
                self.score -= severity.value + 5
        
        return checks
    
    # ---- PARE-FEU & FILTRAGE ----
    
    def check_firewall_status(self) -> Dict[str, Any]:
        """Vérifie l'état du pare-feu"""
        checks = {}
        
        # UFW
        success, stdout, stderr = self.runner.run(['ufw', 'status'])
        checks['ufw_active'] = 'active' in stdout.lower()
        
        finding = SecurityFinding(
            check_name="ufw_firewall",
            result=checks['ufw_active'],
            severity=SeverityLevel.CRITIQUE,
            message="Pare-feu UFW actif",
            remediation="sudo ufw enable"
        )
        self.findings.append(finding)
        
        if not checks['ufw_active']:
            self.score -= 15
        
        return checks
    
    def check_fail2ban(self) -> Dict[str, Any]:
        """Vérifie fail2ban"""
        success, stdout, stderr = self.runner.run(
            ['systemctl', 'is-active', 'fail2ban']
        )
        
        is_active = stdout.strip() == 'active'
        
        finding = SecurityFinding(
            check_name="fail2ban_service",
            result=is_active,
            severity=SeverityLevel.ÉLEVÉ,
            message="Service fail2ban actif",
            remediation="sudo systemctl start fail2ban && sudo systemctl enable fail2ban"
        )
        self.findings.append(finding)
        
        if not is_active:
            self.score -= 10
        
        return {"fail2ban_active": is_active}
    
    # ---- PERMISSIONS & SUID ----
    
    def check_dangerous_suid(self) -> Dict[str, Any]:
        """Détecte les binaires SUID/SGID dangereux"""
        dangerous_binaries = [
            '/usr/bin/find',
            '/usr/bin/passwd',
            '/usr/bin/sudo',
            '/bin/su',
            '/usr/bin/at'
        ]
        
        found_dangerous = []
        for binary in dangerous_binaries:
            success, stdout, stderr = self.runner.run(
                ['find', binary, '-perm', '-4000']
            )
            if stdout.strip():
                found_dangerous.append(binary)
        
        finding = SecurityFinding(
            check_name="dangerous_suid",
            result=len(found_dangerous) == 0,
            severity=SeverityLevel.CRITIQUE,
            message=f"Binaires SUID dangereux détectés : {len(found_dangerous)}",
            evidence="\n".join(found_dangerous)
        )
        self.findings.append(finding)
        
        if found_dangerous:
            self.score -= 20
        
        return {"dangerous_suid": found_dangerous}
    
    def check_file_permissions(self) -> Dict[str, Any]:
        """Vérifie les permissions de fichiers critiques"""
        critical_files = {
            '/etc/passwd': '0644',
            '/etc/shadow': '0640',
            '/etc/sudoers': '0440',
            '/root/.ssh/authorized_keys': '0600',
        }
        
        violations = []
        for filepath, expected_perm in critical_files.items():
            if not os.path.exists(filepath):
                continue
            
            try:
                actual_perm = oct(os.stat(filepath).st_mode)[-4:]
                if actual_perm != expected_perm:
                    violations.append({
                        "file": filepath,
                        "expected": expected_perm,
                        "actual": actual_perm
                    })
            except PermissionError:
                self.logger.warning(f"Pas d'accès à {filepath}")
        
        finding = SecurityFinding(
            check_name="critical_file_permissions",
            result=len(violations) == 0,
            severity=SeverityLevel.ÉLEVÉ,
            message=f"Violations de permissions : {len(violations)}",
            evidence=json.dumps(violations, indent=2)
        )
        self.findings.append(finding)
        
        if violations:
            self.score -= 15
        
        return {"permission_violations": violations}
    
    # ---- UTILISATEURS & AUTHENTIFICATION ----
    
    def check_weak_passwords(self) -> Dict[str, Any]:
        """Vérifie la qualité des mots de passe"""
        success, stdout, stderr = self.runner.run(
            ['apt-cache', 'policy', 'libpam-pwquality']
        )
        
        pwquality_installed = 'none' not in stdout.lower()
        
        finding = SecurityFinding(
            check_name="password_quality_lib",
            result=pwquality_installed,
            severity=SeverityLevel.MOYEN,
            message="Bibliothèque de vérification de mots de passe installée",
            remediation="sudo apt install libpam-pwquality"
        )
        self.findings.append(finding)
        
        if not pwquality_installed:
            self.score -= 8
        
        return {"pwquality_installed": pwquality_installed}
    
    def check_root_login(self) -> Dict[str, Any]:
        """Vérifie qu'aucun utilisateur n'a l'UID 0 sauf root"""
        uid_zero_users = []
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) >= 3 and parts[2] == '0' and parts[0] != 'root':
                        uid_zero_users.append(parts[0])
        except Exception as e:
            self.logger.error(f"Erreur lecture /etc/passwd : {e}")
        
        finding = SecurityFinding(
            check_name="uid_zero_check",
            result=len(uid_zero_users) == 0,
            severity=SeverityLevel.CRITIQUE,
            message=f"Utilisateurs avec UID 0 : {len(uid_zero_users)}",
            evidence=", ".join(uid_zero_users) if uid_zero_users else "Aucun"
        )
        self.findings.append(finding)
        
        if uid_zero_users:
            self.score -= 25
        
        return {"uid_zero_users": uid_zero_users}
    
    def check_sudo_access(self) -> Dict[str, Any]:
        """Vérifie les droits sudo"""
        sudo_users = []
        try:
            with open('/etc/sudoers', 'r') as f:
                for line in f:
                    if line.startswith('%') or (line and not line.startswith('#')):
                        sudo_users.append(line.strip())
        except PermissionError:
            self.logger.warning("Pas d'accès à /etc/sudoers")
        except Exception as e:
            self.logger.error(f"Erreur lecture sudoers : {e}")
        
        return {"sudo_users": sudo_users}
    
    # ---- SERVICES & PROCESSUS ----
    
    def check_running_services(self) -> Dict[str, Any]:
        """Liste les services actifs"""
        success, stdout, stderr = self.runner.run(
            ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager']
        )
        
        services = []
        for line in stdout.splitlines():
            if '.service' in line:
                parts = line.strip().split()
                if parts:
                    services.append(parts[0])
        
        return {"services_actifs": services[:20]}  # Limiter l'affichage
    
    def check_unnecessary_services(self) -> Dict[str, Any]:
        """Détecte les services potentiellement non nécessaires"""
        unnecessary = ['bluetooth', 'avahi-daemon', 'cups', 'snmpd', 'rsync']
        
        enabled = []
        for service in unnecessary:
            success, stdout, stderr = self.runner.run(
                ['systemctl', 'is-enabled', service]
            )
            if 'enabled' in stdout.lower():
                enabled.append(service)
        
        finding = SecurityFinding(
            check_name="unnecessary_services",
            result=len(enabled) == 0,
            severity=SeverityLevel.MOYEN,
            message=f"Services non essentiels activés : {len(enabled)}",
            evidence=", ".join(enabled) if enabled else "Aucun"
        )
        self.findings.append(finding)
        
        if enabled:
            self.score -= 5
        
        return {"unnecessary_services": enabled}
    
    # ---- SÉCURITÉ WEB ----
    
    def check_webshell(self) -> Dict[str, Any]:
        """Détecte les webshells"""
        webshell_paths = [
            '/var/www/html/upload/shell.php',
            '/var/www/html/shell.php',
            '/var/www/shell.php',
            '/tmp/shell.php',
        ]
        
        found = []
        for path in webshell_paths:
            if os.path.exists(path):
                found.append(path)
        
        finding = SecurityFinding(
            check_name="webshell_detection",
            result=len(found) == 0,
            severity=SeverityLevel.CRITIQUE,
            message=f"Webshells détectés : {len(found)}",
            evidence=", ".join(found) if found else "Aucun"
        )
        self.findings.append(finding)
        
        if found:
            self.score = 0  # Score critique
        
        return {"webshells": found}
    
    def check_exposed_config(self) -> Dict[str, Any]:
        """Détecte les fichiers de config exposés"""
        exposed_files = [
            '/var/www/html/config.php',
            '/var/www/config.php',
            '/var/www/html/.env',
            '/var/www/.env',
        ]
        
        found = []
        for path in exposed_files:
            if os.path.exists(path):
                try:
                    os.stat(path)
                    found.append(path)
                except:
                    pass
        
        finding = SecurityFinding(
            check_name="exposed_config",
            result=len(found) == 0,
            severity=SeverityLevel.CRITIQUE,
            message=f"Fichiers de configuration exposés : {len(found)}",
            evidence=", ".join(found) if found else "Aucun"
        )
        self.findings.append(finding)
        
        if found:
            self.score -= 20
        
        return {"exposed_config": found}
    
    # ---- LOGS & AUDIT ----
    
    def check_system_logs(self) -> Dict[str, Any]:
        """Vérifie les fichiers journaux"""
        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/secure',
        ]
        
        active_logs = []
        for logfile in log_files:
            if os.path.exists(logfile):
                try:
                    size = os.path.getsize(logfile)
                    active_logs.append({"file": logfile, "size_bytes": size})
                except:
                    pass
        
        return {"system_logs": active_logs}
    
    # ---- EXÉCUTION COMPLÈTE ----
    
    def run_full_audit(self) -> Dict[str, Any]:
        """Exécute l'audit complet"""
        self.logger.info("Démarrage de l'audit de sécurité complète")
        
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "user": os.getenv('USER', 'unknown'),
            
            # Réseau
            "ports": self.check_open_ports(),
            "listening_services": self.check_listening_services(),
            
            # SSH
            "ssh_hardening": self.check_ssh_hardening(),
            
            # Pare-feu
            "firewall": self.check_firewall_status(),
            "fail2ban": self.check_fail2ban(),
            
            # Permissions
            "suid": self.check_dangerous_suid(),
            "file_permissions": self.check_file_permissions(),
            
            # Utilisateurs
            "weak_passwords": self.check_weak_passwords(),
            "root_login": self.check_root_login(),
            "sudo_access": self.check_sudo_access(),
            
            # Services
            "services": self.check_running_services(),
            "unnecessary_services": self.check_unnecessary_services(),
            
            # Web
            "webshell": self.check_webshell(),
            "exposed_config": self.check_exposed_config(),
            
            # Logs
            "logs": self.check_system_logs(),
        }
        
        self.logger.info(f"Audit terminé. Score : {self.score}/100")
        
        return results

# ============================================================================
# RAPPORTS
# ============================================================================

class ReportGenerator:
    def __init__(self, audit_results: Dict, findings: List[SecurityFinding], score: int):
        self.audit_results = audit_results
        self.findings = findings
        self.score = score
    
    def generate_json_report(self, filename: str = "audit_aegis.json"):
        """Génère un rapport JSON"""
        critical_findings = [
            f for f in self.findings 
            if f.severity == SeverityLevel.CRITIQUE
        ]
        
        report = {
            "audit_metadata": {
                "timestamp": self.audit_results["timestamp"],
                "hostname": self.audit_results["hostname"],
                "score": self.score,
                "severity_distribution": self._count_by_severity(),
                "critical_count": len(critical_findings)
            },
            "audit_results": self.audit_results,
            "findings": [
                {
                    "name": f.check_name,
                    "passed": f.result,
                    "severity": f.severity.name,
                    "message": f.message,
                    "remediation": f.remediation,
                    "evidence": f.evidence
                }
                for f in self.findings
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return filename
    
    def generate_html_report(self, filename: str = "audit_aegis.html"):
        """Génère un rapport HTML"""
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit AEGIS - TechSud</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {'#28a745' if self.score >= 70 else '#ffc107' if self.score >= 50 else '#dc3545'}; }}
        .finding {{ margin: 15px 0; padding: 15px; border-left: 4px solid; border-radius: 3px; }}
        .CRITIQUE {{ background: #f8d7da; border-color: #dc3545; }}
        .ÉLEVÉ {{ background: #fff3cd; border-color: #ffc107; }}
        .MOYEN {{ background: #d1ecf1; border-color: #17a2b8; }}
        .FAIBLE {{ background: #e7e9eb; border-color: #6c757d; }}
        .INFO {{ background: #d1ecf1; border-color: #17a2b8; }}
        .finding-title {{ font-weight: bold; margin-bottom: 5px; }}
        .evidence {{ background: #f9f9f9; padding: 10px; margin-top: 10px; border-radius: 3px; font-family: monospace; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f0f0f0; font-weight: bold; }}
        .pass {{ color: #28a745; font-weight: bold; }}
        .fail {{ color: #dc3545; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Audit de Sécurité AEGIS - TechSud</h1>
        <p><strong>Date :</strong> {self.audit_results['timestamp']}</p>
        <p><strong>Hôte :</strong> {self.audit_results['hostname']}</p>
        
        <h2>Score de Sécurité</h2>
        <div class="score">{self.score}/100</div>
        
        <h2>Résumé des Découvertes</h2>
        {self._generate_summary_html()}
        
        <h2>Vérifications Détaillées</h2>
        {self._generate_findings_html()}
        
        <hr>
        <p style="color: #999; font-size: 12px;">Audit généré automatiquement par AEGIS</p>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filename
    
    def _count_by_severity(self) -> Dict:
        counts = defaultdict(int)
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return dict(counts)
    
    def _generate_summary_html(self) -> str:
        summary = self._count_by_severity()
        html = "<table><tr><th>Sévérité</th><th>Nombre</th></tr>"
        for severity, count in summary.items():
            html += f"<tr><td>{severity}</td><td>{count}</td></tr>"
        html += "</table>"
        return html
    
    def _generate_findings_html(self) -> str:
        html = ""
        for finding in self.findings:
            status = '<span class="pass">✅ OK</span>' if finding.result else '<span class="fail">❌ FAIL</span>'
            html += f"""
        <div class="finding {finding.severity.name}">
            <div class="finding-title">{finding.check_name} {status}</div>
            <div><strong>Sévérité :</strong> {finding.severity.name}</div>
            <div><strong>Message :</strong> {finding.message}</div>
            {f'<div><strong>Remédiation :</strong> {finding.remediation}</div>' if finding.remediation else ''}
            {f'<div class="evidence"><strong>Preuve :</strong><pre>{finding.evidence}</pre></div>' if finding.evidence else ''}
        </div>
"""
        return html

# ============================================================================
# MAIN
# ============================================================================

def main():
    # Vérifier les droits root
    if os.geteuid() != 0:
        print("⚠️  Ce script doit être exécuté en tant que root pour un audit complet")
        print("   Certaines vérifications seront ignorées")
    
    logger = SecurityLogger()
    logger.info("=== Démarrage de l'audit AEGIS ===")
    
    auditor = SecurityAuditor(logger)
    audit_results = auditor.run_full_audit()
    
    # Générer les rapports
    report_gen = ReportGenerator(audit_results, auditor.findings, auditor.score)
    
    json_report = report_gen.generate_json_report()
    html_report = report_gen.generate_html_report()
    
    logger.info(f"✅ Rapport JSON généré : {json_report}")
    logger.info(f"✅ Rapport HTML généré : {html_report}")
    
    # Affichage terminal
    print("\n" + "="*70)
    print("   RAPPORT D'AUDIT AEGIS — TechSud".center(70))
    print("="*70)
    print(f"Score : {auditor.score}/100")
    print(f"Hôte : {audit_results['hostname']}")
    print(f"Date : {audit_results['timestamp']}")
    print("\n--- Vérifications Critiques ---")
    
    for finding in auditor.findings:
        if finding.severity == SeverityLevel.CRITIQUE:
            status = "✅" if finding.result else "❌"
            print(f"{status} {finding.check_name}: {finding.message}")
    
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
