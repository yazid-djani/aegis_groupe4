#!/usr/bin/env python3
"""
Projet AEGIS — TechSud
Script d'audit automatisé du système (VERSION DURCIE)
IPSSI BTC1 — Groupe 4

Fonctionnalités :
- Gestion robuste des erreurs
- Analyse de sécurité approfondie
- Système de score (0-100)
- Rapports JSON + HTML
- Logging structuré
- Vérifications CrowdSec, auditd, AppArmor
- Scan contenu webshell (patterns PHP dangereux)
"""

import subprocess
import json
import datetime
import socket
import os
import sys
import stat
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict

# ============================================================================
# ENUMS & TYPES
# ============================================================================

class SeverityLevel(Enum):
    CRITIQUE = 0
    ELEVE    = 1
    MOYEN    = 2
    FAIBLE   = 3
    INFO     = 4

@dataclass
class SecurityFinding:
    check_name:   str
    result:       bool
    severity:     SeverityLevel
    message:      str
    remediation:  str = ""
    evidence:     str = ""

# ============================================================================
# LOGGER
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

    def info(self, msg):     self.logger.info(msg)
    def warning(self, msg):  self.logger.warning(msg)
    def error(self, msg):    self.logger.error(msg)
    def critical(self, msg): self.logger.critical(msg)

# ============================================================================
# RUNNER
# ============================================================================

class CommandRunner:
    def __init__(self, timeout: int = 10, logger: SecurityLogger = None):
        self.timeout = timeout
        self.logger  = logger or SecurityLogger()

    def run(self, cmd: List[str]) -> Tuple[bool, str, str]:
        """Exécute une commande — retourne (success, stdout, stderr)"""
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
            self.logger.error(f"Timeout : {' '.join(cmd)}")
            return (False, "", "Timeout")
        except FileNotFoundError:
            self.logger.warning(f"Commande introuvable : {cmd[0]}")
            return (False, "", "Command not found")
        except Exception as e:
            self.logger.error(f"Erreur : {e}")
            return (False, "", str(e))

# ============================================================================
# AUDITEUR
# ============================================================================

class SecurityAuditor:
    def __init__(self, logger: SecurityLogger = None):
        self.logger   = logger or SecurityLogger()
        self.runner   = CommandRunner(logger=self.logger)
        self.findings: List[SecurityFinding] = []
        self.score    = 100

    def _deduct(self, points: int):
        """Déduit des points sans passer sous 0"""
        self.score = max(0, self.score - points)

    # ------------------------------------------------------------------ RÉSEAU

    def check_open_ports(self) -> Dict[str, Any]:
        """Liste les ports ouverts via ss"""
        success, stdout, stderr = self.runner.run(['ss', '-tulnp'])
        ports = []
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                ports.append({
                    "protocole": parts[0],
                    "etat":      parts[1],
                    "adresse":   parts[4],
                })
        return {"ports_ouverts": ports, "nombre": len(ports)}

    def check_listening_services(self) -> Dict[str, Any]:
        """Détecte les services réseau en écoute (via ss)"""
        success, stdout, stderr = self.runner.run(['ss', '-tulnp'])
        services = []
        for line in stdout.splitlines()[1:]:
            if 'LISTEN' in line or 'UNCONN' in line:
                services.append(line.strip())

        self.findings.append(SecurityFinding(
            check_name="listening_services",
            result=True,
            severity=SeverityLevel.INFO,
            message=f"{len(services)} service(s) réseau en écoute",
            evidence="\n".join(services[:10])
        ))
        return {"services_reseau": services}

    # -------------------------------------------------------------------- SSH

    def check_ssh_hardening(self) -> Dict[str, Any]:
        """Vérifie le durcissement SSH"""
        sshd_config = "/etc/ssh/sshd_config"
        checks = {}

        if not os.path.exists(sshd_config):
            self.logger.error("sshd_config non trouvé")
            return {"ssh_accessible": False}

        try:
            with open(sshd_config, 'r') as f:
                ssh = f.read()
        except PermissionError:
            self.logger.error("Accès refusé à sshd_config")
            return {"ssh_accessible": False}

        # PermitRootLogin no
        checks['ssh_no_root'] = 'PermitRootLogin no' in ssh
        self.findings.append(SecurityFinding(
            check_name="ssh_no_root",
            result=checks['ssh_no_root'],
            severity=SeverityLevel.CRITIQUE,
            message="PermitRootLogin no",
            remediation="Ajouter 'PermitRootLogin no' dans sshd_config"
        ))
        if not checks['ssh_no_root']:
            self._deduct(15)

        # PasswordAuthentication no
        checks['ssh_no_password'] = 'PasswordAuthentication no' in ssh
        self.findings.append(SecurityFinding(
            check_name="ssh_no_password",
            result=checks['ssh_no_password'],
            severity=SeverityLevel.ELEVE,
            message="PasswordAuthentication no",
            remediation="Ajouter 'PasswordAuthentication no' dans sshd_config"
        ))
        if not checks['ssh_no_password']:
            self._deduct(10)

        # Port custom
        ports_courants = [
            'Port 22\n',    'Port 22 ',
            'Port 222\n',   'Port 222 ',
            'Port 1022\n',  'Port 1022 ',
            'Port 2022\n',  'Port 2022 ',
            'Port 2200\n',  'Port 2200 ',
            'Port 2202\n',  'Port 2202 ',
            'Port 2222\n',  'Port 2222 ',
            'Port 22222\n', 'Port 22222 ',
        ]
        port_courant = any(p in ssh for p in ports_courants)
        port_defini  = 'Port ' in ssh
        checks['ssh_port_custom'] = port_defini and not port_courant
        self.findings.append(SecurityFinding(
            check_name="ssh_port_custom",
            result=checks['ssh_port_custom'],
            severity=SeverityLevel.MOYEN,
            message="Port SSH non standard",
            remediation="Changer le port dans sshd_config (ex: Port 53032)"
        ))
        if not checks['ssh_port_custom']:
            self._deduct(5)

        # AllowTcpForwarding no
        checks['ssh_no_tcp_forwarding'] = 'AllowTcpForwarding no' in ssh
        self.findings.append(SecurityFinding(
            check_name="ssh_no_tcp_forwarding",
            result=checks['ssh_no_tcp_forwarding'],
            severity=SeverityLevel.MOYEN,
            message="AllowTcpForwarding no",
            remediation="Ajouter 'AllowTcpForwarding no' dans sshd_config"
        ))
        if not checks['ssh_no_tcp_forwarding']:
            self._deduct(5)

        # X11Forwarding no
        checks['ssh_no_x11'] = 'X11Forwarding no' in ssh
        self.findings.append(SecurityFinding(
            check_name="ssh_no_x11",
            result=checks['ssh_no_x11'],
            severity=SeverityLevel.MOYEN,
            message="X11Forwarding no",
            remediation="Ajouter 'X11Forwarding no' dans sshd_config"
        ))
        if not checks['ssh_no_x11']:
            self._deduct(5)

        # MaxAuthTries <= 3
        checks['ssh_max_auth_tries'] = False
        for line in ssh.splitlines():
            if line.startswith('MaxAuthTries'):
                try:
                    val = int(line.split()[1])
                    checks['ssh_max_auth_tries'] = val <= 3
                except:
                    pass
                break
        self.findings.append(SecurityFinding(
            check_name="ssh_max_auth_tries",
            result=checks['ssh_max_auth_tries'],
            severity=SeverityLevel.MOYEN,
            message="MaxAuthTries <= 3",
            remediation="Ajouter 'MaxAuthTries 3' dans sshd_config"
        ))
        if not checks['ssh_max_auth_tries']:
            self._deduct(5)

        # AllowAgentForwarding no
        checks['ssh_no_agent_forwarding'] = 'AllowAgentForwarding no' in ssh
        self.findings.append(SecurityFinding(
            check_name="ssh_no_agent_forwarding",
            result=checks['ssh_no_agent_forwarding'],
            severity=SeverityLevel.FAIBLE,
            message="AllowAgentForwarding no",
            remediation="Ajouter 'AllowAgentForwarding no' dans sshd_config"
        ))

        return checks

    # --------------------------------------------------------------- PARE-FEU

    def check_firewall_status(self) -> Dict[str, Any]:
        """Vérifie UFW — utilise sudo pour avoir le vrai statut"""
        success, stdout, stderr = self.runner.run(['sudo', 'ufw', 'status'])
        ufw_active = (
            'active' in stdout.lower() or
            'actif'  in stdout.lower()
        )
        self.findings.append(SecurityFinding(
            check_name="ufw_firewall",
            result=ufw_active,
            severity=SeverityLevel.CRITIQUE,
            message="Pare-feu UFW actif",
            remediation="sudo ufw enable"
        ))
        if not ufw_active:
            self._deduct(15)
        return {"ufw_active": ufw_active}

    def check_fail2ban(self) -> Dict[str, Any]:
        """Vérifie fail2ban"""
        success, stdout, _ = self.runner.run(
            ['systemctl', 'is-active', 'fail2ban']
        )
        is_active = stdout.strip() == 'active'
        self.findings.append(SecurityFinding(
            check_name="fail2ban_service",
            result=is_active,
            severity=SeverityLevel.ELEVE,
            message="Service fail2ban actif",
            remediation="sudo systemctl enable fail2ban --now"
        ))
        if not is_active:
            self._deduct(10)
        return {"fail2ban_active": is_active}

    def check_crowdsec(self) -> Dict[str, Any]:
        """Vérifie CrowdSec"""
        success, stdout, _ = self.runner.run(
            ['systemctl', 'is-active', 'crowdsec']
        )
        is_active = stdout.strip() == 'active'
        self.findings.append(SecurityFinding(
            check_name="crowdsec_service",
            result=is_active,
            severity=SeverityLevel.ELEVE,
            message="CrowdSec IDS/IPS actif",
            remediation="sudo systemctl enable crowdsec --now"
        ))
        if not is_active:
            self._deduct(10)
        return {"crowdsec_active": is_active}

    # ----------------------------------------------------------- PERMISSIONS

    def check_dangerous_suid(self) -> Dict[str, Any]:
        """Détecte les binaires SUID dangereux"""
        dangerous = [
            '/usr/bin/find',
            '/usr/bin/pkexec',
            '/usr/sbin/pppd',
        ]
        found = []
        for binary in dangerous:
            if not os.path.exists(binary):
                continue
            success, stdout, _ = self.runner.run(
                ['find', binary, '-perm', '-4000']
            )
            if stdout.strip():
                found.append(binary)

        self.findings.append(SecurityFinding(
            check_name="dangerous_suid",
            result=len(found) == 0,
            severity=SeverityLevel.CRITIQUE,
            message=f"Binaires SUID dangereux : {len(found)}",
            remediation="sudo chmod u-s <binaire>",
            evidence="\n".join(found) if found else "Aucun"
        ))
        if found:
            self._deduct(20)
        return {"suid_dangereux": found}

    def check_file_permissions(self) -> Dict[str, Any]:
        """Vérifie les permissions des fichiers critiques"""
        critical = {
            '/etc/passwd':  '0644',
            '/etc/shadow':  '0640',
            '/etc/sudoers': '0440',
        }
        violations = []
        for filepath, expected in critical.items():
            if not os.path.exists(filepath):
                continue
            try:
                actual = oct(os.stat(filepath).st_mode)[-4:]
                if actual != expected:
                    violations.append({
                        "fichier": filepath,
                        "attendu": expected,
                        "actuel":  actual
                    })
            except PermissionError:
                pass

        self.findings.append(SecurityFinding(
            check_name="critical_file_permissions",
            result=len(violations) == 0,
            severity=SeverityLevel.ELEVE,
            message=f"Violations de permissions : {len(violations)}",
            evidence=json.dumps(violations, indent=2) if violations else "Aucune"
        ))
        if violations:
            self._deduct(15)
        return {"violations_permissions": violations}

    # --------------------------------------------------------------- COMPTES

    def check_uid_zero(self) -> Dict[str, Any]:
        """Vérifie qu'aucun utilisateur non-root n'a l'UID 0"""
        bad_users = []
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.split(':')
                    if len(parts) >= 3 and parts[2] == '0' and parts[0] != 'root':
                        bad_users.append(parts[0])
        except Exception as e:
            self.logger.error(f"Erreur /etc/passwd : {e}")

        self.findings.append(SecurityFinding(
            check_name="uid_zero_check",
            result=len(bad_users) == 0,
            severity=SeverityLevel.CRITIQUE,
            message=f"Utilisateurs UID 0 non-root : {len(bad_users)}",
            evidence=", ".join(bad_users) if bad_users else "Aucun"
        ))
        if bad_users:
            self._deduct(25)
        return {"uid_zero_users": bad_users}

    def check_deploy_account(self) -> Dict[str, Any]:
        """Vérifie que le compte deploy est verrouillé"""
        try:
            with open('/etc/passwd', 'r') as f:
                passwd = f.read()
            locked = (
                'deploy' not in passwd or
                'deploy:/usr/sbin/nologin' in passwd or
                'deploy:/bin/false' in passwd
            )
        except:
            locked = False

        self.findings.append(SecurityFinding(
            check_name="deploy_account_locked",
            result=locked,
            severity=SeverityLevel.CRITIQUE,
            message="Compte deploy verrouillé",
            remediation="sudo usermod -L deploy && sudo usermod -s /usr/sbin/nologin deploy"
        ))
        if not locked:
            self._deduct(15)
        return {"deploy_locked": locked}

    # ---------------------------------------------------------------- SERVICES

    def check_running_services(self) -> Dict[str, Any]:
        """Liste les services actifs"""
        success, stdout, _ = self.runner.run([
            'systemctl', 'list-units',
            '--type=service', '--state=running', '--no-pager'
        ])
        services = []
        for line in stdout.splitlines():
            if '.service' in line:
                parts = line.strip().split()
                if parts:
                    services.append(parts[0])
        return {"services_actifs": services}

    def check_auditd(self) -> Dict[str, Any]:
        """Vérifie auditd"""
        success, stdout, _ = self.runner.run(
            ['systemctl', 'is-active', 'auditd']
        )
        is_active = stdout.strip() == 'active'
        self.findings.append(SecurityFinding(
            check_name="auditd_service",
            result=is_active,
            severity=SeverityLevel.ELEVE,
            message="Service auditd actif",
            remediation="sudo systemctl enable auditd --now"
        ))
        if not is_active:
            self._deduct(8)
        return {"auditd_active": is_active}

    def check_apparmor(self) -> Dict[str, Any]:
        """Vérifie AppArmor"""
        success, stdout, _ = self.runner.run(
            ['systemctl', 'is-active', 'apparmor']
        )
        is_active = stdout.strip() == 'active'
        self.findings.append(SecurityFinding(
            check_name="apparmor_service",
            result=is_active,
            severity=SeverityLevel.MOYEN,
            message="AppArmor (MAC framework) actif",
            remediation="sudo systemctl enable apparmor --now"
        ))
        if not is_active:
            self._deduct(5)
        return {"apparmor_active": is_active}

    # -------------------------------------------------------------------  WEB

    def check_webshell(self) -> Dict[str, Any]:
        """Détecte les webshells connus par leur chemin"""
        paths = [
            '/var/www/html/upload/shell.php',
            '/var/www/html/shell.php',
            '/var/www/html/upload/cmd.php',
            '/var/www/html/cmd.php',
            '/tmp/shell.php',
        ]
        found = [p for p in paths if os.path.exists(p)]

        self.findings.append(SecurityFinding(
            check_name="webshell_detection",
            result=len(found) == 0,
            severity=SeverityLevel.CRITIQUE,
            message=f"Webshells détectés (par chemin) : {len(found)}",
            remediation="sudo rm <fichier>",
            evidence=", ".join(found) if found else "Aucun"
        ))
        if found:
            self._deduct(30)
        return {"webshells": found}

    def check_webshell_content(self) -> Dict[str, Any]:
        """
        Scanne le contenu des fichiers PHP pour détecter
        des patterns caractéristiques de webshell.
        Détecte même les webshells renommés (ex: image.php).
        """
        # Patterns dangereux — couvrent les webshells classiques
        patterns_dangereux = [
            'system($_GET',
            'system($_POST',
            'exec($_GET',
            'exec($_POST',
            'shell_exec($_GET',
            'shell_exec($_POST',
            'passthru($_GET',
            'passthru($_POST',
            'proc_open($_GET',
            'proc_open($_POST',
            "isset($_GET['cmd'])",
            'isset($_GET["cmd"])',
            "isset($_POST['cmd'])",
            'isset($_POST["cmd"])',
            "$_GET['cmd']",
            '$_GET["cmd"]',
            "$_POST['cmd']",
            '$_POST["cmd"]',
            'base64_decode($_',
            'eval($_',
            'assert($_',
        ]

        # Dossiers à scanner récursivement
        dossiers = [
            '/var/www/html',
            '/var/www',
            '/tmp',
        ]

        fichiers_suspects = []

        for dossier in dossiers:
            if not os.path.exists(dossier):
                continue
            for root, dirs, files in os.walk(dossier):
                for fichier in files:
                    if not fichier.endswith('.php'):
                        continue
                    chemin = os.path.join(root, fichier)
                    try:
                        with open(chemin, 'r', errors='ignore') as f:
                            contenu = f.read()
                        for pattern in patterns_dangereux:
                            if pattern in contenu:
                                fichiers_suspects.append({
                                    "fichier": chemin,
                                    "pattern": pattern,
                                })
                                break  # Un match par fichier suffit
                    except PermissionError:
                        pass
                    except Exception as e:
                        self.logger.warning(f"Erreur lecture {chemin} : {e}")

        self.findings.append(SecurityFinding(
            check_name="webshell_content_scan",
            result=len(fichiers_suspects) == 0,
            severity=SeverityLevel.CRITIQUE,
            message=f"Fichiers PHP avec patterns webshell : {len(fichiers_suspects)}",
            remediation="sudo rm <fichier suspect>",
            evidence=json.dumps(fichiers_suspects, indent=2)
                     if fichiers_suspects else "Aucun pattern dangereux détecté"
        ))

        if fichiers_suspects:
            self._deduct(30)

        return {"webshells_contenu": fichiers_suspects}

    def check_exposed_config(self) -> Dict[str, Any]:
        """Détecte les fichiers config lisibles par tous"""
        config_path = '/var/www/html/config.php'
        exposed  = False
        evidence = "Fichier absent"

        if os.path.exists(config_path):
            try:
                mode = os.stat(config_path).st_mode
                world_readable = bool(mode & stat.S_IROTH)
                exposed  = world_readable
                evidence = (
                    f"Permissions : {oct(mode)[-4:]} — "
                    f"{'lisible par tous !' if world_readable else 'OK'}"
                )
            except PermissionError:
                evidence = "Accès refusé"

        self.findings.append(SecurityFinding(
            check_name="exposed_config",
            result=not exposed,
            severity=SeverityLevel.CRITIQUE,
            message="config.php non lisible publiquement",
            remediation="sudo chmod 640 /var/www/html/config.php",
            evidence=evidence
        ))
        if exposed:
            self._deduct(20)
        return {"config_expose": exposed}

    # ------------------------------------------------------------------- LOGS

    def check_system_logs(self) -> Dict[str, Any]:
        """Vérifie la présence des fichiers de logs"""
        log_files = [
            '/var/log/auth.log',
            '/var/log/syslog',
        ]
        active = []
        for logfile in log_files:
            if os.path.exists(logfile):
                try:
                    size = os.path.getsize(logfile)
                    active.append({"fichier": logfile, "taille_octets": size})
                except:
                    pass
        return {"logs_systeme": active}

    # ------------------------------------------------------------ AUDIT COMPLET

    def run_full_audit(self) -> Dict[str, Any]:
        self.logger.info("=== Démarrage audit AEGIS ===")

        results = {
            "timestamp":        datetime.datetime.now().isoformat(),
            "hostname":         socket.gethostname(),
            "user":             os.getenv('USER', 'unknown'),

            # Réseau
            "ports":            self.check_open_ports(),
            "services_reseau":  self.check_listening_services(),

            # SSH
            "ssh":              self.check_ssh_hardening(),

            # Pare-feu & IDS
            "firewall":         self.check_firewall_status(),
            "fail2ban":         self.check_fail2ban(),
            "crowdsec":         self.check_crowdsec(),

            # Permissions
            "suid":             self.check_dangerous_suid(),
            "permissions":      self.check_file_permissions(),

            # Comptes
            "uid_zero":         self.check_uid_zero(),
            "deploy_account":   self.check_deploy_account(),

            # Services
            "services":         self.check_running_services(),
            "auditd":           self.check_auditd(),
            "apparmor":         self.check_apparmor(),

            # Web
            "webshell":         self.check_webshell(),
            "webshell_content": self.check_webshell_content(),
            "config_expose":    self.check_exposed_config(),

            # Logs
            "logs":             self.check_system_logs(),
        }

        self.logger.info(f"Audit terminé — Score final : {self.score}/100")
        return results

# ============================================================================
# RAPPORTS
# ============================================================================

class ReportGenerator:
    def __init__(self, results: Dict, findings: List[SecurityFinding], score: int):
        self.results  = results
        self.findings = findings
        self.score    = score

    def _count_by_severity(self) -> Dict:
        counts = defaultdict(int)
        for f in self.findings:
            counts[f.severity.name] += 1
        return dict(counts)

    def generate_json(self, filename: str = "audit_aegis.json") -> str:
        report = {
            "metadata": {
                "timestamp":    self.results["timestamp"],
                "hostname":     self.results["hostname"],
                "score":        self.score,
                "distribution": self._count_by_severity(),
                "critiques":    sum(1 for f in self.findings
                                    if f.severity == SeverityLevel.CRITIQUE
                                    and not f.result)
            },
            "resultats": self.results,
            "findings": [
                {
                    "nom":         f.check_name,
                    "ok":          f.result,
                    "severite":    f.severity.name,
                    "message":     f.message,
                    "remediation": f.remediation,
                    "preuve":      f.evidence,
                }
                for f in self.findings
            ]
        }
        with open(filename, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        return filename

    def generate_html(self, filename: str = "audit_aegis.html") -> str:
        score_color = (
            '#28a745' if self.score >= 80
            else '#ffc107' if self.score >= 60
            else '#dc3545'
        )
        findings_html = ""
        for f in self.findings:
            css  = f.severity.name
            icon = "✅" if f.result else "❌"
            extra = ""
            if f.remediation:
                extra += f"<div><strong>Remédiation :</strong> {f.remediation}</div>"
            if f.evidence:
                extra += (
                    f"<div class='evidence'>"
                    f"<strong>Preuve :</strong><pre>{f.evidence}</pre></div>"
                )
            findings_html += f"""
            <div class="finding {css}">
                <div class="finding-title">{icon} {f.check_name}</div>
                <div><strong>Sévérité :</strong> {f.severity.name}</div>
                <div><strong>Message :</strong> {f.message}</div>
                {extra}
            </div>"""

        dist      = self._count_by_severity()
        dist_html = "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in dist.items()
        )

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <title>Audit AEGIS — TechSud</title>
  <style>
    body  {{ font-family: Arial, sans-serif; margin:20px; background:#f5f5f5; }}
    .wrap {{ max-width:1100px; margin:auto; background:#fff;
             padding:24px; border-radius:6px;
             box-shadow:0 0 10px rgba(0,0,0,.1); }}
    h1    {{ color:#333; border-bottom:3px solid #007bff; padding-bottom:8px; }}
    h2    {{ color:#555; margin-top:28px; }}
    .score{{ font-size:52px; font-weight:bold; color:{score_color}; }}
    .finding      {{ margin:12px 0; padding:14px; border-left:4px solid;
                     border-radius:3px; }}
    .CRITIQUE     {{ background:#f8d7da; border-color:#dc3545; }}
    .ELEVE        {{ background:#fff3cd; border-color:#ffc107; }}
    .MOYEN        {{ background:#d1ecf1; border-color:#17a2b8; }}
    .FAIBLE       {{ background:#e9ecef; border-color:#6c757d; }}
    .INFO         {{ background:#e2f0fb; border-color:#007bff; }}
    .finding-title{{ font-weight:bold; margin-bottom:6px; }}
    .evidence     {{ background:#f9f9f9; padding:8px; margin-top:8px;
                     border-radius:3px; font-family:monospace;
                     font-size:12px; white-space:pre-wrap; }}
    table  {{ width:100%; border-collapse:collapse; margin:16px 0; }}
    th, td {{ padding:10px; text-align:left; border-bottom:1px solid #ddd; }}
    th     {{ background:#f0f0f0; }}
  </style>
</head>
<body>
<div class="wrap">
  <h1>🔒 Audit de Sécurité AEGIS — TechSud</h1>
  <p><strong>Date :</strong> {self.results['timestamp']}</p>
  <p><strong>Hôte :</strong> {self.results['hostname']}</p>

  <h2>Score de Sécurité</h2>
  <div class="score">{self.score} / 100</div>

  <h2>Distribution des findings</h2>
  <table>
    <tr><th>Sévérité</th><th>Nombre</th></tr>
    {dist_html}
  </table>

  <h2>Détail des vérifications</h2>
  {findings_html}

  <hr>
  <p style="color:#999;font-size:12px;">
    Rapport généré automatiquement par AEGIS · IPSSI BTC1
  </p>
</div>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as fh:
            fh.write(html)
        return filename

# ============================================================================
# AFFICHAGE TERMINAL
# ============================================================================

def afficher_terminal(results: Dict, findings: List[SecurityFinding], score: int):
    SEP = "=" * 60
    print(f"\n{SEP}")
    print("      RAPPORT D'AUDIT AEGIS — TechSud".center(60))
    print(SEP)
    print(f"  Date   : {results['timestamp']}")
    print(f"  Hôte   : {results['hostname']}")
    print(f"  Score  : {score}/100")

    categories = {
        "Pare-feu & IDS":  ["ufw_firewall", "fail2ban_service", "crowdsec_service"],
        "SSH":             ["ssh_no_root", "ssh_no_password", "ssh_port_custom",
                            "ssh_no_tcp_forwarding", "ssh_no_x11",
                            "ssh_max_auth_tries", "ssh_no_agent_forwarding"],
        "Web":             ["webshell_detection", "webshell_content_scan",
                            "exposed_config"],
        "Permissions":     ["dangerous_suid", "critical_file_permissions"],
        "Comptes":         ["uid_zero_check", "deploy_account_locked"],
        "Services":        ["auditd_service", "apparmor_service"],
    }

    findings_map = {f.check_name: f for f in findings}

    for cat, names in categories.items():
        print(f"\n  [{cat}]")
        for name in names:
            f = findings_map.get(name)
            if not f:
                continue
            icon = "✅" if f.result else "❌"
            sev  = f"[{f.severity.name}]" if not f.result else ""
            print(f"    {icon}  {f.message:<45} {sev}")

    print(f"\n{SEP}\n")

# ============================================================================
# MAIN
# ============================================================================

def main():
    if os.geteuid() != 0:
        print("⚠️  Lancez ce script avec sudo pour un audit complet.")
        print("   sudo python3 audit_durci.py\n")

    logger  = SecurityLogger()
    auditor = SecurityAuditor(logger)
    results = auditor.run_full_audit()

    gen       = ReportGenerator(results, auditor.findings, auditor.score)
    json_file = gen.generate_json("audit_aegis.json")
    html_file = gen.generate_html("audit_aegis.html")

    afficher_terminal(results, auditor.findings, auditor.score)

    print(f"✅ Rapport JSON : {json_file}")
    print(f"✅ Rapport HTML : {html_file}")
    print(f"✅ Log          : audit_aegis.log\n")


if __name__ == "__main__":
    main()
