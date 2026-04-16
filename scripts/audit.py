#!/usr/bin/env python3
"""
Projet AEGIS — TechSud
Script d'audit automatisé du système
IPSSI BTC1 — Groupe 4
"""

import subprocess
import json
import datetime
import socket
import os
import stat

def get_open_ports():
    result = subprocess.run(
        ['ss', '-tulnp'],
        capture_output=True, text=True
    )
    ports = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5:
            ports.append({
                "protocole": parts[0],
                "etat": parts[1],
                "adresse": parts[4],
            })
    return ports

def get_services():
    result = subprocess.run(
        ['systemctl', 'list-units', '--type=service',
         '--state=running', '--no-pager'],
        capture_output=True, text=True
    )
    services = []
    for line in result.stdout.splitlines():
        if '.service' in line:
            parts = line.strip().split()
            if parts:
                services.append(parts[0])
    return services

def check_security():
    checks = {}

    # UFW actif ?
    ufw = subprocess.run(
        ['sudo', 'ufw', 'status'],
        capture_output=True, text=True
    )
    checks['ufw_actif'] = (
	 'active' in ufw.stdout.lower() or
	 'actif' in ufw.stdout.lower()
    )

    # Fail2ban actif ?
    f2b = subprocess.run(
        ['systemctl', 'is-active', 'fail2ban'],
        capture_output=True, text=True
    )
    checks['fail2ban_actif'] = f2b.stdout.strip() == 'active'

    # SSH — lecture config
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            ssh = f.read()

        # PermitRootLogin no ?
        checks['ssh_no_root'] = 'PermitRootLogin no' in ssh

        # Port custom — vérifie que les ports SSH courants sont évités
        ports_ssh_courants = [
            'Port 22\n', 'Port 22 ',
            'Port 2222\n', 'Port 2222 ',
            'Port 222\n', 'Port 222 ',
            'Port 1022\n', 'Port 1022 ',
            'Port 2200\n', 'Port 2200 ',
            'Port 2202\n', 'Port 2202 ',
            'Port 2022\n', 'Port 2022 ',
            'Port 22222\n', 'Port 22222 ',
        ]
        # Port custom = aucun des ports courants n'est utilisé
        # ET un Port est bien défini
        port_courant_utilise = any(p in ssh for p in ports_ssh_courants)
        port_defini = 'Port ' in ssh
        checks['ssh_port_custom'] = port_defini and not port_courant_utilise

        # PasswordAuthentication no ?
        checks['ssh_no_password'] = 'PasswordAuthentication no' in ssh

        # AllowTcpForwarding no ?
        checks['ssh_no_tcp_forwarding'] = 'AllowTcpForwarding no' in ssh

        # PermitRootLogin no ?
        checks['ssh_x11_forwarding_off'] = 'X11Forwarding no' in ssh

        # MaxAuthTries <= 3 ?
        for line in ssh.splitlines():
            if line.startswith('MaxAuthTries'):
                try:
                    val = int(line.split()[1])
                    checks['ssh_max_auth_tries'] = val <= 3
                except:
                    checks['ssh_max_auth_tries'] = False
                break
        else:
            checks['ssh_max_auth_tries'] = False

    except Exception as e:
        checks['ssh_config'] = f'inaccessible: {e}'

    # SUID sur find (faille) ?
    find = subprocess.run(
        ['find', '/usr/bin/find', '-perm', '-4000'],
        capture_output=True, text=True
    )
    checks['suid_find_faille'] = bool(find.stdout.strip())

    # Webshell présent ?
    webshell_paths = [
        '/var/www/html/upload/shell.php',
        '/var/www/html/shell.php',
        '/var/www/html/upload/cmd.php',
        '/var/www/html/cmd.php',
    ]
    checks['webshell_present'] = any(
        os.path.exists(p) for p in webshell_paths
    )

    # Config.php — vérifie les permissions (faille si lisible par tous)
    config_path = '/var/www/html/config.php'
    if os.path.exists(config_path):
        file_stat = os.stat(config_path)
        file_mode = file_stat.st_mode
        # Faille si lisible par "others" (world-readable)
        world_readable = bool(file_mode & stat.S_IROTH)
        checks['config_php_expose'] = world_readable
    else:
        checks['config_php_expose'] = False

    # CrowdSec actif ?
    crowdsec = subprocess.run(
        ['systemctl', 'is-active', 'crowdsec'],
        capture_output=True, text=True
    )
    checks['crowdsec_actif'] = crowdsec.stdout.strip() == 'active'

    # Auditd actif ?
    auditd = subprocess.run(
        ['systemctl', 'is-active', 'auditd'],
        capture_output=True, text=True
    )
    checks['auditd_actif'] = auditd.stdout.strip() == 'active'

    # AppArmor actif ?
    apparmor = subprocess.run(
        ['systemctl', 'is-active', 'apparmor'],
        capture_output=True, text=True
    )
    checks['apparmor_actif'] = apparmor.stdout.strip() == 'active'

    # Compte deploy verrouillé ?
    try:
        with open('/etc/passwd', 'r') as f:
            passwd = f.read()
        checks['deploy_shell_nologin'] = (
            'deploy' not in passwd or
            'deploy:/usr/sbin/nologin' in passwd or
            'deploy:/bin/false' in passwd
        )
    except:
        checks['deploy_shell_nologin'] = False

    return checks

def afficher_rapport(rapport):
    print("\n" + "="*55)
    print("      RAPPORT D'AUDIT AEGIS — TechSud")
    print("="*55)
    print(f"Date     : {rapport['date']}")
    print(f"Hôte     : {rapport['hostname']}")

    print("\n--- Ports ouverts ---")
    for p in rapport['ports_ouverts']:
        print(f"  {p['protocole']:<6} {p['etat']:<12} {p['adresse']}")

    print("\n--- Services actifs ---")
    for s in rapport['services_actifs']:
        print(f"  {s}")

    print("\n--- Vérifications sécurité ---")
    s = rapport['securite']

    # Pare-feu
    print("\n  [Pare-feu]")
    print(f"  UFW actif              : {'✅' if s.get('ufw_actif') else '❌'}")
    print(f"  Fail2ban actif         : {'✅' if s.get('fail2ban_actif') else '❌'}")
    print(f"  CrowdSec actif         : {'✅' if s.get('crowdsec_actif') else '❌'}")

    # SSH
    print("\n  [SSH]")
    print(f"  SSH no-root            : {'✅' if s.get('ssh_no_root') else '❌'}")
    print(f"  SSH port custom        : {'✅' if s.get('ssh_port_custom') else '❌ Port SSH courant détecté'}")
    print(f"  SSH clés seules        : {'✅' if s.get('ssh_no_password') else '❌'}")
    print(f"  SSH no TCP forwarding  : {'✅' if s.get('ssh_no_tcp_forwarding') else '❌'}")
    print(f"  SSH X11 forwarding off : {'✅' if s.get('ssh_x11_forwarding_off') else '❌'}")
    print(f"  SSH MaxAuthTries <= 3  : {'✅' if s.get('ssh_max_auth_tries') else '❌'}")

    # Failles web
    print("\n  [Web]")
    print(f"  SUID find (faille)     : {'❌ FAILLE' if s.get('suid_find_faille') else '✅ OK'}")
    print(f"  Webshell présent       : {'❌ FAILLE' if s.get('webshell_present') else '✅ OK'}")
    print(f"  Config.php world-read  : {'❌ FAILLE' if s.get('config_php_expose') else '✅ OK'}")

    # Système
    print("\n  [Système]")
    print(f"  Auditd actif           : {'✅' if s.get('auditd_actif') else '❌'}")
    print(f"  AppArmor actif         : {'✅' if s.get('apparmor_actif') else '❌'}")
    print(f"  Compte deploy bloqué   : {'✅' if s.get('deploy_shell_nologin') else '❌'}")

    print("\n" + "="*55)

def main():
    rapport = {
        "date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "hostname": socket.gethostname(),
        "ports_ouverts": get_open_ports(),
        "services_actifs": get_services(),
        "securite": check_security()
    }

    afficher_rapport(rapport)

    with open('audit_aegis.json', 'w') as f:
        json.dump(rapport, f, indent=2, ensure_ascii=False)
    print(f"\n✅ Rapport exporté : audit_aegis.json\n")

if __name__ == "__main__":
    main()
