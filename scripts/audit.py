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
    ufw = subprocess.run(['ufw', 'status'],
                         capture_output=True, text=True)
    checks['ufw_actif'] = 'active' in ufw.stdout.lower()

    # Fail2ban actif ?
    f2b = subprocess.run(
        ['systemctl', 'is-active', 'fail2ban'],
        capture_output=True, text=True
    )
    checks['fail2ban_actif'] = f2b.stdout.strip() == 'active'

    # SSH — PermitRootLogin no ?
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            ssh = f.read()
        checks['ssh_no_root'] = 'PermitRootLogin no' in ssh
        checks['ssh_port_custom'] = 'Port 2222' in ssh
        checks['ssh_no_password'] = 'PasswordAuthentication no' in ssh
    except:
        checks['ssh_config'] = 'inaccessible'

    # SUID sur find (faille) ?
    find = subprocess.run(
        ['find', '/usr/bin/find', '-perm', '-4000'],
        capture_output=True, text=True
    )
    checks['suid_find_faille'] = bool(find.stdout.strip())

    # Webshell présent ?
    checks['webshell_present'] = os.path.exists(
        '/var/www/html/upload/shell.php'
    )

    # Credentials en clair ?
    checks['config_php_present'] = os.path.exists(
        '/var/www/html/config.php'
    )

    return checks

def afficher_rapport(rapport):
    print("\n" + "="*50)
    print("   RAPPORT D'AUDIT AEGIS — TechSud")
    print("="*50)
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
    print(f"  UFW actif          : {'✅' if s.get('ufw_actif') else '❌'}")
    print(f"  Fail2ban actif     : {'✅' if s.get('fail2ban_actif') else '❌'}")
    print(f"  SSH no-root        : {'✅' if s.get('ssh_no_root') else '❌'}")
    print(f"  SSH port custom    : {'✅' if s.get('ssh_port_custom') else '❌'}")
    print(f"  SSH clés seules    : {'✅' if s.get('ssh_no_password') else '❌'}")
    print(f"  SUID find (faille) : {'❌ FAILLE' if s.get('suid_find_faille') else '✅ OK'}")
    print(f"  Webshell présent   : {'❌ FAILLE' if s.get('webshell_present') else '✅ OK'}")
    print(f"  Config.php exposé  : {'❌ FAILLE' if s.get('config_php_present') else '✅ OK'}")
    print("="*50)

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
