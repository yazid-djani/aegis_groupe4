# 🛡️ Projet AEGIS — TechSud

> Mission de sécurisation du Système d'Information de la PME fictive TechSud  
> Dans le cadre du projet pédagogique IPSSI — BTC1 — 2026

---

## 👥 Groupe 4

| Nom           |
|---------------|
| Yazid Djani   | 
| Léo Cohen     | 
| Théo Schwartz | 
| Dilhan Noksa  | 

---

## 🎯 Contexte

La PME TechSud a subi une compromission de son système d'information.  
Notre mission est d'auditer, sécuriser et documenter l'infrastructure.

**Serveur cible :** SRV-WEB-01 — Ubuntu — `172.20.10.5`  
**Machine attaquante :** Kali Linux — `172.20.10.4`

---

## 🔴 Vulnérabilités identifiées (avant sécurisation)

| # | Vulnérabilité | Criticité |
|---|---------------|-----------|
| 1 | Webshell PHP accessible publiquement | 🔴 Critique |
| 2 | Connexion SSH root autorisée | 🔴 Critique |
| 3 | Compte `deploy` actif avec mot de passe faible | 🔴 Critique |
| 4 | Bit SUID activé sur `/usr/bin/find` | 🔴 Critique |
| 5 | Credentials en clair dans `config.php` | 🔴 Critique |
| 6 | Aucun pare-feu actif | 🟠 Élevé |
| 7 | Aucun système anti-brute force | 🟠 Élevé |
| 8 | Permissions 777 sur le dossier `/upload/` | 🟠 Élevé |

---

## 🛡️ Mesures de sécurisation appliquées

| # | Action | Statut |
|---|--------|--------|
| 1 | Suppression du webshell + permissions corrigées | ✅ |
| 2 | SSH — PermitRootLogin no | ✅ |
| 3 | SSH — Port custom 2222 | ✅ |
| 4 | SSH — PasswordAuthentication no + clés | ✅ |
| 5 | Pare-feu UFW configuré et activé | ✅ |
| 6 | Fail2ban installé et actif | ✅ |
| 7 | SUID retiré de `/usr/bin/find` | ✅ |
| 8 | Compte `deploy` désactivé | ✅ |

---

## 🐍 Script Python d'audit

Le script `scripts/audit.py` permet de :
- Inventorier les ports ouverts
- Lister les services actifs
- Vérifier les points de sécurité de base
- Exporter le résultat en JSON

**Utilisation :**
```bash
sudo python3 scripts/audit.py
```

---

## 🔗 Ressources

- [Documentation Lynis](https://cisofy.com/lynis/)
- [Fail2ban](https://fail2ban.readthedocs.io)
- [UFW](https://help.ubuntu.com/community/UFW)
- [man.debian.org](https://man.debian.org)
