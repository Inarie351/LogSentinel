# LogSentinel

Analyseur de logs d'authentification SSH — détection de tentatives de connexion suspectes (brute-force) et génération de rapports.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)

## Description

LogSentinel parse les fichiers `auth.log` (format syslog standard sur Debian/Ubuntu) pour identifier les IPs qui multiplient les tentatives de connexion échouées — un signe classique d'attaque par brute-force sur SSH.

L'outil analyse et recommande, sans jamais toucher au système de lui-même.

## Fonctionnalités

- Parsing des logs SSH (échecs, utilisateurs invalides, connexions réussies)
- Agrégation et classement des IPs par nombre de tentatives échouées
- Détection des IPs suspectes selon un seuil configurable
- Recommandations textuelles (blocage, fail2ban, désactivation de l'auth par mot de passe...)
- Export du rapport en **JSON** (exploitable par un autre outil) et **Markdown** (lisible, versionnable)

## Installation

```bash
git clone https://github.com/<ton-username>/log-sentinel.git
cd log-sentinel
pip install -e .
```

Aucune dépendance externe : uniquement la bibliothèque standard Python 3.8+.

## Utilisation

### Analyse simple (log d'exemple fourni)

```bash
logsentinel sample_logs/auth.log.sample
```

Sortie :

```
LOGSENTINEL
────────────────────────────────────────

SSH LOGIN ANALYSIS
────────────────────────────────────────
185.220.101.45      19 failed attempts  ⚠ SUSPICIOUS
10.0.0.12           3 failed attempts
45.155.204.19       2 failed attempts

Top attacking IP
────────────────────────────────────────
185.220.101.45

Recommendation
────────────────────────────────────────
→ Considérer le blocage de 185.220.101.45 (19 tentatives échouées)
→ Envisager l'installation de fail2ban pour un blocage automatique
→ Vérifier si l'authentification par mot de passe peut être désactivée (clés SSH uniquement)
```

### Sur un vrai serveur

```bash
logsentinel /var/log/auth.log
```

### Options avancées

```bash
# Changer le seuil de détection (défaut: 10 échecs)
logsentinel /var/log/auth.log --threshold 15

# Générer les rapports JSON et Markdown
logsentinel /var/log/auth.log --json --markdown

# Choisir le dossier de sortie des rapports
logsentinel /var/log/auth.log --json --output-dir ./reports
```

## Structure du projet

```
log-sentinel/
├── logsentinel/
│   ├── __init__.py
│   ├── cli.py           # Point d'entrée CLI
│   ├── parser.py        # Extraction des événements depuis les logs
│   └── analyzer.py      # Agrégation, détection, recommandations
├── sample_logs/
│   └── auth.log.sample  # Log d'exemple pour tester sans serveur
├── pyproject.toml
└── README.md
```

## Comment fonctionne la détection

1. **Parsing** — chaque ligne du log est testée contre des regex ciblant les messages `sshd` (`Failed password`, `Accepted password/publickey`, utilisateurs invalides)
2. **Agrégation** — les événements sont regroupés par IP source, avec le décompte des échecs et la liste des noms d'utilisateurs tentés
3. **Détection** — toute IP dépassant le seuil d'échecs (par défaut 10) est marquée `SUSPICIOUS`
4. **Recommandation** — le rapport final propose des actions concrètes, à valider et appliquer manuellement

## Licence

MIT
