# LogSentinel

Analyseur de logs d'authentification SSH — détection de tentatives de connexion suspectes (brute-force) et génération de rapports.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)

## Origine du projet

L'idée de LogSentinel est née de l'utilisation de **Wazuh** lors d'un de mes stages.

Wazuh est une plateforme open source de sécurité (SIEM / XDR) qui centralise la collecte des logs d'un parc de machines, détecte les intrusions, analyse les vulnérabilités et aide à la réponse à incident. Concrètement, il surveille en continu les événements système — dont les tentatives de connexion SSH — les corrèle avec des règles de détection, et déclenche des alertes (voire des actions automatiques via son module *Active Response*) lorsqu'un comportement suspect est identifié, typiquement du brute-force sur un service exposé.

En observant comment Wazuh traitait ce genre d'alertes, j'ai voulu comprendre et reproduire, à plus petite échelle, la mécanique de base : parser des logs d'authentification, agréger les tentatives par IP, détecter les seuils suspects et proposer une remédiation. LogSentinel est une version simplifiée et pédagogique de cette logique, pensée pour être lisible, auditable et facile à étendre.

## Description

LogSentinel parse les fichiers `auth.log` (format syslog standard sur Debian/Ubuntu) pour identifier les IPs qui multiplient les tentatives de connexion échouées — un signe classique d'attaque par brute-force sur SSH.

Par défaut, l'outil se contente d'analyser et de recommander sans toucher au système. Le flag optionnel `--block` permet, si vous le souhaitez explicitement, de bloquer une ou plusieurs IPs via `iptables` — cette action reste manuelle et nécessite les privilèges root.

## Fonctionnalités

- Parsing des logs SSH (échecs, utilisateurs invalides, connexions réussies)
- Agrégation et classement des IPs par nombre de tentatives échouées
- Détection des IPs suspectes selon un seuil configurable
- Recommandations textuelles (blocage, fail2ban, désactivation de l'auth par mot de passe...)
- Export du rapport en **JSON** (exploitable par un autre outil) et **Markdown** (lisible, versionnable)
- Blocage optionnel d'IPs via `iptables` avec le flag `--block`
- Aide intégrée via `-h` / `--help`

## Installation

```bash
git clone https://github.com/Inarie351/LogSentinel.git
cd log-sentinel
pipx install -e .
```

`pipx` crée un environnement isolé et rend la commande `logsentinel` disponible globalement, sans toucher au Python système. C'est la méthode recommandée, notamment sur les distributions récentes (Debian/Ubuntu) où `pip install` refuse d'installer hors virtualenv (erreur *externally-managed-environment*).

Alternative avec un virtualenv classique :

```bash
python3 -m venv .venv
source .venv/bin/activate
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

# Bloquer une ou plusieurs IPs via iptables (nécessite root)
sudo logsentinel /var/log/auth.log --block 185.220.101.45 45.155.204.19

# Afficher l'aide
logsentinel --help
```

### Blocage d'IPs (`--block`)

Le flag `--block` accepte une ou plusieurs IPs et exécute, pour chacune, la commande équivalente à :

```bash
iptables -A INPUT -s <ip> -j DROP
```

- Nécessite les privilèges root et la présence d'`iptables` sur le système.
- Chaque IP est validée avant tout appel système ; une IP invalide est signalée sans exécuter de commande.
- Le résultat (succès ou erreur) est affiché pour chaque IP traitée.

## Structure du projet

```
log-sentinel/
├── logsentinel/
│   ├── __init__.py
│   ├── cli.py           # Point d'entrée CLI
│   ├── parser.py        # Extraction des événements depuis les logs
│   ├── analyzer.py      # Agrégation, détection, recommandations
│   └── blocker.py       # Blocage d'IPs via iptables
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

## Stack technique

- Python 3 (stdlib uniquement : `re`, `collections`, `argparse`, `json`, `dataclasses`)
- Aucune dépendance externe → portable et facile à auditer

## Limites connues

- Le format de log supporté est le format syslog classique de `sshd` (Debian/Ubuntu). D'autres formats (journald brut, RHEL) nécessiteraient d'adapter les regex du `parser.py`.
- La géolocalisation des IPs n'est pas incluse (piste d'amélioration future avec `geoip2`).
- Le blocage (`--block`) repose sur `iptables` : il ne fonctionne que sur les systèmes où cet outil est disponible, et les règles ajoutées ne sont pas persistées après redémarrage sans outil complémentaire (`iptables-persistent`, `netfilter-persistent`...).

## Licence

MIT
