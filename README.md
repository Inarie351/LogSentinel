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

## Licence

MIT
