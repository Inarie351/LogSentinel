"""IncidentBot — rédige un résumé d'incident en langage naturel à partir du
report.json généré par LogSentinel, via l'API Anthropic (Claude)."""

import argparse
import json
import os
import sys
from typing import List, Literal

from pydantic import BaseModel

DEFAULT_MODEL = "claude-opus-5"

SEVERITY_ORDER = ["FAIBLE", "MODÉRÉE", "ÉLEVÉE", "CRITIQUE"]


class IncidentReport(BaseModel):
    severity: Literal["FAIBLE", "MODÉRÉE", "ÉLEVÉE", "CRITIQUE"]
    summary: str
    priority_actions: List[str]


SYSTEM_PROMPT = """Tu es un analyste SOC (Security Operations Center) senior. On te \
fournit les données brutes d'une analyse de logs SSH (générée par un outil de \
détection de brute-force) et tu dois rédiger un rapport d'incident clair et \
actionnable, comme tu le ferais pour ton équipe.

Consignes :
- Base-toi uniquement sur les données fournies, ne fabrique aucune information.
- Le résumé doit expliquer ce qui s'est passé, l'ampleur, et le niveau de risque, \
en 3 à 5 phrases, en français.
- Le niveau de gravité doit refléter le volume d'échecs, la diversité des IPs/ \
utilisateurs ciblés, et la présence ou non de connexions réussies depuis une IP \
suspecte.
- Les actions prioritaires doivent être concrètes, ordonnées par urgence, et \
exploitables immédiatement par un administrateur système."""


def build_prompt(report: dict) -> str:
    summary = report.get("summary", {})
    ip_details = report.get("ip_details", {})

    suspicious_details = []
    for ip in summary.get("suspicious_ips", []):
        data = ip_details.get(ip, {})
        suspicious_details.append(
            {
                "ip": ip,
                "failed": data.get("failed", 0),
                "invalid_user": data.get("invalid_user", 0),
                "success": data.get("success", 0),
                "users_tried": data.get("users_tried", []),
            }
        )

    payload = {
        "periode": {
            "premier_evenement": summary.get("first_event"),
            "dernier_evenement": summary.get("last_event"),
        },
        "totaux": {
            "evenements_analyses": summary.get("total_events"),
            "tentatives_echouees": summary.get("total_failed_attempts"),
            "connexions_reussies": summary.get("total_successful_logins"),
            "ips_uniques": summary.get("unique_ips"),
        },
        "seuil_suspicion": summary.get("threshold_used"),
        "top_attaquant": summary.get("top_attacker"),
        "ips_suspectes": suspicious_details,
    }

    return (
        "Voici les données extraites d'un rapport LogSentinel :\n\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=False)}\n\n"
        "Rédige le rapport d'incident correspondant."
    )


def generate_incident_report(report: dict, model: str = DEFAULT_MODEL) -> IncidentReport:
    import anthropic

    client = anthropic.Anthropic()

    try:
        response = client.messages.parse(
            model=model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_prompt(report)}],
            output_format=IncidentReport,
        )
    except (anthropic.AuthenticationError, TypeError) as exc:
        if isinstance(exc, TypeError) and "authentication" not in str(exc).lower():
            raise
        print(
            "Erreur: clé API Anthropic invalide ou absente. "
            "Définissez la variable d'environnement ANTHROPIC_API_KEY.",
            file=sys.stderr,
        )
        sys.exit(1)
    except anthropic.APIError as exc:
        print(f"Erreur lors de l'appel à l'API Anthropic : {exc}", file=sys.stderr)
        sys.exit(1)

    return response.parsed_output


def render_markdown(incident: IncidentReport) -> str:
    lines = [
        "# Rapport d'incident — Généré par IA",
        "",
        f"**Gravité globale : {incident.severity}**",
        "",
        "## Résumé",
        "",
        incident.summary,
        "",
        "## Actions prioritaires",
        "",
    ]
    for i, action in enumerate(incident.priority_actions, start=1):
        lines.append(f"{i}. {action}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="IncidentBot — résumé d'incident généré par IA à partir d'un report.json LogSentinel"
    )
    parser.add_argument(
        "report_json",
        nargs="?",
        default="report.json",
        help="Chemin vers le report.json généré par LogSentinel (défaut: report.json)",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Modèle Claude à utiliser (défaut: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--output",
        help="Fichier dans lequel écrire le rapport Markdown (par défaut, affiché sur stdout)",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.report_json):
        print(
            f"Erreur: fichier introuvable : {args.report_json}\n"
            "Générez-le d'abord avec : logsentinel <auth.log> --json",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        import anthropic  # noqa: F401
    except ImportError:
        print(
            "Erreur: le paquet 'anthropic' n'est pas installé. "
            "Installez-le avec : pip install 'logsentinel[ai]'",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(args.report_json, "r", encoding="utf-8") as f:
        report = json.load(f)

    incident = generate_incident_report(report, model=args.model)
    markdown = render_markdown(incident)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"Rapport d'incident généré : {args.output}")
    else:
        print(markdown)


if __name__ == "__main__":
    main()
