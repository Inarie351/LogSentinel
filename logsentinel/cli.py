import json
import os
from datetime import datetime

from .analyzer import aggregate_by_ip, build_recommendations, build_summary
from .parser import parse_log_file

WIDTH = 40


def print_header(title: str):
    print("\n" + title)
    print("─" * WIDTH)


def print_console_report(summary: dict, stats: dict, recommendations: list):
    print("\nLOGSENTINEL")
    print("─" * WIDTH)

    print_header("SSH LOGIN ANALYSIS")
    if not stats:
        print("Aucun événement SSH trouvé dans ce fichier.")
        return

    sorted_ips = sorted(
        stats.items(),
        key=lambda kv: kv[1]["failed"] + kv[1]["invalid_user"],
        reverse=True,
    )

    for ip, data in sorted_ips:
        total_failed = data["failed"] + data["invalid_user"]
        if total_failed == 0:
            continue
        label = f"{total_failed} failed attempt" + ("s" if total_failed != 1 else "")
        flag = "SUSPICIOUS" if ip in summary["suspicious_ips"] else ""
        print(f"{ip:<20}{label}{flag}")

    if summary["top_attacker"]:
        print_header("Top attacking IP")
        print(summary["top_attacker"])

    print_header("Recommendation")
    for rec in recommendations:
        print(f"-> {rec}")

    print_header("SUMMARY")
    print(f"Total events analyzed : {summary['total_events']}")
    print(f"Failed attempts       : {summary['total_failed_attempts']}")
    print(f"Successful logins     : {summary['total_successful_logins']}")
    print(f"Unique IPs            : {summary['unique_ips']}")
    print(f"Suspicious IPs        : {len(summary['suspicious_ips'])}")


def export_json(summary: dict, stats: dict, recommendations: list, output_dir: str):
    serializable_stats = {
        ip: {
            "failed": d["failed"],
            "invalid_user": d["invalid_user"],
            "success": d["success"],
            "users_tried": sorted(d["users_tried"]),
        }
        for ip, d in stats.items()
    }
    report = {
        "generated_at": datetime.now().isoformat(),
        "summary": summary,
        "ip_details": serializable_stats,
        "recommendations": recommendations,
    }
    path = os.path.join(output_dir, "report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return path


def export_markdown(summary: dict, stats: dict, recommendations: list, output_dir: str):
    lines = [
        "# LogSentinel — Rapport d'analyse SSH",
        "",
        f"*Généré le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
        "",
        "## Résumé",
        "",
        f"- Événements analysés : **{summary['total_events']}**",
        f"- Tentatives échouées : **{summary['total_failed_attempts']}**",
        f"- Connexions réussies : **{summary['total_successful_logins']}**",
        f"- IPs uniques : **{summary['unique_ips']}**",
        f"- IPs suspectes (seuil={summary['threshold_used']}) : **{len(summary['suspicious_ips'])}**",
        "",
        "## Détail par IP",
        "",
        "| IP | Échecs | Utilisateurs tentés | Statut |",
        "|---|---|---|---|",
    ]

    sorted_ips = sorted(
        stats.items(),
        key=lambda kv: kv[1]["failed"] + kv[1]["invalid_user"],
        reverse=True,
    )
    for ip, data in sorted_ips:
        total_failed = data["failed"] + data["invalid_user"]
        if total_failed == 0:
            continue
        users = ", ".join(sorted(data["users_tried"])[:5])
        status = "SUSPECT" if ip in summary["suspicious_ips"] else "OK"
        lines.append(f"| {ip} | {total_failed} | {users} | {status} |")

    lines += ["", "## Recommandations", ""]
    for rec in recommendations:
        lines.append(f"- {rec}")

    path = os.path.join(output_dir, "report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path
