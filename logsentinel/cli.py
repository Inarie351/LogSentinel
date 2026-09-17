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
