from collections import defaultdict
from typing import Dict, List

from .parser import SSHEvent


def aggregate_by_ip(events: List[SSHEvent]) -> Dict[str, Dict]:
    stats: Dict[str, Dict] = defaultdict(
        lambda: {"failed": 0, "invalid_user": 0, "success": 0, "users_tried": set()}
    )

    for event in events:
        stats[event.ip][event.event_type] += 1
        stats[event.ip]["users_tried"].add(event.user)

    return stats


def detect_suspicious_ips(stats: Dict[str, Dict], threshold: int = 10) -> List[str]:
    suspicious = []
    for ip, data in stats.items():
        total_failed = data["failed"] + data["invalid_user"]
        if total_failed >= threshold:
            suspicious.append(ip)

    suspicious.sort(
        key=lambda ip: stats[ip]["failed"] + stats[ip]["invalid_user"], reverse=True
    )
    return suspicious


def build_summary(events: List[SSHEvent], stats: Dict[str, Dict], threshold: int) -> Dict:
    total_failed = sum(d["failed"] + d["invalid_user"] for d in stats.values())
    total_success = sum(d["success"] for d in stats.values())
    suspicious_ips = detect_suspicious_ips(stats, threshold)

    top_attacker = suspicious_ips[0] if suspicious_ips else None

    timestamps = [e.timestamp for e in events]

    return {
        "total_events": len(events),
        "total_failed_attempts": total_failed,
        "total_successful_logins": total_success,
        "unique_ips": len(stats),
        "suspicious_ips": suspicious_ips,
        "top_attacker": top_attacker,
        "top_attacker_attempts": (
            stats[top_attacker]["failed"] + stats[top_attacker]["invalid_user"]
            if top_attacker
            else 0
        ),
        "first_event": timestamps[0] if timestamps else None,
        "last_event": timestamps[-1] if timestamps else None,
        "threshold_used": threshold,
    }
