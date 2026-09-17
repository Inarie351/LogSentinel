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
