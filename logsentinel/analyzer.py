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
