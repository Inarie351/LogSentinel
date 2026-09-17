import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class SSHEvent:
    timestamp: str
    event_type: str
    user: str
    ip: str
    port: Optional[str] = None

PATTERNS = [
    (
        re.compile(
            r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*:\s+"
            r"Failed password for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
        ),
        "failed",
    ),
    (
        re.compile(
            r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*:\s+"
            r"Failed password for invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
        ),
        "invalid_user",
    ),
    (
        re.compile(
            r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*:\s+"
            r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)"
        ),
        "success",
    ),
]


def parse_line(line: str) -> Optional[SSHEvent]:
    for pattern, event_type in [PATTERNS[1], PATTERNS[0], PATTERNS[2]]:
        match = pattern.search(line)
        if match:
            data = match.groupdict()
            return SSHEvent(
                timestamp=data["ts"],
                event_type=event_type,
                user=data["user"],
                ip=data["ip"],
                port=data.get("port"),
            )
    return None
