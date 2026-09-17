from dataclasses import dataclass
from typing import Optional


@dataclass
class SSHEvent:
    timestamp: str
    event_type: str
    user: str
    ip: str
    port: Optional[str] = None
