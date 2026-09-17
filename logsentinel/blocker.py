import subprocess
from ipaddress import ip_address
from typing import Tuple


def block_ip(ip: str) -> Tuple[bool, str]:
    try:
        ip_address(ip)
    except ValueError:
        return False, f"{ip} n'est pas une adresse IP valide"

    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
            text=True,
        )
        return True, f"{ip} bloquée avec succès (iptables DROP)"
    except FileNotFoundError:
        return False, "iptables introuvable sur ce système"
    except subprocess.CalledProcessError as exc:
        return False, f"Échec du blocage de {ip} : {exc.stderr.strip()}"
