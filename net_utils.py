# net_utils.py
"""Общие помощники для широковещательного поиска."""
import socket

try:
    import netifaces
    HAVE_NETIFACES = True
except ImportError:
    HAVE_NETIFACES = False


def get_broadcast_addresses(include_global: bool = True) -> list[str]:
    """Broadcast-адреса всех IPv4-интерфейсов (+ глобальный 255.255.255.255)."""
    result: set[str] = set()
    if include_global:
        result.add("255.255.255.255")
    if HAVE_NETIFACES:
        for iface in netifaces.interfaces():
            for info in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                br = info.get("broadcast")
                if br:
                    result.add(br)
    return sorted(result)