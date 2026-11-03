# net_utils.py
"""Общие помощники для широковещательного и активного поиска."""
import ipaddress
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


def get_local_subnets(min_hosts: int = 2, max_hosts: int = 4096) -> list[ipaddress.IPv4Network]:
    """
    Все IPv4-подсети локальных интерфейсов.
    Отбрасывает loopback, /31, /32 и слишком большие (> max_hosts) сети.
    """
    result: list[ipaddress.IPv4Network] = []
    if not HAVE_NETIFACES:
        return result
    for iface in netifaces.interfaces():
        for info in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
            addr = info.get("addr")
            mask = info.get("netmask")
            if not addr or not mask or addr.startswith("127."):
                continue
            try:
                net = ipaddress.ip_network(f"{addr}/{mask}", strict=False)
            except ValueError:
                continue
            if net.num_addresses < min_hosts:
                continue
            if net.num_addresses > max_hosts:
                continue  # защита от /16 и больше — слишком долго
            if net not in result:
                result.append(net)
    return result