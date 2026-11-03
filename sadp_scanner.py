# SADP (Hikvision)
# sadp_scanner.py
import ctypes
import socket
import threading
import time
import uuid
import xml.etree.ElementTree as ET

from net_utils import get_broadcast_addresses

SADP_MULTICAST_ADDRS = ("239.255.255.250", "239.255.255.230")
SADP_PORT = 37020

SADP_PROBE_TEMPLATE = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<Probe>\n<Uuid>{uuid}</Uuid>\n<Types>inquiry</Types>\n</Probe>"
)


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except Exception:
        return True


def discover_hikvision_sadp(timeout: float = 5.0,
                            broadcast: bool = True,
                            require_admin: bool = True,
                            stop_event: threading.Event | None = None) -> list[dict]:
    if require_admin and not _is_admin():
        raise PermissionError("SADP discovery requires administrator privileges")

    if stop_event and stop_event.is_set():
        return []

    devices: list[dict] = []
    seen: set[str] = set()
    payload = SADP_PROBE_TEMPLATE.format(uuid=str(uuid.uuid4()).upper()).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)
    sock.bind(("", 0))

    try:
        for group in SADP_MULTICAST_ADDRS:
            if stop_event and stop_event.is_set():
                return devices
            try:
                sock.sendto(payload, (group, SADP_PORT))
            except OSError:
                pass
        if broadcast:
            for addr in get_broadcast_addresses():
                if stop_event and stop_event.is_set():
                    return devices
                try:
                    sock.sendto(payload, (addr, SADP_PORT))
                except OSError:
                    pass

        start = time.time()
        while time.time() - start < timeout:
            if stop_event and stop_event.is_set():
                break
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            src_ip = addr[0]
            if src_ip in seen:
                continue
            try:
                root = ET.fromstring(data.decode("utf-8", errors="ignore"))
            except ET.ParseError:
                continue
            info = {(c.tag or "").strip(): (c.text or "").strip() for c in root}
            devices.append({
                "ip":        info.get("IPv4Address") or src_ip,
                "mac":       info.get("MAC", ""),
                "serial":    info.get("DeviceSN", ""),
                "model":     info.get("DeviceDescription", ""),
                "firmware":  info.get("SoftwareVersion", ""),
                "activated": info.get("Activated", ""),
            })
            seen.add(src_ip)
    finally:
        sock.close()

    return devices