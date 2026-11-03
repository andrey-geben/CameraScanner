# dahua_scanner.py
"""Dahua/Amcrest discovery: UDP broadcast на 37810, JSON-запрос/ответ."""
import json
import socket
import threading
import time

from net_utils import get_broadcast_addresses

DAHUA_PORT = 37810
DAHUA_PROBE = {
    "method": "DHDiscover.search",
    "params": {"mac": "", "unicast": False},
    "id": 1,
}


def discover_dahua(timeout: float = 5.0,
                   stop_event: threading.Event | None = None) -> list[dict]:
    if stop_event and stop_event.is_set():
        return []

    devices: list[dict] = []
    seen: set[str] = set()
    payload = json.dumps(DAHUA_PROBE).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.5)
    sock.bind(("", 0))

    try:
        for addr in get_broadcast_addresses():
            if stop_event and stop_event.is_set():
                return devices
            try:
                sock.sendto(payload, (addr, DAHUA_PORT))
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
                resp = json.loads(data.decode("utf-8", errors="ignore"))
            except json.JSONDecodeError:
                continue
            if resp.get("method") != "DHDiscover.search":
                continue
            p = resp.get("params", {}) or {}
            devices.append({
                "ip":        p.get("IPv4Address") or src_ip,
                "mac":       p.get("MAC", ""),
                "serial":    p.get("SerialNo", ""),
                "model":     p.get("DeviceType", ""),
                "firmware":  p.get("Version", ""),
                "activated": p.get("Activated", ""),
            })
            seen.add(src_ip)
    finally:
        sock.close()

    return devices