"""SSDP/UPnP discovery: M-SEARCH на 239.255.255.250:1900."""
from __future__ import annotations

import re
import socket
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def _parse_headers(data: bytes) -> dict[str, str]:
    text = data.decode("utf-8", errors="ignore")
    headers: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _fetch_description(location: str, source_ip: str, timeout: float) -> dict:
    """Читает UPnP-описание, только если оно на том же хосте (без SSRF)."""
    try:
        parsed = urllib.parse.urlparse(location)
        if parsed.scheme not in ("http", "https") or parsed.hostname != source_ip:
            return {}
        with urllib.request.urlopen(location, timeout=timeout) as resp:
            body = resp.read(128 * 1024)
        root = ET.fromstring(body)
        found: dict[str, str] = {}
        for el in root.iter():
            key = _local(el.tag)
            if key in ("friendlyname", "manufacturer", "modelname", "modelnumber",
                       "devicetype") and el.text and key not in found:
                found[key] = el.text.strip()
        return found
    except Exception:
        return {}


def discover_ssdp(timeout: float = 3.0,
                  stop_event: threading.Event | None = None) -> list[dict]:
    if stop_event and stop_event.is_set():
        return []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(0.5)
    sock.bind(("", 0))
    devices: dict[str, dict] = {}
    try:
        sock.sendto(_MSEARCH.encode(), (SSDP_ADDR, SSDP_PORT))
        start = time.time()
        while time.time() - start < timeout:
            if stop_event and stop_event.is_set():
                break
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            ip = addr[0]
            if ip in devices:
                continue
            h = _parse_headers(data)
            location = h.get("location", "")
            desc = _fetch_description(location, ip, timeout=min(2.0, timeout)) if location else {}
            friendly = desc.get("friendlyname", "")
            vendor = desc.get("manufacturer", "")
            model = desc.get("modelname", "") or desc.get("modelnumber", "")
            server = h.get("server", "")
            st = h.get("st", "")
            info_bits = [x for x in (friendly, vendor, model, server, st) if x]
            devices[ip] = {
                "ip": ip, "protocol": "SSDP", "info": " | ".join(info_bits),
                "vendor": vendor, "model": model, "web_url": location,
                "serial": "", "firmware": "",
            }
    finally:
        sock.close()
    return list(devices.values())
