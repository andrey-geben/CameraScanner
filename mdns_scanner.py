"""mDNS/Bonjour discovery через zeroconf: ONVIF, RTSP, Axis."""
from __future__ import annotations

import threading
import time

from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf

SERVICE_TYPES = (
    "_onvif._tcp.local.",
    "_rtsp._tcp.local.",
    "_axis-video._tcp.local.",
)


class _Listener(ServiceListener):
    def __init__(self):
        self.items: dict[str, dict] = {}
        self._lock = threading.Lock()

    def _save(self, zc: Zeroconf, type_: str, name: str) -> None:
        info: ServiceInfo | None = zc.get_service_info(type_, name, timeout=1500)
        if not info:
            return
        addrs = [a for a in info.parsed_addresses() if ":" not in a]
        if not addrs:
            return
        props = {}
        for k, v in (info.properties or {}).items():
            key = k.decode("utf-8", "ignore") if isinstance(k, bytes) else str(k)
            val = v.decode("utf-8", "ignore") if isinstance(v, bytes) else ("" if v is None else str(v))
            props[key.lower()] = val
        ip = addrs[0]
        model = props.get("model", "") or props.get("product", "")
        vendor = props.get("manufacturer", "") or props.get("vendor", "")
        with self._lock:
            prev = self.items.get(ip, {})
            self.items[ip] = {
                "ip": ip, "protocol": "mDNS", "mac": "", "vendor": vendor,
                "model": model, "firmware": "", "serial": "",
                "info": f"{name} | {type_} | port {info.port}" + (f" | {model}" if model else ""),
                "web_url": prev.get("web_url", ""),
            }

    def add_service(self, zc, type_, name):
        self._save(zc, type_, name)

    def update_service(self, zc, type_, name):
        self._save(zc, type_, name)

    def remove_service(self, zc, type_, name):
        pass


def discover_mdns(timeout: float = 4.0,
                  stop_event: threading.Event | None = None) -> list[dict]:
    if stop_event and stop_event.is_set():
        return []
    zc = Zeroconf()
    listener = _Listener()
    browsers = []
    try:
        for st in SERVICE_TYPES:
            browsers.append(ServiceBrowser(zc, st, listener))
        start = time.time()
        while time.time() - start < timeout:
            if stop_event and stop_event.is_set():
                break
            time.sleep(0.2)
    finally:
        for b in browsers:
            try:
                b.cancel()
            except Exception:
                pass
        zc.close()
    return list(listener.items.values())
