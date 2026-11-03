# port_scanner.py
"""Быстрый TCP-скан портов для активного обнаружения устройств."""
import concurrent.futures
import socket
import threading

# Порты, характерные для камер и NVR
DEFAULT_PORTS: dict[int, str] = {
    80:    "http",
    443:   "https",
    554:   "rtsp",
    8000:  "hikvision-sdk",
    8080:  "http-alt",
    8443:  "https-alt",
    37777: "dahua-sdk",
    34567: "xmeye-sdk",
}


def _check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def port_scan(hosts: list[str],
              ports: list[int] | None = None,
              timeout: float = 0.5,
              max_workers: int = 128,
              stop_event: threading.Event | None = None,
              progress_cb=None) -> list[dict]:
    """
    Возвращает [{ip, ports: {port: name}, vendor_hint}].
    vendor_hint выставляется эвристически по открытым портам.
    """
    if stop_event and stop_event.is_set():
        return []

    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        return []
    if ports is None:
        ports = list(DEFAULT_PORTS.keys())

    tasks = [(ip, p) for ip in hosts for p in ports]
    total = len(tasks)
    done = 0
    lock = threading.Lock()
    found: dict[str, list[int]] = {}

    def _one(args):
        nonlocal done
        ip, port = args
        if stop_event and stop_event.is_set():
            return
        if _check_port(ip, port, timeout):
            with lock:
                found.setdefault(ip, []).append(port)
        with lock:
            done += 1
            if progress_cb:
                progress_cb(done, total)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(_one, tasks))

    out: list[dict] = []
    for ip, open_ports in found.items():
        open_ports.sort()
        vendor = None
        if 8000 in open_ports:
            vendor = "Hikvision (port 8000)"
        elif 37777 in open_ports:
            vendor = "Dahua (port 37777)"
        elif 34567 in open_ports:
            vendor = "XMEye/generic (port 34567)"
        elif 554 in open_ports and (80 in open_ports or 443 in open_ports):
            vendor = "RTSP+HTTP (camera-like)"
        out.append({
            "ip": ip,
            "ports": {p: DEFAULT_PORTS.get(p, "") for p in open_ports},
            "vendor_hint": vendor,
        })
    return out