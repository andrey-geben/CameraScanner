# arp_scanner.py
"""
ARP-обнаружение: параллельный ping-sweep + чтение системной ARP-таблицы.
Работает без прав администратора, на Windows/Linux/macOS.
"""
import concurrent.futures
import platform
import re
import subprocess
import threading

_CREATE_NO_WINDOW = 0x08000000 if platform.system().lower() == "windows" else 0


def _ping(ip: str, timeout_ms: int = 500) -> bool:
    """Быстрый ping одного адреса."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_ms / 1000 + 0.5,
            creationflags=_CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _read_arp_table() -> dict[str, str]:
    """Читает системную ARP-таблицу. Возвращает {ip: mac}."""
    result: dict[str, str] = {}
    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            stderr=subprocess.DEVNULL,
            timeout=5,
            text=True,
            errors="ignore",
            creationflags=_CREATE_NO_WINDOW,
        )
    except Exception:
        return result

    patterns = [
        re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F\-]{17})"),         # Windows
        re.compile(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F:]{17})"), # Linux/macOS
    ]
    for line in output.splitlines():
        for pat in patterns:
            m = pat.search(line)
            if m:
                ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
                if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    result[ip] = mac
                break
    return result


def arp_scan(hosts: list[str],
             max_workers: int = 64,
             stop_event: threading.Event | None = None,
             progress_cb=None) -> list[dict]:
    """
    Ping-sweep + чтение ARP-таблицы. Возвращает [{ip, mac}].
    Хосты, ответившие на ping, но отсутствующие в ARP-таблице (бывает на некоторых
    ОС), тоже включаются с пустым MAC.
    """
    if stop_event and stop_event.is_set():
        return []

    hosts = list(dict.fromkeys(hosts))  # без дубликатов, порядок сохранён
    if not hosts:
        return []

    total = len(hosts)
    done = 0
    alive: set[str] = set()
    lock = threading.Lock()

    def _one(ip: str):
        nonlocal done
        if stop_event and stop_event.is_set():
            return
        if _ping(ip):
            with lock:
                alive.add(ip)
        with lock:
            done += 1
            if progress_cb:
                progress_cb(done, total)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(_one, hosts))

    if stop_event and stop_event.is_set():
        return []

    arp = _read_arp_table()
    result = []
    for ip in hosts:
        if ip in arp:
            result.append({"ip": ip, "mac": arp[ip]})
        elif ip in alive:
            # ping прошёл, но в ARP-таблице ещё нет (редко — например, IPv6-only)
            result.append({"ip": ip, "mac": ""})
    return result