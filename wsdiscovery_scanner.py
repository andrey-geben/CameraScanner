#ONVIF WS-Discovery
# wsdiscovery_scanner.py
import re
import socket
import threading
import time
import uuid

from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery
from wsdiscovery import QName

from net_utils import get_broadcast_addresses

WSD_MULTICAST = "239.255.255.250"
WSD_PORT = 3702

_WSD_PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{uuid}</w:MessageID>
    <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>
  </e:Body>
</e:Envelope>"""


def _extract_ip_from_xaddr(xaddr: str) -> str | None:
    m = re.search(r"://([^/:]+)", xaddr or "")
    return m.group(1) if m else None


def _library_multicast(timeout: float, stop_event: threading.Event | None = None) -> list[dict]:
    """
    Multicast-поиск через библиотеку. Один блокирующий вызов searchServices().
    Если stop_event взведён во время работы — снимаем флаг в самом конце,
    после возврата из библиотеки (внутри прервать searchServices нельзя).
    """
    if stop_event and stop_event.is_set():
        return []

    wsd = WSDiscovery(relates_to=True)
    wsd.start()
    try:
        services = wsd.searchServices(
            types=[QName("http://www.onvif.org/ver10/network/wsdl",
                         "NetworkVideoTransmitter")],
            timeout=timeout,
        )
    finally:
        wsd.stop()

    out = []
    for svc in services:
        xaddrs = svc.getXAddrs() or []
        ip = _extract_ip_from_xaddr(xaddrs[0]) if xaddrs else None
        if ip:
            out.append({"ip": ip, "xaddrs": xaddrs,
                        "scopes": [str(s) for s in svc.getScopes()]})
    return out


def _broadcast_probe(timeout: float, stop_event: threading.Event | None = None) -> list[dict]:
    payload = _WSD_PROBE_TEMPLATE.format(uuid=uuid.uuid4()).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(0.5)
    sock.bind(("", 0))
    seen: set[str] = set()
    out = []
    try:
        for addr in get_broadcast_addresses():
            if stop_event and stop_event.is_set():
                return out
            try:
                sock.sendto(payload, (addr, WSD_PORT))
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
            ip = addr[0]
            if ip in seen:
                continue
            m = re.search(rb"<[^>]*XAddrs[^>]*>\s*([^<]+)\s*<", data)
            xaddr = m.group(1).decode(errors="ignore") if m else ""
            out.append({"ip": ip, "xaddrs": [xaddr] if xaddr else [], "scopes": []})
            seen.add(ip)
    finally:
        sock.close()
    return out


def discover_onvif(timeout: float = 5,
                   broadcast_fallback: bool = True,
                   stop_event: threading.Event | None = None) -> list[dict]:
    found: dict[str, dict] = {}

    try:
        for dev in _library_multicast(timeout, stop_event):
            found.setdefault(dev["ip"], dev)
    except Exception as exc:
        print(f"WS-Discovery multicast failed: {exc}")

    if broadcast_fallback and not (stop_event and stop_event.is_set()):
        try:
            for dev in _broadcast_probe(timeout, stop_event):
                found.setdefault(dev["ip"], dev)
        except Exception as exc:
            print(f"WS-Discovery broadcast failed: {exc}")

    return list(found.values())