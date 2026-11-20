"""Слияние результатов разных протоколов в одно устройство по IP."""
from __future__ import annotations

import ipaddress


def _ip_key(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def merge_devices(rows: list[dict]) -> list[dict]:
    """Один IP -> одна запись; протоколы и доказательства объединяются."""
    devices: dict[str, dict] = {}
    orphans: list[dict] = []

    for row in rows:
        ip = (row.get("ip") or "").strip()
        if not ip:
            orphans.append(dict(row))
            continue
        d = devices.setdefault(ip, {
            "ip": ip, "mac": "", "vendor": "", "model": "", "firmware": "",
            "serial": "", "protocols": [], "info": [], "rtsp_urls": [],
            "web_url": "", "type": "",
        })
        for key in ("mac", "vendor", "model", "firmware", "serial", "web_url", "type"):
            val = (row.get(key) or "").strip()
            if val and not d[key]:
                d[key] = val
        proto = (row.get("protocol") or "").strip()
        if proto and proto not in d["protocols"]:
            d["protocols"].append(proto)
        info = (row.get("info") or "").strip()
        if info and info not in d["info"]:
            d["info"].append(info)
        for url in row.get("rtsp_urls") or []:
            if url and url not in d["rtsp_urls"]:
                d["rtsp_urls"].append(url)

    out: list[dict] = []
    for d in devices.values():
        label = " / ".join(x for x in (d["vendor"], d["model"]) if x)
        d["device"] = label or "—"
        d["protocol"] = ", ".join(d["protocols"])
        d["info"] = " | ".join(d["info"])
        out.append(d)
    out.sort(key=lambda d: _ip_key(d["ip"]))
    out.extend(orphans)
    return out
