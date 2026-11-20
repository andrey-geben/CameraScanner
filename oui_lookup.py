"""Локальный поиск вендора по MAC (IEEE OUI, без сетевых запросов)."""
from __future__ import annotations

import csv
import gzip
import json
import os
import sys
import urllib.request

_cache: dict[str, str] | None = None
_online_cache: dict[str, str] = {}


def _data_path() -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "assets", "oui.csv.gz")


def _load() -> dict[str, str]:
    global _cache
    if _cache is not None:
        return _cache
    result: dict[str, str] = {}
    path = _data_path()
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="ignore", newline="") as fh:
            reader = csv.reader(fh)
            next(reader, None)  # header
            for row in reader:
                if len(row) >= 3:
                    prefix = (row[1] or "").strip().upper()
                    org = (row[2] or "").strip()
                    if len(prefix) == 6 and org:
                        result[prefix] = org
    except OSError:
        pass
    _cache = result
    return result


def normalize_mac(mac: str) -> str:
    return "".join(ch for ch in (mac or "").upper() if ch in "0123456789ABCDEF")


def _online_lookup(mac: str, timeout: float = 3.0) -> str:
    prefix = normalize_mac(mac)[:6]
    if len(prefix) != 6:
        return ""
    if prefix in _online_cache:
        return _online_cache[prefix]
    url = f"https://api.maclookup.app/v2/macs/{prefix}"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "CameraScanner/1.8", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(8192).decode("utf-8", "ignore"))
        company = (data.get("company") or "").strip() if data.get("found") else ""
    except Exception:
        company = ""
    _online_cache[prefix] = company
    return company


def lookup_vendor(mac: str, online: bool = False) -> str:
    """Вендор по MAC: сначала онлайн (если включено), затем локальный IEEE."""
    prefix = normalize_mac(mac)[:6]
    if len(prefix) != 6:
        return ""
    if online:
        company = _online_lookup(mac)
        if company:
            return company
    return _load().get(prefix, "")
