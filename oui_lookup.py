"""Локальный поиск вендора по MAC (IEEE OUI, без сетевых запросов)."""
from __future__ import annotations

import csv
import gzip
import os
import sys

_cache: dict[str, str] | None = None


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


def lookup_vendor(mac: str) -> str:
    """Возвращает организацию IEEE для первых 24 бит MAC или пустую строку."""
    prefix = normalize_mac(mac)[:6]
    if len(prefix) != 6:
        return ""
    return _load().get(prefix, "")
