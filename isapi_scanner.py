# isapi_scanner.py
"""
Проба ISAPI (Hikvision HTTP API).
Без аутентификации достаём полезное из 401-ответа (realm, server),
а в редких случаях — и полную DeviceInfo.
"""
import http.client
import re
import ssl


def _http_get(host: str, port: int, path: str,
              timeout: float = 2.0, use_ssl: bool = False):
    """Возвращает (status, headers_lower, body_snippet) или (None, {}, '')."""
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "CameraScanner/1.0"})
        resp = conn.getresponse()
        body = resp.read(4096).decode("utf-8", errors="ignore")
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, hdrs, body
    except Exception:
        return None, {}, ""


def _parse_serial_from_realm(headers: dict) -> dict:
    """Hikvision кладёт серийник/модель в realm=... при 401."""
    auth = headers.get("www-authenticate", "")
    m = re.search(r'realm="([^"]+)"', auth)
    if not m:
        return {}
    realm = m.group(1)
    out = {"realm": realm}
    m2 = re.search(r"\(([A-Z0-9\-]+)\)", realm)
    if m2:
        out["serial_from_realm"] = m2.group(1)
    return out


def isapi_probe(ip: str, timeout: float = 2.0) -> dict | None:
    """
    Пытается GET /ISAPI/System/deviceInfo на http:80 и https:443.
    Возвращает dict с полями model/serial/firmware/auth_required или None.
    """
    for use_ssl, port in ((False, 80), (True, 443)):
        status, headers, body = _http_get(
            ip, port, "/ISAPI/System/deviceInfo",
            timeout=timeout, use_ssl=use_ssl,
        )
        if status is None:
            continue
        scheme = "https" if use_ssl else "http"

        # Полный ответ без auth (редко)
        if status == 200 and "<DeviceInfo" in body:
            def _get(tag: str):
                m = re.search(rf"<{tag}>([^<]+)</{tag}>", body)
                return m.group(1) if m else None
            return {
                "ip": ip,
                "scheme": scheme,
                "port": port,
                "auth_required": False,
                "model": _get("model"),
                "serial": _get("serialNumber"),
                "firmware": _get("firmwareVersion"),
            }

        # 401 — но realm уже полезен
        if status == 401:
            realm_info = _parse_serial_from_realm(headers)
            return {
                "ip": ip,
                "scheme": scheme,
                "port": port,
                "auth_required": True,
                "server": headers.get("server", ""),
                **realm_info,
            }

        # 200 без DeviceInfo, 404 — тоже Hikvision-подобное
        if status in (200, 404, 403):
            return {
                "ip": ip,
                "scheme": scheme,
                "port": port,
                "auth_required": status != 200,
                "http_status": status,
            }
    return None