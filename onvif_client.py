"""Минимальный ONVIF-клиент: DeviceInformation, Capabilities, Profiles, StreamUri."""
from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse
import os
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from xml.sax.saxutils import escape

_NS_TDS = "http://www.onvif.org/ver10/device/wsdl"
_NS_TRT = "http://www.onvif.org/ver10/media/wsdl"


def redact_rtsp_url(url: str) -> str:
    """Не показываем пароль из URL, который некоторые камеры кладут в GetStreamUri."""
    url = re.sub(r"(?i)(password=)[^&;]+", r"\1***", url)
    url = re.sub(r"(?i)(://[^/@:]+:)[^/@]+@", r"\1***@", url)
    return url


def extract_rtsp_credentials(urls: list[str]) -> dict:
    """Достаёт логин/пароль, которые некоторые камеры кладут в RTSP-URL.

    Это не подбор: камера сама возвращает их в GetStreamUri. Использовать
    только для собственного устройства; на экран по умолчанию не выводим.
    """
    for url in urls or []:
        user = password = None
        m = re.match(r"rtsp://([^/@:]+):([^/@]+)@", url)
        if m:
            user = urllib.parse.unquote(m.group(1))
            password = urllib.parse.unquote(m.group(2))
        if not user:
            m = re.search(r"(?:[?&/]|^)user=([^&_/]+)", url)
            if m:
                user = urllib.parse.unquote(m.group(1))
        if not password:
            m = re.search(r"(?:[?&/]|_)password=([^&]+)", url)
            if m:
                password = m.group(1)
                for stop in ("_channel=", "_stream=", "&"):
                    password = password.split(stop)[0]
                password = urllib.parse.unquote(password)
        if user and password:
            return {"user": user, "password": password, "source": "ONVIF GetStreamUri"}
    return {}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _security(user: str, password: str) -> str:
    nonce = os.urandom(16)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = base64.b64encode(
        hashlib.sha1(nonce + created.encode() + password.encode()).digest()
    ).decode()
    return (
        '<s:Header><wsse:Security s:mustUnderstand="1" '
        'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
        'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
        f"<wsse:UsernameToken><wsse:Username>{escape(user)}</wsse:Username>"
        '<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'
        f"{digest}</wsse:Password>"
        '<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
        f"{base64.b64encode(nonce).decode()}</wsse:Nonce>"
        f"<wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>"
    )


def _envelope(body: str, user: str | None = None, password: str | None = None) -> bytes:
    header = _security(user, password) if user else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        f'xmlns:tds="{_NS_TDS}" xmlns:trt="{_NS_TRT}" '
        'xmlns:tt="http://www.onvif.org/ver10/schema">'
        f"{header}<s:Body>{body}</s:Body></s:Envelope>"
    ).encode("utf-8")


def _post(xaddr: str, body: str, user: str | None, password: str | None,
          timeout: float) -> ET.Element | None:
    if not xaddr.startswith(("http://", "https://")):
        xaddr = "http://" + xaddr
    req = urllib.request.Request(
        xaddr,
        data=_envelope(body, user, password),
        headers={"Content-Type": "application/soap+xml; charset=utf-8",
                 "User-Agent": "CameraScanner/1.3"},
        method="POST",
    )
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read(256 * 1024)
        return ET.fromstring(data)
    except (urllib.error.URLError, urllib.error.HTTPError, ET.ParseError, OSError):
        return None


def get_device_information(xaddr: str, user: str | None = None,
                           password: str | None = None,
                           timeout: float = 2.5) -> dict:
    root = _post(xaddr, "<tds:GetDeviceInformation/>", user, password, timeout)
    if root is None:
        return {}
    out: dict[str, str] = {}
    keys = {
        "manufacturer": "manufacturer", "model": "model",
        "firmwareversion": "firmware", "serialnumber": "serial",
        "hardwareid": "hardware",
    }
    for el in root.iter():
        key = keys.get(_local(el.tag).lower())
        if key and el.text and key not in out:
            out[key] = el.text.strip()
    return out


def get_media_xaddr(xaddr: str, user: str | None = None,
                    password: str | None = None,
                    timeout: float = 2.5) -> str | None:
    root = _post(
        xaddr,
        "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>",
        user, password, timeout,
    )
    if root is None:
        return None
    for media in root.iter():
        if _local(media.tag) == "Media":
            for el in media.iter():
                if _local(el.tag) == "XAddr" and el.text:
                    return el.text.strip()
    return None


def get_profiles(media_xaddr: str, user: str | None = None,
                 password: str | None = None, timeout: float = 2.5) -> list[str]:
    root = _post(media_xaddr, "<trt:GetProfiles/>", user, password, timeout)
    if root is None:
        return []
    tokens = []
    for el in root.iter():
        if _local(el.tag) == "Profiles":
            token = el.attrib.get("token")
            if token:
                tokens.append(token)
    return tokens


def get_stream_uri(media_xaddr: str, profile_token: str,
                   user: str | None = None, password: str | None = None,
                   timeout: float = 2.5) -> str | None:
    body = (
        "<trt:GetStreamUri><trt:StreamSetup>"
        "<tt:Stream>RTP-Unicast</tt:Stream>"
        "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport>"
        "</trt:StreamSetup>"
        f"<trt:ProfileToken>{escape(profile_token)}</trt:ProfileToken>"
        "</trt:GetStreamUri>"
    )
    root = _post(media_xaddr, body, user, password, timeout)
    if root is None:
        return None
    for el in root.iter():
        if _local(el.tag) == "Uri" and el.text:
            return el.text.strip()
    return None


def enrich(xaddr: str, user: str | None = None, password: str | None = None,
           timeout: float = 2.5) -> dict:
    """Best-effort: без авторизации многие камеры ответят только на часть запросов."""
    if not xaddr:
        return {}
    info = get_device_information(xaddr, user, password, timeout)
    media = get_media_xaddr(xaddr, user, password, timeout)
    tokens = get_profiles(media, user, password, timeout) if media else []
    raw_uris = []
    for token in tokens[:2]:
        uri = get_stream_uri(media, token, user, password, timeout)
        if uri:
            raw_uris.append(uri)
    creds = extract_rtsp_credentials(raw_uris)
    if not creds and user and password and raw_uris:
        creds = {"user": user, "password": password,
                 "source": "ONVIF-авторизация (введена вручную)"}
    return {
        **info,
        "rtsp_urls": [redact_rtsp_url(u) for u in raw_uris],
        "rtsp_credentials": creds,
        "onvif_media": media or "",
        "onvif_profiles": tokens,
    }
