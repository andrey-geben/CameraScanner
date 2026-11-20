"""Smoke-тесты CameraScanner (без сети и GUI)."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import exporter  # noqa: E402
import isapi_scanner  # noqa: E402
import main  # noqa: E402


class CameraScannerTests(unittest.TestCase):
    def test_csv_bom_and_sorted_columns(self):
        path = os.path.join(tempfile.mkdtemp(), "out.csv")
        exporter.export_to_csv([
            {"ip": "10.0.0.1", "protocol": "SNMP"},
            {"mac": "aa:bb", "ip": "10.0.0.2"},
        ], path)
        with open(path, "rb") as fh:
            raw = fh.read()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        header = raw.decode("utf-8-sig").splitlines()[0]
        self.assertEqual(header, "ip,mac,protocol")

    def test_realm_serial(self):
        headers = {"www-authenticate": 'Digest realm="DS-2CD(ABC123)", qop="auth"'}
        info = isapi_scanner._parse_serial_from_realm(headers)
        self.assertEqual(info["serial_from_realm"], "ABC123")

    def test_restore_dict(self):
        args = main.build_restore_dict(argparse.Namespace(
            subnet="192.168.1.0/24", community="public", snmp_version="v2c",
            auto="1", snmp="0", onvif="1", dahua="1", arp="0",
            portscan="1", isapi="0",
        ))
        self.assertEqual(args["subnet"], "192.168.1.0/24")
        self.assertTrue(args["auto"])
        self.assertFalse(args["snmp"])


    def test_merge_devices(self):
        from device_merge import merge_devices
        merged = merge_devices([
            {"ip": "10.0.0.5", "mac": "aa:bb", "protocol": "SADP",
             "model": "DS-2CD", "vendor": "Hikvision"},
            {"ip": "10.0.0.5", "protocol": "ONVIF", "serial": "SN1"},
            {"ip": "10.0.0.5", "protocol": "Port scan", "info": "Open: 80/http"},
        ])
        self.assertEqual(len(merged), 1)
        dev = merged[0]
        self.assertEqual(dev["mac"], "aa:bb")
        self.assertIn("SADP", dev["protocol"])
        self.assertIn("ONVIF", dev["protocol"])
        self.assertEqual(dev["device"], "Hikvision / DS-2CD")

    def test_ssdp_headers(self):
        from ssdp_scanner import _parse_headers
        h = _parse_headers(b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux/1.0 UPnP/1.1\r\n\r\n")
        self.assertEqual(h["st"], "upnp:rootdevice")
        self.assertIn("server", h)


    def test_rtsp_password_redacted(self):
        from onvif_client import redact_rtsp_url
        url = "rtsp://192.168.1.87:554/user=andrew_password=secret_channel=0_stream=0.sdp"
        safe = redact_rtsp_url(url)
        self.assertNotIn("secret_channel", safe)
        self.assertIn("password=***", safe)
        self.assertNotIn("secret", safe)

    def test_ico_exists(self):
        ok, info = main.validate_ico(main.resource_path("assets/app.ico"))
        self.assertTrue(ok, info)


if __name__ == "__main__":
    unittest.main()
