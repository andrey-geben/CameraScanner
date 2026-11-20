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

    def test_ico_exists(self):
        ok, info = main.validate_ico(main.resource_path("assets/app.ico"))
        self.assertTrue(ok, info)


if __name__ == "__main__":
    unittest.main()
