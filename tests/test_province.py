import re
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.models import ProvinceRule
from wifi_auto_login.province import resolve_province_fields


class ProvinceTests(unittest.TestCase):
    def test_resolve_province_fields_by_realm(self):
        rules = [
            ProvinceRule(
                name="ex",
                realm="wlan.example.net",
                username_patterns=[re.compile(r"^138\d{8}$")],
            )
        ]
        self.assertEqual(
            resolve_province_fields("foo@wlan.example.net", rules),
            {
                "shortname": "ex",
                "province": "wlan.example.net",
                "prov": "ex",
            },
        )

    def test_resolve_province_fields_by_username_pattern(self):
        rules = [
            ProvinceRule(
                name="ex",
                realm="wlan.example.net",
                username_patterns=[re.compile(r"^138\d{8}$")],
            )
        ]
        self.assertEqual(
            resolve_province_fields("13800138000", rules),
            {
                "shortname": "ex",
                "province": "wlan.example.net",
                "prov": "ex",
            },
        )


if __name__ == "__main__":
    unittest.main()
