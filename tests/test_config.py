import sys
import json
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def write_config(self, tmpdir: str, content: str) -> Path:
        path = Path(tmpdir) / "settings.json"
        path.write_text(content, encoding="utf-8")
        return path

    def test_load_config_raises_for_missing_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "missing.json"
            with self.assertRaises(ConfigError) as cm:
                load_config(path)
        self.assertIn("Config file not found", str(cm.exception))

    def test_load_config_raises_for_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(tmpdir, "{invalid")
            with self.assertRaises(ConfigError) as cm:
                load_config(path)
        self.assertIn("not valid JSON", str(cm.exception))

    def test_load_config_raises_for_missing_required_keys(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(tmpdir, json.dumps({"ssid": "MyWiFi"}))
            with self.assertRaises(ConfigError) as cm:
                load_config(path)
        self.assertIn("missing required keys", str(cm.exception))

    def test_load_config_raises_for_non_mapping_sections(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(
                tmpdir,
                json.dumps(
                    {
                        "ssid": "MyWiFi",
                        "check_url": "http://example.com",
                        "portal": [],
                        "login": {},
                    }
                ),
            )
            with self.assertRaises(ConfigError) as cm:
                load_config(path)
        self.assertIn("portal", str(cm.exception))

    def test_load_config_raises_for_invalid_login_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(
                tmpdir,
                json.dumps(
                    {
                        "ssid": "MyWiFi",
                        "check_url": "http://example.com",
                        "portal": {},
                        "login": {"mode": "teleport"},
                    }
                ),
            )
            with self.assertRaises(ConfigError) as cm:
                load_config(path)
        self.assertIn("login.mode", str(cm.exception))

    def test_load_config_parses_typed_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self.write_config(
                tmpdir,
                json.dumps(
                    {
                        "ssid": "MyWiFi",
                        "check_url": "http://example.com",
                        "portal": {"portal_base_url": "http://portal"},
                        "login": {"username": "u", "password": "p"},
                        "captcha": {"enabled": True, "max_attempts": 3},
                    }
                ),
            )
            config = load_config(path)
        self.assertEqual(config.ssid, "MyWiFi")
        self.assertEqual(config.portal.portal_base_url, "http://portal")
        self.assertEqual(config.portal.auth_path, "/authServlet")
        self.assertEqual(config.login.mode, "auto")
        self.assertEqual(config.login.username, "u")
        self.assertTrue(config.captcha.enabled)
        self.assertEqual(config.captcha.max_attempts, 3)
        self.assertEqual(config.http.timeout_seconds, 8)


if __name__ == "__main__":
    unittest.main()
