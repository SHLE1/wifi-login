import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.system import get_current_ssid, get_wifi_device


class SystemTests(unittest.TestCase):
    @patch("wifi_auto_login.system.run_shell", return_value="en0")
    def test_get_wifi_device_prefers_shell_result(self, _run_shell):
        self.assertEqual(get_wifi_device(), "en0")

    @patch("wifi_auto_login.system.run_shell", return_value="")
    @patch(
        "wifi_auto_login.system.run_cmd",
        return_value="Hardware Port: Wi-Fi\nDevice: en1\nEthernet Address: 00:11:22:33:44:55",
    )
    def test_get_wifi_device_falls_back_to_networksetup(self, _run_cmd, _run_shell):
        self.assertEqual(get_wifi_device(), "en1")

    @patch("wifi_auto_login.system._ssid_from_corewlan", return_value="PCDN_5G")
    def test_get_current_ssid_prefers_corewlan(self, _corewlan):
        self.assertEqual(get_current_ssid("en0"), "PCDN_5G")

    @patch("wifi_auto_login.system._ssid_from_corewlan", return_value=None)
    @patch("wifi_auto_login.system.run_shell", side_effect=["", "", ""])
    @patch(
        "wifi_auto_login.system.run_cmd",
        return_value="Current Wi-Fi Network: MyWiFi",
    )
    def test_get_current_ssid_falls_back_to_airportnetwork(
        self, _run_cmd, _run_shell, _corewlan
    ):
        self.assertEqual(get_current_ssid("en0"), "MyWiFi")


if __name__ == "__main__":
    unittest.main()
