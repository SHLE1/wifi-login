import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.app import build_login_url, main
from wifi_auto_login.config import (
    AppConfig,
    ConfigError,
    CaptchaConfig,
    DebugConfig,
    HttpConfig,
    LoginConfig,
    PortalConfig,
)
from wifi_auto_login.models import PortalPage


def make_config() -> AppConfig:
    return AppConfig(
        ssid="MyWiFi",
        check_url="http://check",
        portal=PortalConfig(
            portal_base_url="http://portal.example",
            probe_url="http://probe",
            login_path="/style/logon.jsp",
            index_path="/style/index.jsp",
            auth_path="/authServlet",
        ),
        login=LoginConfig(mode="form", auto_province=False, username="u", password="p"),
        http=HttpConfig(timeout_seconds=5, user_agent="ua"),
        captcha=CaptchaConfig(),
        debug=DebugConfig(),
    )


class AppTests(unittest.TestCase):
    def test_build_login_url_with_param_str(self):
        self.assertEqual(
            build_login_url(
                "http://portal.example/index.jsp",
                "/style/logon.jsp",
                "PARAM123456789012",
            ),
            "http://portal.example/style/logon.jsp?paramStr=PARAM123456789012",
        )

    def test_build_login_url_rejects_invalid_portal_url(self):
        self.assertEqual(build_login_url("", "/style/logon.jsp", "PARAM"), "")
        self.assertEqual(build_login_url("portal-only", "/style/logon.jsp", "PARAM"), "")

    @patch("sys.stderr", new_callable=io.StringIO)
    @patch("wifi_auto_login.app.load_config", side_effect=ConfigError("bad config"))
    def test_main_returns_error_when_config_invalid(self, _load_config, _stderr):
        self.assertEqual(main(), 2)

    @patch("wifi_auto_login.logging_config.setup_logging")
    @patch("wifi_auto_login.app.requests.Session")
    @patch("wifi_auto_login.app.has_portal_connectivity", return_value=False)
    @patch("wifi_auto_login.app.check_online", return_value=False)
    @patch("wifi_auto_login.app.get_current_ssid", return_value="MyWiFi")
    @patch("wifi_auto_login.app.get_wifi_device", return_value="en0")
    @patch("wifi_auto_login.app.load_config", return_value=make_config())
    def test_main_returns_error_when_portal_unreachable(
        self,
        _load_config,
        _get_wifi_device,
        _get_current_ssid,
        _check_online,
        _has_portal_connectivity,
        session_cls,
        _setup_logging,
    ):
        session_cls.return_value.headers = {}
        self.assertEqual(main(), 3)

    @patch("wifi_auto_login.logging_config.setup_logging")
    @patch(
        "wifi_auto_login.app.discover_portal",
        return_value=PortalPage(url="http://portal.example", param_str="PARAM123456789012"),
    )
    @patch("wifi_auto_login.app.submit_login_form")
    @patch("wifi_auto_login.app.check_online", side_effect=[False, True])
    @patch("wifi_auto_login.app.has_portal_connectivity", return_value=True)
    @patch("wifi_auto_login.app.get_current_ssid", return_value="MyWiFi")
    @patch("wifi_auto_login.app.get_wifi_device", return_value="en0")
    @patch("wifi_auto_login.app.requests.Session")
    @patch("wifi_auto_login.app.load_config", return_value=make_config())
    @patch("wifi_auto_login.app.time.sleep")
    def test_main_logs_in_via_form_flow(
        self,
        _sleep,
        _load_config,
        session_cls,
        _get_wifi_device,
        _get_current_ssid,
        _has_portal_connectivity,
        _check_online,
        submit_login_form_mock,
        discover_portal_mock,
        _setup_logging,
    ):
        session = session_cls.return_value
        session.headers = {}
        session.get.return_value.text = "<form></form>"
        session.get.return_value.headers = {}
        session.get.return_value.status_code = 200
        submit_login_form_mock.return_value = SimpleNamespace(last_status=200, error_hint="")
        self.assertEqual(main(), 0)
        discover_portal_mock.assert_called_once()
        submit_login_form_mock.assert_called_once()
        # form 登录使用复用的页面 HTML，而不是重新抓取
        request = submit_login_form_mock.call_args[0][1]
        self.assertEqual(request.html, "<form></form>")
        self.assertEqual(request.login.username, "u")


if __name__ == "__main__":
    unittest.main()
