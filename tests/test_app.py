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


from wifi_auto_login.app import attempt_direct_login, build_login_url, load_login_page, main
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
    def test_ssid_mismatch_never_creates_network_session(self):
        with patch("wifi_auto_login.app.load_config", return_value=make_config()), \
             patch("wifi_auto_login.logging_config.setup_logging"), \
             patch("wifi_auto_login.app.get_wifi_device", return_value="en0"), \
             patch("wifi_auto_login.app.get_current_ssid", return_value="OtherWiFi"), \
             patch("wifi_auto_login.app.build_session") as session, \
             self.assertLogs("wifi_portal_login", level="INFO") as logs:
            self.assertEqual(main(), 0)
        session.assert_not_called()
        self.assertIn("SSID mismatch: current=OtherWiFi target=MyWiFi", "\n".join(logs.output))

    def test_missing_device_returns_exit_2_without_network(self):
        with patch("wifi_auto_login.app.load_config", return_value=make_config()), \
             patch("wifi_auto_login.logging_config.setup_logging"), \
             patch("wifi_auto_login.app.get_wifi_device", return_value=None), \
             patch("wifi_auto_login.app.build_session") as session, \
             self.assertLogs("wifi_portal_login", level="ERROR") as logs:
            self.assertEqual(main(), 2)
        session.assert_not_called()
        self.assertIn("Wi-Fi device not found", "\n".join(logs.output))

    def test_already_online_skips_portal_discovery(self):
        with patch("wifi_auto_login.app.load_config", return_value=make_config()), \
             patch("wifi_auto_login.logging_config.setup_logging"), \
             patch("wifi_auto_login.app.get_wifi_device", return_value="en0"), \
             patch("wifi_auto_login.app.get_current_ssid", return_value="MyWiFi"), \
             patch("wifi_auto_login.app.build_session"), \
             patch("wifi_auto_login.app.check_online", return_value=True), \
             patch("wifi_auto_login.app.load_login_page") as load_page, \
             self.assertLogs("wifi_portal_login", level="INFO") as logs:
            self.assertEqual(main(), 0)
        load_page.assert_not_called()
        self.assertIn("Already online", "\n".join(logs.output))

    def test_load_login_page_reuses_html_and_fetches_only_frame(self):
        from unittest.mock import Mock

        session = Mock()
        session.get.return_value.text = "<form></form>"
        page = PortalPage(
            url="http://portal/index",
            html='<frame name="mainFrame" src="/login?paramStr=FRAMEPARAM12345678">',
        )
        with patch("wifi_auto_login.app.discover_portal", return_value=page):
            result = load_login_page(session, make_config(), 5)
        self.assertEqual(result.url, "http://portal/login?paramStr=FRAMEPARAM12345678")
        self.assertEqual(result.param_str, "FRAMEPARAM12345678")
        self.assertEqual(result.html, "<form></form>")
        session.get.assert_called_once_with(result.url, timeout=5)

    def test_direct_mode_failure_does_not_fall_back_to_form(self):
        config = make_config()
        config.login.mode = "direct"
        with patch("wifi_auto_login.app.load_config", return_value=config), \
             patch("wifi_auto_login.logging_config.setup_logging"), \
             patch("wifi_auto_login.app.get_wifi_device", return_value="en0"), \
             patch("wifi_auto_login.app.get_current_ssid", return_value=config.ssid), \
             patch("wifi_auto_login.app.build_session"), \
             patch("wifi_auto_login.app.check_online", return_value=False), \
             patch("wifi_auto_login.app.has_portal_connectivity", return_value=True), \
             patch("wifi_auto_login.app.load_login_page", return_value=PortalPage(url="http://portal/login")), \
             patch("wifi_auto_login.app.attempt_direct_login", return_value=False), \
             patch("wifi_auto_login.app.attempt_form_login") as form, \
             patch("wifi_auto_login.app.time.sleep"), \
             self.assertLogs("wifi_portal_login", level="ERROR") as logs:
            self.assertEqual(main(), 4)
        form.assert_not_called()
        self.assertIn("Login failed", "\n".join(logs.output))

    def test_attempt_direct_login_checks_online_only_after_request(self):
        import requests
        from unittest.mock import Mock

        session = Mock()
        session.get.return_value.status_code = 200
        session.get.return_value.headers = {}
        with patch("wifi_auto_login.app.check_online", return_value=True) as online:
            self.assertTrue(attempt_direct_login(session, "http://portal/login", "http://check", 5))
        session.get.assert_called_once_with("http://portal/login", timeout=5)
        online.assert_called_once_with(session, "http://check", 5)

        session.get.side_effect = requests.ConnectionError("offline")
        with patch("wifi_auto_login.app.check_online") as online:
            self.assertFalse(attempt_direct_login(session, "http://portal/login", "http://check", 5))
        online.assert_not_called()

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
        return_value=PortalPage(
            url="http://portal.example", html="<form></form>", param_str="PARAM123456789012"
        ),
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
        session.get.assert_not_called()
        # form 登录使用复用的页面 HTML，而不是重新抓取
        request = submit_login_form_mock.call_args[0][1]
        self.assertEqual(request.html, "<form></form>")
        self.assertEqual(request.login.username, "u")
        self.assertEqual(request.param_str, "PARAM123456789012")
        self.assertEqual(request.param_str_source, "discover")


if __name__ == "__main__":
    unittest.main()
