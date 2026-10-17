import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.config import CaptchaConfig, DebugConfig, LoginConfig
from wifi_auto_login.submit import SubmitRequest, build_request_headers, submit_login_form


class FakeResponse:
    def __init__(self, status_code=200, url="http://portal/auth", headers=None, text=""):
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self.text = text


class FakeSession:
    def __init__(self, response=None):
        self.response = response or FakeResponse()
        self.calls = []

    def post(self, url, data=None, timeout=None, headers=None):
        self.calls.append(("post", url, data, timeout, headers))
        return self.response

    def get(self, url, params=None, timeout=None, headers=None):
        self.calls.append(("get", url, params, timeout, headers))
        return self.response


def make_request(
    html: str,
    login: LoginConfig = None,
    captcha: CaptchaConfig = None,
    auth_url: str = "http://portal/auth",
) -> SubmitRequest:
    return SubmitRequest(
        portal_url="http://portal/index",
        html=html,
        login=login
        or LoginConfig(
            username="alice",
            password="secret",
            username_field="UserName",
            password_field="PassWord",
        ),
        login_url="http://portal/login",
        auth_url=auth_url,
        check_url="http://check",
        captcha=captcha or CaptchaConfig(),
        debug=DebugConfig(),
        timeout=5,
    )


class SubmitTests(unittest.TestCase):
    def test_build_request_headers_handles_invalid_portal_url(self):
        headers = build_request_headers("portal-only")
        self.assertEqual(headers["Origin"], "")
        self.assertEqual(headers["Referer"], "portal-only")

    def test_submit_login_form_returns_form_not_found(self):
        session = FakeSession()
        result = submit_login_form(session, make_request("<html></html>"))
        self.assertFalse(result.success)
        self.assertEqual(result.error_hint, "form_not_found")
        self.assertEqual(result.attempts, 0)
        self.assertEqual(session.calls, [])

    @patch("wifi_auto_login.submit.check_online", return_value=True)
    def test_submit_login_form_marks_success_on_check_online(self, _check_online):
        session = FakeSession(FakeResponse(status_code=200, text="ok"))
        html = """
        <form action="/auth" method="post">
          <input name="UserName" value="">
          <input name="PassWord" value="">
        </form>
        """
        result = submit_login_form(session, make_request(html))
        self.assertTrue(result.success)
        self.assertEqual(result.last_status, 200)
        self.assertEqual(result.attempts, 1)
        self.assertEqual(session.calls[0][0], "post")
        self.assertEqual(session.calls[0][2]["UserName"], "alice")

    @patch("wifi_auto_login.submit.solve_captcha", side_effect=["", "ABCD"])
    @patch("wifi_auto_login.submit.check_online", return_value=True)
    def test_submit_login_form_retries_captcha_until_valid(self, _check_online, _solve):
        session = FakeSession(FakeResponse(status_code=200, text="ok"))
        html = """
        <form action="/auth" method="post">
          <input name="UserName" value="">
          <input name="PassWord" value="">
        </form>
        """
        captcha = CaptchaConfig(
            enabled=True,
            max_attempts=2,
            min_length=4,
            max_length=4,
            retry_delay=0.0,
        )
        result = submit_login_form(session, make_request(html, captcha=captcha))
        self.assertTrue(result.success)
        self.assertEqual(result.captcha_attempts, 2)
        self.assertEqual(result.captcha_failures, 1)
        self.assertEqual(result.attempts, 1)
        self.assertEqual(session.calls[-1][2]["verifycode"], "ABCD")


if __name__ == "__main__":
    unittest.main()
