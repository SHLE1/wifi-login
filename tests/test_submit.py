import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.config import CaptchaConfig, DebugConfig, LoginConfig
from wifi_auto_login.submit import (
    SubmitRequest,
    build_request_headers,
    sanitize_response,
    save_response_snapshot,
    submit_login_form,
)


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
    def test_sanitize_response_masks_all_secrets(self):
        text = (
            '<input name="UserName" value="alice">'
            '<input name="PassWord" value="s3cr3t">'
            '<input name="verifycode" value="A1B2">'
            "<p>paramStr=ABCsDEF1234567890&next=1</p>"
        )
        sanitized = sanitize_response(text, "alice", "s3cr3t")
        self.assertNotIn("alice", sanitized)
        self.assertNotIn("s3cr3t", sanitized)
        self.assertNotIn("A1B2", sanitized)
        self.assertNotIn("ABCsDEF1234567890", sanitized)
        self.assertIn("paramStr=***", sanitized)

    def test_sanitize_response_handles_empty_input(self):
        self.assertEqual(sanitize_response("", "alice", "s3cr3t"), "")

    def test_save_response_snapshot_truncates_to_max_bytes(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            debug = DebugConfig(
                save_response=True,
                response_dir=tmpdir,
                max_response_bytes=16,
            )
            save_response_snapshot(debug, "x" * 1000)
            files = list(Path(tmpdir).glob("response_*.html"))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].stat().st_size, 16)

    def test_save_response_snapshot_skips_empty_text(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            save_response_snapshot(DebugConfig(response_dir=tmpdir), "")
            self.assertEqual(list(Path(tmpdir).glob("*.html")), [])

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

    @patch("wifi_auto_login.submit.check_online", return_value=False)
    def test_submit_login_form_uses_get_with_params_for_get_forms(self, _check_online):
        session = FakeSession(FakeResponse(status_code=200, text="nope"))
        html = """
        <form action="/auth" method="get">
          <input name="UserName" value="">
          <input name="PassWord" value="">
        </form>
        """
        result = submit_login_form(session, make_request(html))

        method, url, payload, _timeout, _headers = session.calls[0]
        self.assertEqual(method, "get")
        self.assertEqual(url, "http://portal/auth")
        self.assertEqual(payload["UserName"], "alice")
        self.assertFalse(result.success)
        self.assertEqual(result.last_status, 200)

    @patch("wifi_auto_login.submit.check_online", return_value=False)
    def test_submit_login_form_reports_captcha_failure_hint(self, _check_online):
        session = FakeSession(FakeResponse(status_code=200, text="ok"))
        html = """
        <form action="/auth" method="post">
          <input name="UserName" value="">
          <input name="PassWord" value="">
        </form>
        """
        captcha = CaptchaConfig(enabled=True, max_attempts=2, retry_delay=0.0)
        with patch("wifi_auto_login.submit.solve_captcha", return_value=""):
            result = submit_login_form(session, make_request(html, captcha=captcha))

        self.assertFalse(result.success)
        self.assertEqual(result.captcha_attempts, 2)
        self.assertEqual(result.captcha_failures, 2)
        # OCR 始终失败时不应留下无法诊断的空 hint
        self.assertEqual(result.error_hint, "captcha_failed")
        # 从未提交过任何请求
        self.assertEqual(session.calls, [])

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
