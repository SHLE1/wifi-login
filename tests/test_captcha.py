import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

import requests
from wifi_auto_login.captcha import (
    binarize_image,
    filter_whitelist,
    refresh_captcha_url,
    solve_captcha,
)
from wifi_auto_login.config import CaptchaConfig


class FakeResponse:
    def __init__(self, status_code=200, content=b""):
        self.status_code = status_code
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")


class FakeSession:
    def __init__(self, response=None):
        self.response = response or FakeResponse()
        self.urls = []

    def get(self, url, timeout=None):
        self.urls.append(url)
        return self.response


def png_bytes(value: int, size=(4, 4)) -> bytes:
    from io import BytesIO

    from PIL import Image

    buffer = BytesIO()
    Image.new("L", size, color=value).save(buffer, format="PNG")
    return buffer.getvalue()


class CaptchaTests(unittest.TestCase):
    def test_refresh_captcha_url_appends_random_when_absent(self):
        self.assertEqual(refresh_captcha_url(""), "")
        self.assertTrue(refresh_captcha_url("/captcha").startswith("/captcha?random="))

    def test_refresh_captcha_url_replaces_existing_random(self):
        refreshed = refresh_captcha_url("/captcha?random=123&v=2")
        self.assertNotIn("random=123", refreshed)
        self.assertIn("v=2", refreshed)

    def test_refresh_captcha_url_uses_ampersand_when_query_present(self):
        self.assertIn("&random=", refresh_captcha_url("/captcha?v=2"))

    def test_filter_whitelist_keeps_only_allowed_chars(self):
        self.assertEqual(filter_whitelist("a1b2", "0123456789"), "12")
        self.assertEqual(filter_whitelist("a1b2", ""), "a1b2")
        self.assertEqual(filter_whitelist("", "0123"), "")
        self.assertEqual(filter_whitelist("a!b", "ab"), "ab")

    def test_binarize_image_disabled_when_threshold_zero(self):
        raw = png_bytes(10)
        self.assertEqual(binarize_image(raw, 0), raw)

    def test_binarize_image_thresholds_pixels(self):
        from io import BytesIO

        from PIL import Image

        out = binarize_image(png_bytes(200), 150)
        self.assertEqual(Image.open(BytesIO(out)).getpixel((0, 0)), 255)

        out = binarize_image(png_bytes(50), 150)
        self.assertEqual(Image.open(BytesIO(out)).getpixel((0, 0)), 0)

    def test_solve_captcha_returns_empty_without_src(self):
        session = FakeSession()
        self.assertEqual(
            solve_captcha(session, "http://portal", "<html></html>", 5, CaptchaConfig()),
            "",
        )
        self.assertEqual(session.urls, [])

    def test_solve_captcha_uses_js_src_as_absolute_url(self):
        session = FakeSession(FakeResponse(content=png_bytes(200)))
        html = '<script>createVerifycode("/createVerifycode");</script>'

        with patch("wifi_auto_login.captcha.get_ocr_instance") as ocr:
            ocr.return_value.classification.return_value = "abcd"
            code = solve_captcha(session, "http://portal/", html, 5, CaptchaConfig())

        # 修复前这里会是 http://portal/createVerifycode( 这样的坏 URL
        self.assertEqual(session.urls[0].split("?")[0], "http://portal/createVerifycode")
        self.assertEqual(code, "abcd")

    def test_solve_captcha_returns_empty_on_http_error(self):
        session = FakeSession(FakeResponse(status_code=404))
        self.assertEqual(
            solve_captcha(
                session, "http://portal", '<img id="verifyCode_img" src="/c">', 5, CaptchaConfig()
            ),
            "",
        )

    def test_solve_captcha_returns_empty_when_ocr_raises(self):
        session = FakeSession(FakeResponse(content=png_bytes(200)))
        html = '<img id="verifyCode_img" src="/c">'

        with patch("wifi_auto_login.captcha.get_ocr_instance") as ocr:
            ocr.return_value.classification.side_effect = RuntimeError("model gone")
            self.assertEqual(solve_captcha(session, "http://portal", html, 5, CaptchaConfig()), "")

    def test_solve_captcha_applies_whitelist(self):
        session = FakeSession(FakeResponse(content=png_bytes(200)))
        html = '<img id="verifyCode_img" src="/c">'

        with patch("wifi_auto_login.captcha.get_ocr_instance") as ocr:
            ocr.return_value.classification.return_value = "a1-b2"
            code = solve_captcha(
                session, "http://portal", html, 5, CaptchaConfig(whitelist="0123456789")
            )

        self.assertEqual(code, "12")


if __name__ == "__main__":
    unittest.main()
