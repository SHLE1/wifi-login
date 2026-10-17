import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.models import PortalForm
from wifi_auto_login.parsing import (
    choose_form,
    extract_error_hint,
    extract_param_str,
    extract_param_str_from_html,
    find_captcha_src,
    find_frame_src,
    find_param_str_in_html,
    resolve_param_str,
)


class ParsingTests(unittest.TestCase):
    def test_extract_error_hint_from_alert(self):
        html = '<script>alert("验证码错误，请重试");</script>'
        self.assertEqual(extract_error_hint(html), "验证码错误，请重试")

    def test_extract_error_hint_from_error_element(self):
        html = '<p class="form-error">  用户名或密码错误  </p>'
        self.assertEqual(extract_error_hint(html), "用户名或密码错误")

    def test_extract_param_str_from_url(self):
        url = "http://example.com/login?foo=1&paramStr=ABCDEF1234567890&bar=2"
        self.assertEqual(extract_param_str(url), "ABCDEF1234567890")

    def test_find_param_str_in_html(self):
        html = '<a href="/index.jsp?paramStr=ABCDEF1234567890">go</a>'
        self.assertEqual(find_param_str_in_html(html), "ABCDEF1234567890")

    def test_extract_param_str_from_html_hidden_input(self):
        html = '<input type="hidden" name="paramStr" value="ABCDEF1234567890">'
        self.assertEqual(extract_param_str_from_html(html), "ABCDEF1234567890")

    def test_resolve_param_str_prefers_form_input(self):
        form = PortalForm(
            action="/auth",
            method="post",
            inputs={"paramStr": "FORMPARAM12345678"},
        )
        source, value = resolve_param_str(
            "http://portal/index.jsp?paramStr=PORTALPARAM123456",
            "http://portal/logon.jsp?paramStr=LOGINPARAM1234567",
            '<input name="paramStr" value="HTMLPARAM12345678">',
            "DISCOVERPARAM123456",
            form,
        )
        self.assertEqual((source, value), ("form_input", "FORMPARAM12345678"))

    def test_resolve_param_str_falls_back_to_form_action(self):
        form = PortalForm(
            action="/authServlet?paramStr=ACTIONPARAM123456",
            method="post",
            inputs={},
        )
        source, value = resolve_param_str(
            "http://portal/index.jsp",
            "http://portal/logon.jsp",
            "",
            "",
            form,
        )
        self.assertEqual((source, value), ("form_action", "ACTIONPARAM123456"))

    def test_resolve_param_str_falls_back_to_html_then_discover(self):
        source, value = resolve_param_str(
            "http://portal/index.jsp",
            "http://portal/logon.jsp",
            '<input type="hidden" name="paramStr" value="HTMLPARAM12345678">',
            "DISCOVERPARAM123456",
            None,
        )
        self.assertEqual((source, value), ("html", "HTMLPARAM12345678"))

        source, value = resolve_param_str(
            "http://portal/index.jsp",
            "http://portal/logon.jsp",
            "",
            "DISCOVERPARAM123456",
            None,
        )
        self.assertEqual((source, value), ("discover", "DISCOVERPARAM123456"))

    def test_choose_form_returns_first_form(self):
        html = """
        <form action="/first" method="post">
          <input name="UserName" value="">
        </form>
        <form action="/second" method="post"></form>
        """
        form = choose_form(html)
        self.assertIsNotNone(form)
        self.assertEqual(form.action, "/first")
        self.assertIn("UserName", form.inputs)

    def test_find_frame_src_prefers_named_frame(self):
        html = """
        <frameset>
          <frame name="sidebar" src="/left.html">
          <frame name="mainFrame" src="/main.html">
        </frameset>
        """
        self.assertEqual(find_frame_src(html), "/main.html")

    def test_find_captcha_src_supports_image_and_js_fallback(self):
        html = '<img id="verifyCode_img" src="/captcha?random=1">'
        self.assertEqual(find_captcha_src(html), "/captcha?random=1")

        js_html = '<script>createVerifycode("/createVerifycode");</script>'
        self.assertEqual(find_captcha_src(js_html), "/createVerifycode")

        # 无参调用拿不到可用 URL，应返回空串而不是截断的函数名
        self.assertEqual(find_captcha_src("<script>createVerifycode()</script>"), "")


if __name__ == "__main__":
    unittest.main()
