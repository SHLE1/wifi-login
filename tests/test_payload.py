import re
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.models import PortalForm, ProvinceRule
from wifi_auto_login.payload import build_login_payload
from wifi_auto_login.config import LoginConfig


class PayloadTests(unittest.TestCase):
    def test_build_login_payload_sets_fields_and_overrides(self):
        form = PortalForm(
            action="/auth",
            method="post",
            inputs={
                "UserName": "",
                "PassWord": "",
                "paramStr": "OLDPARAM123456789",
                "defaultProv": "ah",
                "province": "",
            },
        )
        login = LoginConfig(
            username="alice",
            password="secret",
            username_field="UserName",
            password_field="PassWord",
            extra_fields={"custom": "1", "prov": "ex"},
        )
        payload = build_login_payload(
            form=form,
            login=login,
            auto_province=False,
            certify_rules=[],
            param_str="NEWPARAM123456789",
        )
        self.assertEqual(payload["UserName"], "alice")
        self.assertEqual(payload["PassWord"], "secret")
        self.assertEqual(payload["paramStr"], "NEWPARAM123456789")
        self.assertEqual(payload["prov"], "ex")
        self.assertEqual(payload["province"], "ah")
        self.assertEqual(payload["custom"], "1")

    def test_build_login_payload_guesses_fields_and_auto_province(self):
        form = PortalForm(
            action="/auth",
            method="post",
            inputs={
                "userAccount": "",
                "pwdValue": "",
                "province": "",
            },
        )
        rules = [
            ProvinceRule(
                name="ex",
                realm="wlan.example.net",
                username_patterns=[re.compile(r"^138\d{8}$")],
            )
        ]
        login = LoginConfig(username="13800138000", password="secret")
        payload = build_login_payload(
            form=form,
            login=login,
            auto_province=True,
            certify_rules=rules,
            param_str="",
        )
        self.assertEqual(payload["userAccount"], "13800138000")
        self.assertEqual(payload["pwdValue"], "secret")
        self.assertEqual(payload["prov"], "ex")
        self.assertEqual(payload["province"], "wlan.example.net")
        self.assertEqual(payload["shortname"], "ex")


if __name__ == "__main__":
    unittest.main()
