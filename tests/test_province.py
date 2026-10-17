import re
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from wifi_auto_login.models import ProvinceRule
from wifi_auto_login.province import (
    load_certify_js_path,
    load_certify_rules,
    normalize_js_regex,
    resolve_province_fields,
)

CERTIFY_JS = """
provs[1].name="ex";
provs[1].realm.rule[0].exp="wlan.example.net";
provs[1].username.rule[0].exp="^138\\\\d{8}$";
provs[1].username.rule[1].exp="^139\\\\d{8}$";
provs[2].name="ah";
provs[2].realm.rule[0].exp="wlan.ah.example.net";
provs[3].name="nameless";
"""


class ProvinceTests(unittest.TestCase):
    def setUp(self):
        # lru_cache 会跨测试复用同一 Path 的解析结果
        load_certify_rules.cache_clear()

    def write_certify(self, content: str) -> Path:
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        path = Path(tmpdir.name) / "certify.js"
        path.write_text(content, encoding="utf-8")
        return path

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

    def test_normalize_js_regex_unescapes_double_backslash(self):
        self.assertEqual(normalize_js_regex(r"^138\\d{8}$"), r"^138\d{8}$")

    def test_resolve_province_fields_returns_empty_without_match(self):
        rules = [ProvinceRule(name="ex", realm="wlan.example.net", username_patterns=[])]
        self.assertEqual(resolve_province_fields("99999999", rules), {})
        self.assertEqual(resolve_province_fields("", rules), {})
        self.assertEqual(resolve_province_fields("13800138000", []), {})

    def test_load_certify_rules_parses_real_shaped_js(self):
        rules = load_certify_rules(self.write_certify(CERTIFY_JS))
        by_name = {rule.name: rule for rule in rules}

        self.assertEqual(set(by_name), {"ex", "ah", "nameless"})
        self.assertEqual(by_name["ex"].realm, "wlan.example.net")
        self.assertEqual(len(by_name["ex"].username_patterns), 2)
        # 未经转义的 JS 正则在这里必须能编译并匹配真实手机号
        self.assertTrue(by_name["ex"].username_patterns[0].match("13800138000"))
        # 没有 realm 的条目仍保留（name 存在即收录）
        self.assertEqual(by_name["nameless"].realm, "")

    def test_load_certify_rules_skips_uncompilable_patterns(self):
        rules = load_certify_rules(
            self.write_certify(
                'provs[1].name="ex";\nprovs[1].username.rule[0].exp="^(unclosed";\n'
            )
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].username_patterns, [])

    def test_load_certify_rules_skips_entries_without_name(self):
        self.assertEqual(
            load_certify_rules(self.write_certify('provs[1].realm.rule[0].exp="^x$";\n')),
            [],
        )

    def test_load_certify_rules_returns_empty_on_missing_file(self):
        self.assertEqual(load_certify_rules(Path("/nonexistent/certify.js")), [])

    def test_load_certify_js_path_prefers_explicit_file(self):
        path = self.write_certify(CERTIFY_JS)
        self.assertEqual(load_certify_js_path(str(path), PROJECT_ROOT), path)

    def test_load_certify_js_path_falls_back_to_rglob(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "_files" / "certify.js"
            target.parent.mkdir(parents=True)
            target.write_text(CERTIFY_JS, encoding="utf-8")
            nested = Path(root) / "deep" / "nested"
            nested.mkdir(parents=True)
            (nested / "certify.js").write_text(CERTIFY_JS, encoding="utf-8")
            # 明确指定一个不存在的路径，应回退到扫描
            self.assertEqual(
                load_certify_js_path("/nonexistent/certify.js", Path(root)), target
            )

    def test_load_certify_js_path_returns_none_without_candidates(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertIsNone(load_certify_js_path("", Path(root)))

    def test_load_certify_js_path_ignores_venv(self):
        with tempfile.TemporaryDirectory() as root:
            venv = Path(root) / ".venv" / "lib" / "certify.js"
            venv.parent.mkdir(parents=True)
            venv.write_text(CERTIFY_JS, encoding="utf-8")
            self.assertIsNone(load_certify_js_path("", Path(root)))


if __name__ == "__main__":
    unittest.main()
