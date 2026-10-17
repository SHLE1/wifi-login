import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


from wifi_auto_login.network import (
    check_online,
    discover_portal,
    has_portal_connectivity,
    probe_portal_manual,
    resolve_portal_url,
)
from wifi_auto_login.parsing import (
    hash_param_str,
    is_valid_param_str,
    normalize_param_str,
    select_best_param_str,
)
import requests


class FakeResponse:
    def __init__(self, status_code=200, url="", headers=None, history=None, text=""):
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self.history = history or []
        self.text = text


class FakeSession:
    def __init__(self, response):
        self._response = response

    def get(self, *_args, **_kwargs):
        return self._response


class RecordingSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls = []

    def get(self, url, **_kwargs):
        self.urls.append(url)
        if not self.responses:
            raise AssertionError(f"unexpected request: {url}")
        return self.responses.pop(0)


class RedirectSession:
    """按 URL 返回预设响应，未命中则报错（避免静默 404 掩盖意外请求）。"""

    def __init__(self, responses):
        self.responses = responses
        self.urls = []

    def get(self, url, **_kwargs):
        self.urls.append(url)
        if url not in self.responses:
            raise AssertionError(f"unexpected request: {url}")
        return self.responses[url]


class NetworkTests(unittest.TestCase):
    def test_check_online_true_for_204(self):
        session = FakeSession(FakeResponse(status_code=204))
        self.assertTrue(check_online(session, "http://check", 5))

    def test_check_online_false_for_redirect(self):
        session = FakeSession(FakeResponse(status_code=302, headers={"Location": "http://portal"}))
        self.assertFalse(check_online(session, "http://check", 5))

    def test_has_portal_connectivity_true_when_portal_reachable(self):
        session = FakeSession(FakeResponse(status_code=200))
        self.assertTrue(
            has_portal_connectivity(session, "http://portal.example", "http://probe", 5)
        )

    def test_check_online_false_when_request_raises(self):
        class RaisingSession:
            def get(self, *_args, **_kwargs):
                raise requests.RequestException("boom")

        self.assertFalse(check_online(RaisingSession(), "http://check", 5))

    def test_has_portal_connectivity_false_when_requests_fail(self):
        class RaisingSession:
            def get(self, *_args, **_kwargs):
                raise requests.RequestException("boom")

        self.assertFalse(
            has_portal_connectivity(RaisingSession(), "http://portal.example", "http://probe", 5)
        )

    def test_probe_portal_manual_follows_multi_hop_chain(self):
        session = RedirectSession(
            {
                "http://check": FakeResponse(
                    status_code=302,
                    headers={"Location": "/a/step1"},
                ),
                "http://check/a/step1": FakeResponse(
                    status_code=302,
                    headers={"Location": "/a/step2?paramStr=MIDPARAM1234567890"},
                ),
                "http://check/a/step2?paramStr=MIDPARAM1234567890": FakeResponse(
                    status_code=200,
                    url="http://check/a/step2?paramStr=MIDPARAM1234567890",
                    text="<html>final</html>",
                ),
            }
        )

        url, param, html, chain = probe_portal_manual(session, "http://check", 5)

        self.assertEqual(url, "http://check/a/step2?paramStr=MIDPARAM1234567890")
        # Location 上的 paramStr 被发现，并原样返回
        self.assertEqual(param, "MIDPARAM1234567890")
        self.assertEqual(html, "<html>final</html>")
        self.assertEqual(
            chain,
            [
                "http://check",
                "http://check/a/step1",
                "http://check/a/step2?paramStr=MIDPARAM1234567890",
            ],
        )

    def test_probe_portal_manual_prefers_longest_param_str(self):
        session = RedirectSession(
            {
                "http://check": FakeResponse(
                    status_code=302,
                    headers={"Location": "/login?paramStr=SHORT123"},
                ),
                "http://check/login?paramStr=SHORT123": FakeResponse(
                    status_code=200,
                    url="http://check/login?paramStr=SHORT123",
                    text='<input name="paramStr" value="AVERYLONGPARAMSTR123456">',
                ),
            }
        )

        _url, param, _html, _chain = probe_portal_manual(session, "http://check", 5)

        # Location 上的 paramStr 太短（不合法），HTML input 里的更长更优
        self.assertEqual(param, "AVERYLONGPARAMSTR123456")

    def test_probe_portal_manual_stops_at_max_redirects(self):
        loop = {
            "http://check": FakeResponse(
                status_code=302, headers={"Location": "/a1"}
            ),
        }
        for i in range(1, 6):
            loop[f"http://check/a{i}"] = FakeResponse(
                status_code=302, headers={"Location": f"/a{i + 1}"}
            )
        session = RedirectSession(loop)

        _url, param, html, chain = probe_portal_manual(
            session, "http://check", 5, max_redirects=3
        )

        self.assertEqual(len(chain), 3)
        # 重定向耗尽：未拿到落地 HTML，也未拿到 paramStr
        self.assertEqual(html, "")
        self.assertEqual(param, "")
        self.assertNotIn("http://check/a4", session.urls)

    def test_is_valid_param_str_rejects_placeholder_and_short_values(self):
        self.assertFalse(is_valid_param_str(""))
        self.assertFalse(is_valid_param_str("   "))
        self.assertFalse(is_valid_param_str("null"))
        self.assertFalse(is_valid_param_str("undefined"))
        self.assertFalse(is_valid_param_str("short"))
        self.assertTrue(is_valid_param_str("PARAM123456789012"))

    def test_normalize_param_str_expands_encoded_crlf(self):
        self.assertEqual(normalize_param_str("AB%0D%0ACDEF"), "AB\r\nCDEF")
        self.assertEqual(normalize_param_str(""), "")

    def test_select_best_param_str_falls_back_when_none_valid(self):
        self.assertEqual(select_best_param_str([]), ("", ""))
        # 候选都不合法时退化为取最长值，不丢弃信息
        self.assertEqual(
            select_best_param_str([("a", "null"), ("b", "undefined")]),
            ("b", "undefined"),
        )
        self.assertEqual(
            select_best_param_str([("a", "short"), ("b", "muchlongervalue123")]),
            ("b", "muchlongervalue123"),
        )

    def test_hash_param_str_is_stable_and_short(self):
        self.assertEqual(hash_param_str("abc"), hash_param_str("abc"))
        self.assertNotEqual(hash_param_str("abc"), hash_param_str("abd"))
        self.assertEqual(len(hash_param_str("abc")), 8)
        self.assertEqual(hash_param_str(""), "")

    def test_resolve_portal_url_falls_back_to_base_and_index(self):
        self.assertEqual(
            resolve_portal_url("", "http://portal.example", "/style/index.jsp"),
            "http://portal.example/style/index.jsp",
        )

    def test_discover_portal_prefers_probe_url_when_it_has_param_str(self):
        session = RecordingSession(
            [
                FakeResponse(
                    status_code=200,
                    url="http://portal.example",
                    text='<a href="/index.jsp?paramStr=PROBEPARAM1234567890">login</a>',
                )
            ]
        )

        page = discover_portal(
            session,
            "http://check",
            5,
            "http://portal.example",
            "/style/index.jsp",
            "http://portal.example",
        )

        self.assertEqual(page.url, "http://portal.example")
        self.assertEqual(page.param_str, "PROBEPARAM1234567890")
        # 探测时抓到的 HTML 直接复用，不再重复请求
        self.assertIn("PROBEPARAM1234567890", page.html)
        self.assertEqual(session.urls, ["http://portal.example"])

    def test_discover_portal_falls_back_to_check_url_when_probe_has_no_param_str(self):
        session = RecordingSession(
            [
                FakeResponse(status_code=200, url="http://portal.example", text="<html></html>"),
                FakeResponse(
                    status_code=302,
                    url="http://check",
                    headers={"Location": "http://portal/login?paramStr=CHECKPARAM1234567890"},
                ),
                FakeResponse(
                    status_code=200,
                    url="http://portal/login?paramStr=CHECKPARAM1234567890",
                    text="<html></html>",
                ),
            ]
        )

        page = discover_portal(
            session,
            "http://check",
            5,
            "http://portal.example",
            "/style/index.jsp",
            "http://portal.example",
        )

        self.assertEqual(page.url, "http://portal/login?paramStr=CHECKPARAM1234567890")
        self.assertEqual(page.param_str, "CHECKPARAM1234567890")
        # probe_url 探测失败后不再对同一 URL 二次探测
        self.assertEqual(
            session.urls,
            [
                "http://portal.example",
                "http://check",
                "http://portal/login?paramStr=CHECKPARAM1234567890",
            ],
        )


if __name__ == "__main__":
    unittest.main()
