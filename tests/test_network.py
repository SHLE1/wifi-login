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
    resolve_portal_url,
)


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
            return FakeResponse(status_code=404, url=url)
        return self.responses.pop(0)


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

    def test_has_portal_connectivity_false_when_requests_fail(self):
        class RaisingSession:
            def get(self, *_args, **_kwargs):
                raise Exception("boom")

        self.assertFalse(
            has_portal_connectivity(RaisingSession(), "http://portal.example", "http://probe", 5)
        )

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
