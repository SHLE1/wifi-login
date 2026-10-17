import hashlib
import logging
import re
from html.parser import HTMLParser
from typing import Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

from .models import PortalForm


logger = logging.getLogger("wifi_portal_login")


class SimpleFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[PortalForm] = []
        self._in_form = False
        self._current_action = ""
        self._current_method = "get"
        self._current_inputs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[Tuple[str, str]]) -> None:
        attrs_dict = dict(attrs)
        if tag.lower() == "form":
            self._in_form = True
            self._current_action = attrs_dict.get("action", "")
            self._current_method = attrs_dict.get("method", "get").lower()
            self._current_inputs = {}
            return

        if self._in_form and tag.lower() == "input":
            name = attrs_dict.get("name")
            if not name:
                return
            value = attrs_dict.get("value", "")
            self._current_inputs[name] = value

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_form:
            self.forms.append(
                PortalForm(
                    action=self._current_action,
                    method=self._current_method,
                    inputs=self._current_inputs,
                )
            )
            self._in_form = False

    def close(self) -> None:
        super().close()
        if self._in_form:
            self.forms.append(
                PortalForm(
                    action=self._current_action,
                    method=self._current_method,
                    inputs=self._current_inputs,
                )
            )
            self._in_form = False


def clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def extract_error_hint(text: str) -> str:
    if not text:
        return ""
    patterns = (
        r'alert\(["\']([^"\']+)["\']\)',
        r'<p[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)</p>',
        r'<span[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)</span>',
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return clean_text(match.group(1))
    return ""


def extract_param_str(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    values = query.get("paramStr")
    if values:
        return values[0]
    return ""


def find_param_str_in_html(html: str) -> str:
    match = re.search(r"paramStr=([A-Za-z0-9%+_=\-]+)", html)
    return match.group(1) if match else ""


def normalize_param_str(value: str) -> str:
    if not value:
        return ""
    return value.replace("%0D%0A", "\r\n")


def hash_param_str(value: str) -> str:
    """稳定短 hash（跨进程可对齐日志）。"""
    if not value:
        return ""
    return hashlib.md5(value.encode("utf-8")).hexdigest()[:8]


def extract_param_str_from_html(html: str) -> str:
    match = re.search(r'name="paramStr"[^>]*value="([^"]+)"', html, re.IGNORECASE)
    if match:
        return match.group(1)
    return ""


def is_valid_param_str(value: str) -> bool:
    if not value:
        return False
    trimmed = value.strip()
    if not trimmed:
        return False
    if trimmed.lower() in {"null", "undefined"}:
        return False
    return len(trimmed) >= 16


def select_best_param_str(candidates: list[Tuple[str, str]]) -> Tuple[str, str]:
    if not candidates:
        return "", ""
    valid_candidates = [item for item in candidates if is_valid_param_str(item[1])]
    if valid_candidates:
        return max(valid_candidates, key=lambda item: len(item[1]))
    return max(candidates, key=lambda item: len(item[1]))


def resolve_param_str(
    portal_url: str,
    login_url: str,
    html: str,
    discover_param: str,
    form: Optional[PortalForm],
) -> Tuple[str, str]:
    if form:
        if "paramStr" in form.inputs and form.inputs["paramStr"]:
            form_param = form.inputs["paramStr"]
            if is_valid_param_str(form_param):
                logger.debug("Using paramStr from form input (freshest)")
                return "form_input", normalize_param_str(form_param)
        if form.action:
            action_value = extract_param_str(urljoin(portal_url, form.action))
            if is_valid_param_str(action_value):
                logger.debug("Using paramStr from form action")
                return "form_action", normalize_param_str(action_value)

    html_param = extract_param_str_from_html(html)
    if is_valid_param_str(html_param):
        logger.debug("Using paramStr from HTML input field")
        return "html", normalize_param_str(html_param)

    candidates: list[Tuple[str, str]] = []
    for label, value in (
        ("discover", discover_param),
        ("portal_url", extract_param_str(portal_url)),
        ("login_url", extract_param_str(login_url)),
    ):
        if value:
            candidates.append((label, value))

    best_label, best_value = select_best_param_str(candidates)
    return best_label, normalize_param_str(best_value)


def choose_form(html: str) -> Optional[PortalForm]:
    parser = SimpleFormParser()
    parser.feed(html)
    parser.close()
    if not parser.forms:
        return None
    return parser.forms[0]


def find_frame_src(html: str, preferred_name: str = "mainFrame") -> str:
    match = re.search(
        rf'<frame[^>]+name="{re.escape(preferred_name)}"[^>]+src="([^"]+)"',
        html,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    match = re.search(r'<frame[^>]+src="([^"]+)"', html, re.IGNORECASE)
    return match.group(1) if match else ""


def find_captcha_src(html: str) -> str:
    match = re.search(r'id="verifyCode_img"[^>]+src="([^"]+)"', html, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r'createVerifycode[^"]*', html, re.IGNORECASE)
    return match.group(0) if match else ""
