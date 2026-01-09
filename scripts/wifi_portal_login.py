#!/usr/bin/env python3
import json
import logging
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from functools import lru_cache
from html.parser import HTMLParser
from io import BytesIO
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

import requests
import pytesseract
from PIL import Image

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
CONFIG_PATH = PROJECT_ROOT / "config" / "settings.json"
LOG_DIR = PROJECT_ROOT / "logs"

logger = logging.getLogger("wifi_portal_login")


@dataclass
class PortalForm:
    action: str
    method: str
    inputs: Dict[str, str]


@dataclass
class ProvinceRule:
    name: str
    realm: str
    username_patterns: list[re.Pattern]


@dataclass
class SubmitResult:
    success: bool
    attempts: int
    last_status: Optional[int]
    last_url: str
    last_location: str
    error_hint: str
    captcha_attempts: int
    captcha_failures: int


class SimpleFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[PortalForm] = []
        self._in_form = False
        self._current_action = ""
        self._current_method = "get"
        self._current_inputs: Dict[str, str] = {}

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


def load_config() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def mask_value(value: str, keep: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}***{value[-keep:]}"


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


def normalize_js_regex(value: str) -> str:
    return value.replace("\\\\", "\\")


def load_certify_js_path(config: dict) -> Optional[Path]:
    configured = (
        config.get("portal", {}).get("certify_js_path")
        or config.get("login", {}).get("certify_js_path")
    )
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return path
        logger.warning("Configured certify_js_path not found: %s", path)

    candidates = []
    for path in PROJECT_ROOT.rglob("certify.js"):
        if "venv" in path.parts:
            continue
        candidates.append(path)
    if not candidates:
        return None
    candidates.sort(
        key=lambda p: (
            0 if "_files" in p.as_posix() else 1,
            len(p.as_posix()),
        )
    )
    return candidates[0]


@lru_cache(maxsize=2)
def load_certify_rules(certify_path: Path) -> list[ProvinceRule]:
    rules: dict[int, dict[str, object]] = {}
    name_re = re.compile(r'^provs\[(\d+)\]\.name="([^"]+)"')
    realm_re = re.compile(r'^provs\[(\d+)\]\.realm\.rule\[\d+\]\.exp="([^"]+)"')
    user_re = re.compile(
        r'^provs\[(\d+)\]\.username\.rule\[\d+\]\.exp="([^"]+)"'
    )

    try:
        lines = certify_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        logger.warning("Failed to read certify.js: %s", exc)
        return []

    for line in lines:
        name_match = name_re.match(line)
        if name_match:
            idx = int(name_match.group(1))
            entry = rules.setdefault(idx, {"name": "", "realm": "", "patterns": []})
            entry["name"] = name_match.group(2)
            continue

        realm_match = realm_re.match(line)
        if realm_match:
            idx = int(realm_match.group(1))
            entry = rules.setdefault(idx, {"name": "", "realm": "", "patterns": []})
            entry["realm"] = realm_match.group(2)
            continue

        user_match = user_re.match(line)
        if user_match:
            idx = int(user_match.group(1))
            entry = rules.setdefault(idx, {"name": "", "realm": "", "patterns": []})
            pattern = normalize_js_regex(user_match.group(2))
            entry["patterns"].append(pattern)

    result: list[ProvinceRule] = []
    for entry in rules.values():
        name = str(entry.get("name") or "")
        if not name:
            continue
        realm = str(entry.get("realm") or "")
        compiled: list[re.Pattern] = []
        for pattern in entry.get("patterns", []):
            try:
                compiled.append(re.compile(pattern))
            except re.error:
                logger.debug("Invalid certify.js pattern skipped: %s", pattern)
        result.append(
            ProvinceRule(
                name=name,
                realm=realm,
                username_patterns=compiled,
            )
        )
    return result


def resolve_province_fields(username: str, rules: list[ProvinceRule]) -> Dict[str, str]:
    if not username or not rules:
        return {}

    username_base = username
    realm = ""
    if "@" in username:
        username_base, realm = username.split("@", 1)

    if realm:
        for rule in rules:
            if rule.realm == realm:
                return {"shortname": rule.name, "province": rule.realm, "prov": rule.name}

    for rule in rules:
        for pattern in rule.username_patterns:
            if pattern.match(username_base):
                return {"shortname": rule.name, "province": rule.realm, "prov": rule.name}

    return {}


def sanitize_response(text: str, username: str, password: str) -> str:
    if not text:
        return ""
    sanitized = text
    for label, value in (("UserName", username), ("PassWord", password)):
        if value:
            sanitized = sanitized.replace(value, f"{label}=***")
    sanitized = re.sub(r"(paramStr=)[^&\"\\s>]+", r"\\1***", sanitized)
    sanitized = re.sub(
        r'(<input[^>]+name="verifycode"[^>]+value=")[^"]*(")',
        r"\\1***\\2",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


def save_response_snapshot(debug_config: dict, text: str) -> None:
    if not text:
        return
    response_dir = Path(debug_config.get("response_dir", "logs/portal_responses"))
    max_bytes = int(debug_config.get("max_response_bytes", 32768))
    response_dir_path = response_dir
    if not response_dir_path.is_absolute():
        response_dir_path = PROJECT_ROOT / response_dir_path
    response_dir_path.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    file_path = response_dir_path / f"response_{timestamp}.html"
    payload = text.encode("utf-8", errors="ignore")[:max_bytes]
    file_path.write_bytes(payload)
    logger.info("Saved response snapshot: %s", file_path)


def run_cmd(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def run_shell(command: str) -> str:
    result = subprocess.run(
        ["/bin/zsh", "-lc", command], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def get_wifi_device() -> Optional[str]:
    shell_cmd = (
        "_get_wifi_ifname() {\n"
        "  if ! scutil <<< list |\n"
        "    awk -F/ '/Setup:.*AirPort$/{i=$(NF-1);exit} END {if(i) {print i} else {exit 1}}'; then\n"
        "    scutil <<< list | awk -F/ '/en[0-9]+/AirPort$/ {print $(NF-1);exit}'\n"
        "  fi\n"
        "}\n"
        "_get_wifi_ifname\n"
    )
    output = run_shell(shell_cmd)
    if output:
        return output

    output = run_cmd(["networksetup", "-listallhardwareports"])
    if not output:
        return None

    lines = output.splitlines()
    for idx, line in enumerate(lines):
        if "Hardware Port: Wi-Fi" in line or "Hardware Port: AirPort" in line:
            for j in range(idx + 1, min(idx + 4, len(lines))):
                if "Device:" in lines[j]:
                    return lines[j].split(":", 1)[1].strip()
    return None


def get_current_ssid(device: str) -> Optional[str]:
    shell_cmd = (
        f"networksetup -listpreferredwirelessnetworks \"{device}\" | "
        "awk 'NR==2 && sub(\"\\t\",\"\") { print; exit }'"
    )
    output = run_shell(shell_cmd)
    if output:
        return output

    output = run_cmd(["networksetup", "-getairportnetwork", device])
    if not output or "Current Wi-Fi Network" not in output:
        return None
    return output.split(":", 1)[1].strip()


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
    decoded = value.replace("%0D%0A", "\r\n")
    return decoded


def hash_param_str(value: str) -> str:
    if not value:
        return ""
    return f"{abs(hash(value))}"


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


def collect_param_str_candidates(response: Optional[requests.Response]) -> list[Tuple[str, str]]:
    if response is None:
        return []
    candidates: list[Tuple[str, str]] = []
    if response.url:
        candidates.append(("response_url", extract_param_str(response.url)))
    if "Location" in response.headers:
        candidates.append(("response_location", extract_param_str(response.headers["Location"])))
    for idx, hist in enumerate(response.history):
        if hist.url:
            candidates.append((f"history_{idx}_url", extract_param_str(hist.url)))
        if "Location" in hist.headers:
            candidates.append(
                (f"history_{idx}_location", extract_param_str(hist.headers["Location"]))
            )
    return candidates


def probe_portal_manual(
    session: requests.Session,
    url: str,
    timeout: int,
    max_redirects: int = 10,
) -> Tuple[str, str, list[str]]:
    """手动跟踪重定向链，确保捕获每一步的 paramStr。"""
    if not url:
        return "", "", []

    candidates: list[Tuple[str, str]] = []
    chain: list[str] = []
    current_url = url
    final_html = ""

    for step in range(max_redirects):
        try:
            resp = session.get(current_url, allow_redirects=False, timeout=timeout)
        except requests.RequestException as exc:
            logger.debug("Manual probe step %d failed: %s", step, exc)
            break

        chain.append(current_url)

        # 从当前请求 URL 提取
        extracted = extract_param_str(current_url)
        if extracted:
            candidates.append((f"step_{step}_request_url", extracted))

        # 从响应 URL 提取
        if resp.url and resp.url != current_url:
            extracted = extract_param_str(resp.url)
            if extracted:
                candidates.append((f"step_{step}_response_url", extracted))

        # 从 Location 头提取
        location = resp.headers.get("Location", "")
        if location:
            # 处理相对路径
            full_location = urljoin(current_url, location)
            extracted = extract_param_str(full_location)
            if extracted:
                candidates.append((f"step_{step}_location", extracted))
            logger.debug(
                "Manual probe step %d: status=%d location=%s paramStr_len=%d",
                step,
                resp.status_code,
                full_location[:100],
                len(extracted),
            )

        # 检查是否需要继续重定向
        if resp.status_code in (301, 302, 303, 307, 308) and location:
            current_url = urljoin(current_url, location)
        else:
            # 最终页面，尝试从 HTML 中提取
            final_html = resp.text
            html_param = extract_param_str_from_html(final_html)
            if html_param:
                candidates.append((f"step_{step}_html_input", html_param))
            url_param = find_param_str_in_html(final_html)
            if url_param:
                candidates.append((f"step_{step}_html_url", url_param))
            break

    source, param = select_best_param_str(candidates)
    portal_url = current_url

    if chain:
        logger.debug("Manual probe redirect chain (%d steps): %s", len(chain), " -> ".join(chain))
    if candidates:
        logger.debug(
            "Manual probe candidates: %s",
            ", ".join(f"{src}({len(val)})" for src, val in candidates if val),
        )
    if param:
        logger.debug(
            "Manual probe paramStr source=%s length=%s hash=%s",
            source,
            len(param),
            hash_param_str(param),
        )

    return portal_url, normalize_param_str(param), chain


def probe_portal(
    session: requests.Session,
    url: str,
    timeout: int,
) -> Tuple[str, str, list[str]]:
    if not url:
        return "", "", []
    try:
        response = session.get(url, allow_redirects=True, timeout=timeout)
    except requests.RequestException:
        return "", "", []
    chain = [resp.url for resp in response.history] + [response.url]
    candidates = collect_param_str_candidates(response)
    source, param = select_best_param_str(candidates)
    portal_url = response.url or ""
    if not portal_url and "Location" in response.headers:
        portal_url = response.headers.get("Location", "")
    if chain:
        logger.debug("Probe redirect chain: %s", " -> ".join(chain))
    if param:
        logger.debug(
            "Probe paramStr source=%s length=%s hash=%s",
            source,
            len(param),
            hash_param_str(param),
        )
    return portal_url, normalize_param_str(param), chain


def resolve_param_str(
    portal_url: str,
    login_url: str,
    html: str,
    discover_param: str,
    form: Optional[PortalForm],
) -> Tuple[str, str]:
    # 优先使用表单中的 paramStr（最新的，与当前会话匹配）
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

    # 其次使用 HTML 中的 paramStr
    html_param = extract_param_str_from_html(html)
    if is_valid_param_str(html_param):
        logger.debug("Using paramStr from HTML input field")
        return "html", normalize_param_str(html_param)

    # 最后回退到其他来源
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


def check_online(session: requests.Session, check_url: str, timeout: int) -> bool:
    try:
        response = session.get(check_url, allow_redirects=False, timeout=timeout)
    except requests.RequestException:
        return False

    if response.status_code == 204:
        return True
    if "Location" not in response.headers and response.status_code in (200, 204):
        return True
    return False


def discover_portal(
    session: requests.Session,
    check_url: str,
    timeout: int,
    portal_base_url: str,
    index_path: str,
    probe_url: str,
) -> Tuple[str, str]:
    # 首先尝试手动跟踪重定向链（更可靠）
    logger.debug("Trying manual probe with check_url: %s", check_url)
    portal_url, param_str, _ = probe_portal_manual(session, check_url, timeout)

    # 如果手动方式没有获取到有效 paramStr，尝试自动方式
    if not is_valid_param_str(param_str):
        logger.debug("Manual probe failed, trying auto probe with check_url")
        portal_url_auto, param_str_auto, _ = probe_portal(session, check_url, timeout)
        if is_valid_param_str(param_str_auto):
            portal_url, param_str = portal_url_auto, param_str_auto

    # 尝试 probe_url（通常是 captive.apple.com）
    if not is_valid_param_str(param_str) and probe_url:
        logger.debug("Trying manual probe with probe_url: %s", probe_url)
        portal_url_probe, param_str_probe, _ = probe_portal_manual(session, probe_url, timeout)
        if is_valid_param_str(param_str_probe):
            portal_url, param_str = portal_url_probe, param_str_probe
        else:
            # 再尝试自动方式
            portal_url_auto, param_str_auto, _ = probe_portal(session, probe_url, timeout)
            if is_valid_param_str(param_str_auto):
                portal_url, param_str = portal_url_auto, param_str_auto

    if not portal_url and portal_base_url:
        portal_url = urljoin(portal_base_url.rstrip("/") + "/", index_path.lstrip("/"))

    if not portal_url:
        return "", ""

    if is_valid_param_str(param_str):
        return portal_url, param_str

    # 最后尝试直接访问 portal 页面提取
    try:
        logger.debug("Fetching portal page directly: %s", portal_url)
        portal_resp = session.get(portal_url, timeout=timeout)
    except requests.RequestException:
        return portal_url, param_str

    html_param = extract_param_str_from_html(portal_resp.text)
    if is_valid_param_str(html_param):
        logger.debug("Found paramStr in portal HTML input field, length=%d", len(html_param))
        return portal_url, normalize_param_str(html_param)

    html_param = find_param_str_in_html(portal_resp.text)
    if html_param:
        logger.debug("Found paramStr in portal HTML URL pattern, length=%d", len(html_param))
    return portal_url, normalize_param_str(html_param)


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
    match = re.search(
        r'id="verifyCode_img"[^>]+src="([^"]+)"', html, re.IGNORECASE
    )
    if match:
        return match.group(1)
    match = re.search(r'createVerifycode[^"]*', html, re.IGNORECASE)
    return match.group(0) if match else ""


def refresh_captcha_url(src: str) -> str:
    if not src:
        return src
    token = f"random={time.time():.6f}"
    if "random=" in src:
        return re.sub(r"random=[^&]+", token, src)
    joiner = "&" if "?" in src else "?"
    return f"{src}{joiner}{token}"


def preprocess_captcha(image: Image.Image, threshold: int) -> Image.Image:
    grayscale = image.convert("L")
    binary = grayscale.point(lambda x: 0 if x < threshold else 255, "1")
    return binary


def solve_captcha(
    session: requests.Session,
    portal_url: str,
    html: str,
    timeout: int,
    captcha_config: dict,
) -> str:
    src = find_captcha_src(html)
    if not src:
        return ""
    captcha_url = urljoin(portal_url, refresh_captcha_url(src))
    try:
        response = session.get(captcha_url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException:
        return ""

    try:
        image = Image.open(BytesIO(response.content))
    except Exception:
        return ""

    threshold = int(captcha_config.get("threshold", 150))
    processed = preprocess_captcha(image, threshold)
    whitelist = captcha_config.get("whitelist", "")
    tesseract_config = "--psm 7"
    if whitelist:
        tesseract_config += f" -c tessedit_char_whitelist={whitelist}"
    text = pytesseract.image_to_string(processed, config=tesseract_config)
    cleaned = re.sub(r"[^0-9A-Za-z]", "", text)
    return cleaned.strip()


def build_login_payload(
    form: PortalForm,
    username: str,
    password: str,
    username_field: str,
    password_field: str,
    extra_fields: Dict[str, str],
    auto_province: bool,
    certify_rules: list[ProvinceRule],
    param_str: str,
) -> Dict[str, str]:
    data = dict(form.inputs)
    if "paramStr" in data:
        data["paramStr"] = normalize_param_str(data["paramStr"])
    if param_str:
        data["paramStr"] = param_str

    resolved_user_field = username_field if username_field in data else ""
    resolved_pass_field = password_field if password_field in data else ""
    if not resolved_user_field:
        resolved_user_field = guess_field(data, ("user", "account", "uid"))
    if not resolved_pass_field:
        resolved_pass_field = guess_field(data, ("pass", "pwd"))

    if resolved_user_field:
        data[resolved_user_field] = username
    if resolved_pass_field:
        data[resolved_pass_field] = password

    if "prov" not in data and data.get("defaultProv"):
        data["prov"] = data["defaultProv"]
    if "province" in data and not data["province"] and data.get("prov"):
        data["province"] = data["prov"]

    if auto_province and username:
        resolved = resolve_province_fields(username, certify_rules)
        if resolved:
            logger.debug(
                "Resolved province fields user=%s prov=%s province=%s",
                mask_value(username),
                resolved.get("prov", ""),
                resolved.get("province", ""),
            )
            for key, value in resolved.items():
                if value:
                    data[key] = value

    for key, value in extra_fields.items():
        if value:
            data[key] = value

    return data

def guess_field(fields: Dict[str, str], keywords: tuple[str, ...]) -> str:
    for name in fields:
        lowered = name.lower()
        if any(k in lowered for k in keywords):
            return name
    return ""


def submit_login_form(
    session: requests.Session,
    portal_url: str,
    html: str,
    username: str,
    password: str,
    username_field: str,
    password_field: str,
    extra_fields: Dict[str, str],
    login_url: str,
    auth_url: str,
    check_url: str,
    captcha_config: dict,
    auto_province: bool,
    certify_rules: list[ProvinceRule],
    debug_config: dict,
    param_str: str,
    param_str_source: str,
    timeout: int,
) -> SubmitResult:
    form = choose_form(html)
    if not form:
        logger.warning("No form found on portal page")
        return SubmitResult(
            success=False,
            attempts=0,
            last_status=None,
            last_url="",
            last_location="",
            error_hint="form_not_found",
            captcha_attempts=0,
            captcha_failures=0,
        )

    data = build_login_payload(
        form,
        username,
        password,
        username_field,
        password_field,
        extra_fields,
        auto_province,
        certify_rules,
        param_str,
    )

    action_url = auth_url or ""
    if not action_url:
        action_url = urljoin(portal_url, form.action) if form.action else ""
    if not action_url:
        action_url = login_url or portal_url

    captcha_enabled = bool(captcha_config.get("enabled", False))
    max_attempts = int(captcha_config.get("max_attempts", 1)) if captcha_enabled else 1
    min_len = int(captcha_config.get("min_length", 0))
    max_len = int(captcha_config.get("max_length", 0))

    result = SubmitResult(
        success=False,
        attempts=max_attempts,
        last_status=None,
        last_url="",
        last_location="",
        error_hint="",
        captcha_attempts=0,
        captcha_failures=0,
    )

    logger.debug(
        "Submitting login form method=%s url=%s fields=%s",
        form.method,
        action_url,
        ",".join(sorted(data.keys())),
    )
    if "paramStr" in data:
        logger.debug(
            "paramStr source=%s length=%s hash=%s",
            param_str_source or "unknown",
            len(data["paramStr"]),
            hash_param_str(data["paramStr"]),
        )

    for _ in range(max_attempts):
        if captcha_enabled:
            result.captcha_attempts += 1
            captcha_code = solve_captcha(session, portal_url, html, timeout, captcha_config)
            if not captcha_code:
                result.captcha_failures += 1
                logger.debug("Captcha OCR empty")
                continue
            if min_len and len(captcha_code) < min_len:
                result.captcha_failures += 1
                logger.debug("Captcha OCR too short length=%s", len(captcha_code))
                continue
            if max_len and len(captcha_code) > max_len:
                result.captcha_failures += 1
                logger.debug("Captcha OCR too long length=%s", len(captcha_code))
                continue
            data["verifycode"] = captcha_code

        try:
            headers = {
                "Origin": urlparse(portal_url).scheme + "://" + urlparse(portal_url).netloc,
                "Referer": portal_url,
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
            if form.method == "post":
                response = session.post(
                    action_url,
                    data=data,
                    timeout=timeout,
                    headers=headers,
                )
            else:
                response = session.get(
                    action_url,
                    params=data,
                    timeout=timeout,
                    headers=headers,
                )
        except requests.RequestException as exc:
            logger.debug("Login submit request failed: %s", exc)
            continue

        result.last_status = response.status_code
        result.last_url = response.url
        result.last_location = response.headers.get("Location", "")
        result.error_hint = extract_error_hint(response.text)

        if check_url and check_online(session, check_url, timeout):
            result.success = True
            return result

        if debug_config.get("save_response"):
            safe_text = sanitize_response(
                response.text,
                username,
                password,
            )
            save_response_snapshot(debug_config, safe_text)

    return result


def main() -> int:
    config = load_config()

    from config.logging_config import setup_logging

    setup_logging(LOG_DIR, log_level=config.get("log_level", "INFO"))

    ssid_target = config.get("ssid", "")
    device = get_wifi_device()
    if not device:
        logger.error("Wi-Fi device not found")
        return 2

    ssid = get_current_ssid(device)
    if ssid != ssid_target:
        logger.info("SSID mismatch: current=%s target=%s", ssid, ssid_target)
        return 0

    timeout = int(config.get("http", {}).get("timeout_seconds", 8))
    session = requests.Session()
    session.headers.update({"User-Agent": config.get("http", {}).get("user_agent", "")})

    if check_online(session, config.get("check_url", ""), timeout):
        logger.info("Already online")
        return 0

    cookies_config = config.get("cookies", {})
    if cookies_config.get("enabled"):
        for name, value in cookies_config.get("values", {}).items():
            if value:
                session.cookies.set(name, value)

    portal_url, param_str = discover_portal(
        session,
        config.get("check_url", ""),
        timeout,
        config.get("portal", {}).get("portal_base_url", ""),
        config.get("portal", {}).get("index_path", ""),
        config.get("portal", {}).get("probe_url", ""),
    )

    if not portal_url:
        logger.error("Portal URL not found")
        return 3

    try:
        portal_root_page = session.get(portal_url, timeout=timeout)
        frame_src = find_frame_src(portal_root_page.text)
        if frame_src:
            portal_url = urljoin(portal_url, frame_src)
            if not param_str:
                param_str = extract_param_str(portal_url)
    except requests.RequestException:
        logger.warning("Failed to load portal root page for frame parsing")

    parsed_portal = urlparse(portal_url)
    base_url = f"{parsed_portal.scheme}://{parsed_portal.netloc}"

    login_path = config.get("portal", {}).get("login_path", "")
    login_url = urljoin(base_url + "/", login_path.lstrip("/"))
    if param_str:
        login_url = f"{login_url}?paramStr={param_str}"

    login_config = config.get("login", {})
    login_mode = login_config.get("mode", "auto")
    auto_province = bool(login_config.get("auto_province", True))
    debug_config = config.get("debug", {})
    certify_rules: list[ProvinceRule] = []
    if auto_province:
        certify_path = load_certify_js_path(config)
        if certify_path:
            certify_rules = load_certify_rules(certify_path)
            if certify_rules:
                logger.info("Loaded certify rules from %s", certify_path)
            else:
                logger.warning("certify.js parsed no rules: %s", certify_path)
        else:
            logger.warning("certify.js not found; auto_province disabled")
            auto_province = False
    else:
        logger.info("auto_province disabled by config")

    form_result: Optional[SubmitResult] = None

    if login_mode in ("auto", "direct"):
        try:
            response = session.get(login_url, timeout=timeout)
            logger.info(
                "Attempted direct login status=%s location=%s",
                response.status_code,
                response.headers.get("Location", ""),
            )
        except requests.RequestException as exc:
            logger.warning("Direct login request failed: %s", exc)

    if login_mode in ("auto", "form"):
        try:
            portal_page = session.get(portal_url, timeout=timeout)
            form = choose_form(portal_page.text)
            param_source, resolved_param_str = resolve_param_str(
                portal_url,
                login_url,
                portal_page.text,
                param_str,
                form,
            )
            if not resolved_param_str or len(resolved_param_str.strip()) < 16:
                logger.warning(
                    "paramStr unresolved or too short source=%s length=%s",
                    param_source or "unknown",
                    len(resolved_param_str or ""),
                )
            form_result = submit_login_form(
                session,
                portal_url,
                portal_page.text,
                login_config.get("username", ""),
                login_config.get("password", ""),
                login_config.get("username_field", ""),
                login_config.get("password_field", ""),
                login_config.get("extra_fields", {}),
                login_url,
                urljoin(
                    base_url + "/",
                    config.get("portal", {}).get("auth_path", "/authServlet").lstrip("/"),
                ),
                config.get("check_url", ""),
                config.get("captcha", {}),
                auto_province,
                certify_rules,
                debug_config,
                resolved_param_str,
                param_source,
                timeout,
            )
            logger.info(
                "Attempted form login status=%s hint=%s",
                form_result.last_status,
                form_result.error_hint or "none",
            )
        except requests.RequestException as exc:
            logger.warning("Form login request failed: %s", exc)

    time.sleep(2)
    if check_online(session, config.get("check_url", ""), timeout):
        logger.info("Login success")
        return 0

    if form_result:
        logger.error(
            "Login failed status=%s location=%s hint=%s",
            form_result.last_status,
            form_result.last_location,
            form_result.error_hint or "none",
        )
    else:
        logger.error("Login failed")
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
