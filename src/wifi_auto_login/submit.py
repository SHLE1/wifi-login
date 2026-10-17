import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from .captcha import solve_captcha
from .config import PROJECT_ROOT, CaptchaConfig, DebugConfig, LoginConfig
from .models import ProvinceRule, SubmitResult
from .network import check_online
from .parsing import choose_form, extract_error_hint, hash_param_str
from .payload import build_login_payload


logger = logging.getLogger("wifi_portal_login")


@dataclass
class SubmitRequest:
    """一次表单登录所需的全部上下文。"""

    portal_url: str
    html: str
    login: LoginConfig
    login_url: str
    auth_url: str
    check_url: str
    captcha: CaptchaConfig
    debug: DebugConfig
    auto_province: bool = False
    certify_rules: list[ProvinceRule] = field(default_factory=list)
    param_str: str = ""
    param_str_source: str = ""
    timeout: int = 8


def build_request_headers(portal_url: str) -> dict[str, str]:
    parsed = urlparse(portal_url)
    origin = ""
    if parsed.scheme and parsed.netloc:
        origin = f"{parsed.scheme}://{parsed.netloc}"
    return {
        "Origin": origin,
        "Referer": portal_url,
        "Accept-Language": "zh-CN,zh;q=0.9",
    }


def sanitize_response(text: str, username: str, password: str) -> str:
    if not text:
        return ""
    sanitized = text
    for label, value in (("UserName", username), ("PassWord", password)):
        if value:
            sanitized = sanitized.replace(value, f"{label}=***")
    sanitized = re.sub(r"(paramStr=)[^&\"\s>]+", r"\1***", sanitized)
    sanitized = re.sub(
        r'(<input[^>]+name="verifycode"[^>]+value=")[^"]*(")',
        r"\1***\2",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


def save_response_snapshot(debug: DebugConfig, text: str) -> None:
    if not text:
        return
    response_dir = Path(debug.response_dir)
    if not response_dir.is_absolute():
        response_dir = PROJECT_ROOT / response_dir
    response_dir.mkdir(parents=True, exist_ok=True)
    file_path = response_dir / f"response_{time.strftime('%Y%m%d_%H%M%S')}.html"
    file_path.write_bytes(text.encode("utf-8", errors="ignore")[: debug.max_response_bytes])
    logger.info("Saved response snapshot: %s", file_path)


def submit_login_form(session: requests.Session, request: SubmitRequest) -> SubmitResult:
    form = choose_form(request.html)
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
        request.login,
        request.param_str,
        request.auto_province,
        request.certify_rules,
    )

    action_url = (
        request.auth_url
        or (urljoin(request.portal_url, form.action) if form.action else "")
        or request.login_url
        or request.portal_url
    )

    captcha = request.captcha
    max_attempts = captcha.max_attempts if captcha.enabled else 1
    result = SubmitResult(
        success=False,
        attempts=0,
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
            request.param_str_source or "unknown",
            len(data["paramStr"]),
            hash_param_str(data["paramStr"]),
        )

    for attempt in range(max_attempts):
        if attempt > 0 and captcha.retry_delay > 0:
            time.sleep(captcha.retry_delay)

        if captcha.enabled:
            result.captcha_attempts += 1
            captcha_code = solve_captcha(
                session, request.portal_url, request.html, request.timeout, captcha
            )
            if not captcha_code:
                result.captcha_failures += 1
                logger.debug("Captcha OCR empty")
                continue
            if captcha.min_length and len(captcha_code) < captcha.min_length:
                result.captcha_failures += 1
                logger.debug("Captcha OCR too short length=%s", len(captcha_code))
                continue
            if captcha.max_length and len(captcha_code) > captcha.max_length:
                result.captcha_failures += 1
                logger.debug("Captcha OCR too long length=%s", len(captcha_code))
                continue
            data["verifycode"] = captcha_code

        result.attempts += 1
        try:
            headers = build_request_headers(request.portal_url)
            if form.method == "post":
                response = session.post(
                    action_url, data=data, timeout=request.timeout, headers=headers
                )
            else:
                response = session.get(
                    action_url, params=data, timeout=request.timeout, headers=headers
                )
        except requests.RequestException as exc:
            logger.debug("Login submit request failed: %s", exc)
            continue

        result.last_status = response.status_code
        result.last_url = response.url
        result.last_location = response.headers.get("Location", "")
        result.error_hint = extract_error_hint(response.text)

        if request.check_url and check_online(session, request.check_url, request.timeout):
            result.success = True
            return result

        if request.debug.save_response:
            save_response_snapshot(
                request.debug,
                sanitize_response(response.text, request.login.username, request.login.password),
            )

    # 所有验证码尝试均未产出可提交的请求：给出可诊断的 hint，而不是空值
    if result.attempts == 0 and result.captcha_attempts > 0 and not result.error_hint:
        result.error_hint = "captcha_failed"
        logger.debug(
            "Captcha never solved attempts=%s failures=%s",
            result.captcha_attempts,
            result.captcha_failures,
        )

    return result
