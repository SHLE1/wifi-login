import logging
import sys
import time
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from . import logging_config
from .config import (
    AppConfig,
    ConfigError,
    HttpConfig,
    LOG_DIR,
    PROJECT_ROOT,
    load_config,
)
from .models import PortalPage, ProvinceRule, SubmitResult
from .network import check_online, discover_portal, has_portal_connectivity
from .parsing import choose_form, extract_param_str, find_frame_src, resolve_param_str
from .province import load_certify_js_path, load_certify_rules
from .submit import SubmitRequest, submit_login_form
from .system import get_current_ssid, get_wifi_device


logger = logging.getLogger("wifi_portal_login")


def build_login_url(portal_url: str, login_path: str, param_str: str) -> str:
    if not portal_url:
        return ""
    parsed_portal = urlparse(portal_url)
    if not parsed_portal.scheme or not parsed_portal.netloc:
        return ""
    base_url = f"{parsed_portal.scheme}://{parsed_portal.netloc}"
    login_url = urljoin(base_url + "/", login_path.lstrip("/"))
    if param_str:
        login_url = f"{login_url}?paramStr={param_str}"
    return login_url


def build_auth_url(portal_url: str, auth_path: str) -> str:
    parsed = urlparse(portal_url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urljoin(f"{parsed.scheme}://{parsed.netloc}" + "/", auth_path.lstrip("/"))


def build_session(http: HttpConfig) -> requests.Session:
    session = requests.Session()
    if http.user_agent:
        session.headers.update({"User-Agent": http.user_agent})
    return session


def fetch_text(session: requests.Session, url: str, timeout: int) -> str:
    try:
        return session.get(url, timeout=timeout).text
    except requests.RequestException as exc:
        logger.warning("Failed to fetch %s: %s", url, exc)
        return ""


def load_login_page(
    session: requests.Session,
    config: AppConfig,
    timeout: int,
) -> Optional[PortalPage]:
    """探测 Portal 落地页并解析 frame；同一 URL 只请求一次，HTML 复用。"""
    page = discover_portal(
        session,
        config.check_url,
        timeout,
        config.portal.portal_base_url,
        config.portal.index_path,
        config.portal.probe_url,
    )
    if not page.url:
        return None

    html = page.html or fetch_text(session, page.url, timeout)
    frame_src = find_frame_src(html)
    if not frame_src:
        return PortalPage(url=page.url, html=html, param_str=page.param_str)

    portal_url = urljoin(page.url, frame_src)
    return PortalPage(
        url=portal_url,
        html=fetch_text(session, portal_url, timeout),
        param_str=page.param_str or extract_param_str(portal_url),
    )


def load_province_rules(config: AppConfig) -> tuple[bool, list[ProvinceRule]]:
    if not config.login.auto_province:
        logger.info("auto_province disabled by config")
        return False, []
    certify_path = load_certify_js_path(config.portal.certify_js_path, PROJECT_ROOT)
    if not certify_path:
        logger.warning("certify.js not found; auto_province disabled")
        return False, []
    rules = load_certify_rules(certify_path)
    if not rules:
        logger.warning("certify.js parsed no rules: %s", certify_path)
        return False, []
    logger.info("Loaded certify rules from %s", certify_path)
    return True, rules


def attempt_direct_login(
    session: requests.Session,
    login_url: str,
    check_url: str,
    timeout: int,
) -> bool:
    try:
        response = session.get(login_url, timeout=timeout)
        logger.info(
            "Attempted direct login status=%s location=%s",
            response.status_code,
            response.headers.get("Location", ""),
        )
    except requests.RequestException as exc:
        logger.warning("Direct login request failed: %s", exc)
        return False
    return check_online(session, check_url, timeout)


def attempt_form_login(
    session: requests.Session,
    page: PortalPage,
    config: AppConfig,
    login_url: str,
    auth_url: str,
    timeout: int,
) -> SubmitResult:
    form = choose_form(page.html)
    param_source, resolved_param_str = resolve_param_str(
        page.url, login_url, page.html, page.param_str, form
    )
    if not resolved_param_str or len(resolved_param_str.strip()) < 16:
        logger.warning(
            "paramStr unresolved or too short source=%s length=%s",
            param_source or "unknown",
            len(resolved_param_str or ""),
        )
    auto_province, certify_rules = load_province_rules(config)
    request = SubmitRequest(
        portal_url=page.url,
        html=page.html,
        login=config.login,
        login_url=login_url,
        auth_url=auth_url,
        check_url=config.check_url,
        captcha=config.captcha,
        debug=config.debug,
        auto_province=auto_province,
        certify_rules=certify_rules,
        param_str=resolved_param_str,
        param_str_source=param_source,
        timeout=timeout,
    )
    result = submit_login_form(session, request)
    logger.info(
        "Attempted form login status=%s hint=%s",
        result.last_status,
        result.error_hint or "none",
    )
    return result


def main() -> int:
    try:
        config = load_config()
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    logging_config.setup_logging(LOG_DIR, log_level=config.log_level)

    device = get_wifi_device()
    if not device:
        logger.error("Wi-Fi device not found")
        return 2

    ssid = get_current_ssid(device)
    if ssid != config.ssid:
        logger.info("SSID mismatch: current=%s target=%s", ssid, config.ssid)
        return 0

    timeout = config.http.timeout_seconds
    session = build_session(config.http)

    if check_online(session, config.check_url, timeout):
        logger.info("Already online")
        return 0
    if not has_portal_connectivity(
        session, config.portal.portal_base_url, config.portal.probe_url, timeout
    ):
        logger.warning("Portal not reachable")
        return 3

    if config.cookies.enabled:
        for name, value in config.cookies.values.items():
            if value:
                session.cookies.set(name, value)

    page = load_login_page(session, config, timeout)
    if page is None:
        logger.error("Portal URL not found")
        return 3

    login_url = build_login_url(page.url, config.portal.login_path, page.param_str)
    if not login_url:
        logger.error("Invalid portal URL: %s", page.url)
        return 3
    auth_url = build_auth_url(page.url, config.portal.auth_path)

    # 直连登录：部分 Portal 直接带 paramStr GET 一次即可完成认证，成功则省掉整个表单流程
    if config.login.mode in ("auto", "direct"):
        if attempt_direct_login(session, login_url, config.check_url, timeout):
            logger.info("Login success")
            return 0

    form_result: Optional[SubmitResult] = None
    if config.login.mode in ("auto", "form"):
        form_result = attempt_form_login(session, page, config, login_url, auth_url, timeout)

    time.sleep(1)
    if check_online(session, config.check_url, timeout):
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
