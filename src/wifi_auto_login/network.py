import logging
from typing import Tuple
from urllib.parse import urljoin

import requests

from .models import PortalPage
from .parsing import (
    extract_param_str,
    extract_param_str_from_html,
    find_param_str_in_html,
    hash_param_str,
    is_valid_param_str,
    normalize_param_str,
    select_best_param_str,
)


logger = logging.getLogger("wifi_portal_login")


def check_online(session: requests.Session, check_url: str, timeout: int) -> bool:
    try:
        response = session.get(check_url, allow_redirects=False, timeout=timeout)
    except requests.RequestException:
        return False
    # 正常的 connectivity check 返回 204/200 且不重定向；被 Portal 劫持时会 302 到登录页
    return response.status_code in (200, 204) and "Location" not in response.headers


def has_portal_connectivity(
    session: requests.Session,
    portal_base_url: str,
    probe_url: str,
    timeout: int,
) -> bool:
    for url in (portal_base_url, probe_url):
        if not url:
            continue
        try:
            response = session.get(url, allow_redirects=False, timeout=timeout)
        except requests.RequestException:
            continue
        if response.status_code < 500:
            return True
    return False


def resolve_portal_url(candidate: str, portal_base_url: str, index_path: str) -> str:
    if candidate:
        return candidate
    if portal_base_url:
        return urljoin(portal_base_url.rstrip("/") + "/", index_path.lstrip("/"))
    return ""


def probe_portal_manual(
    session: requests.Session,
    url: str,
    timeout: int,
    max_redirects: int = 10,
) -> Tuple[str, str, str, list[str]]:
    """单次请求 + 手动跟跳转，收集 redirect 链上所有 paramStr 候选。

    返回 (portal_url, param_str, html, chain)。
    """
    candidates: list[Tuple[str, str]] = []
    chain: list[str] = []
    html = ""
    current_url = url

    for step in range(max_redirects):
        try:
            resp = session.get(current_url, allow_redirects=False, timeout=timeout)
        except requests.RequestException as exc:
            logger.debug("Manual probe step %d failed: %s", step, exc)
            break

        chain.append(current_url)

        extracted = extract_param_str(current_url)
        if extracted:
            candidates.append((f"step_{step}_request_url", extracted))

        location = resp.headers.get("Location", "")
        if location:
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

        if resp.status_code in (301, 302, 303, 307, 308) and location:
            current_url = urljoin(current_url, location)
        else:
            html = resp.text
            html_param = extract_param_str_from_html(html)
            if html_param:
                candidates.append((f"step_{step}_html_input", html_param))
            url_param = find_param_str_in_html(html)
            if url_param:
                candidates.append((f"step_{step}_html_url", url_param))
            break

    if chain:
        logger.debug("Manual probe redirect chain (%d steps): %s", len(chain), " -> ".join(chain))
    source, param = select_best_param_str(candidates)
    if param:
        logger.debug(
            "Manual probe paramStr source=%s length=%s hash=%s",
            source,
            len(param),
            hash_param_str(param),
        )
    return current_url, normalize_param_str(param), html, chain


def discover_portal(
    session: requests.Session,
    check_url: str,
    timeout: int,
    portal_base_url: str,
    index_path: str,
    probe_url: str,
) -> PortalPage:
    """探测 Portal 落地页与 paramStr；同一 URL 只探测一次，HTML 供上层复用。"""
    portal_url = ""
    param_str = ""
    html = ""

    for url in (probe_url, check_url):
        if not url:
            continue
        logger.debug("Probing portal via: %s", url)
        probed_url, probed_param, probed_html, _chain = probe_portal_manual(session, url, timeout)
        if is_valid_param_str(probed_param):
            portal_url, param_str, html = probed_url, probed_param, probed_html
            break

    portal_url = resolve_portal_url(portal_url, portal_base_url, index_path)
    if not portal_url:
        return PortalPage(url="")

    if is_valid_param_str(param_str):
        return PortalPage(url=portal_url, html=html, param_str=param_str)

    try:
        logger.debug("Fetching portal page directly: %s", portal_url)
        html = session.get(portal_url, timeout=timeout).text
    except requests.RequestException:
        return PortalPage(url=portal_url)

    html_param = extract_param_str_from_html(html)
    if is_valid_param_str(html_param):
        logger.debug("Found paramStr in portal HTML input field, length=%d", len(html_param))
        return PortalPage(url=portal_url, html=html, param_str=normalize_param_str(html_param))

    html_param = find_param_str_in_html(html)
    if html_param:
        logger.debug("Found paramStr in portal HTML URL pattern, length=%d", len(html_param))
    return PortalPage(url=portal_url, html=html, param_str=normalize_param_str(html_param))
