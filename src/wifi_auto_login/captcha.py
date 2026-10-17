import io
import logging
import re
import time
from functools import lru_cache
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import requests
from PIL import Image

from .config import CaptchaConfig
from .parsing import find_captcha_src

if TYPE_CHECKING:
    import ddddocr

logger = logging.getLogger("wifi_portal_login")


def refresh_captcha_url(src: str) -> str:
    if not src:
        return src
    token = f"random={time.time():.6f}"
    if "random=" in src:
        return re.sub(r"random=[^&]+", token, src)
    joiner = "&" if "?" in src else "?"
    return f"{src}{joiner}{token}"


@lru_cache(maxsize=1)
def get_ocr_instance() -> "ddddocr.DdddOcr":
    # 延迟导入：未启用验证码时不加载 onnxruntime
    import ddddocr

    return ddddocr.DdddOcr(show_ad=False)


def filter_whitelist(text: str, whitelist: str) -> str:
    if not text:
        return ""
    if whitelist:
        return "".join(ch for ch in text if ch in whitelist)
    return re.sub(r"[^0-9A-Za-z]", "", text)


def binarize_image(image_bytes: bytes, threshold: int) -> bytes:
    """threshold > 0 时做灰度二值化去噪；0 表示关闭预处理。"""
    if threshold <= 0:
        return image_bytes
    image = Image.open(io.BytesIO(image_bytes)).convert("L")
    image = image.point(lambda p: 255 if p > threshold else 0)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def solve_captcha(
    session: requests.Session,
    portal_url: str,
    html: str,
    timeout: int,
    captcha: CaptchaConfig,
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
        ocr = get_ocr_instance()
        text = ocr.classification(binarize_image(response.content, captcha.threshold))
    except Exception as exc:
        logger.debug("OCR failed: %s", exc)
        return ""
    return filter_whitelist(text, captcha.whitelist).strip()
