from dataclasses import dataclass, field
from typing import Dict, Optional
import re


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


@dataclass
class PortalPage:
    """Portal 探测结果：最终落地页、页面 HTML（复用避免重复请求）与 paramStr。"""

    url: str
    html: str = ""
    param_str: str = ""
