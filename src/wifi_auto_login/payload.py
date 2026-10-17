import logging
from typing import Dict

from .config import LoginConfig
from .models import PortalForm, ProvinceRule
from .parsing import normalize_param_str
from .province import resolve_province_fields


logger = logging.getLogger("wifi_portal_login")


def mask_value(value: str, keep: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}***{value[-keep:]}"


def guess_field(fields: Dict[str, str], keywords: tuple[str, ...]) -> str:
    for name in fields:
        lowered = name.lower()
        if any(k in lowered for k in keywords):
            return name
    return ""


def build_login_payload(
    form: PortalForm,
    login: LoginConfig,
    param_str: str,
    auto_province: bool,
    certify_rules: list[ProvinceRule],
) -> Dict[str, str]:
    data = dict(form.inputs)
    if "paramStr" in data:
        data["paramStr"] = normalize_param_str(data["paramStr"])
    if param_str:
        data["paramStr"] = param_str

    resolved_user_field = login.username_field if login.username_field in data else ""
    resolved_pass_field = login.password_field if login.password_field in data else ""
    if not resolved_user_field:
        resolved_user_field = guess_field(data, ("user", "account", "uid"))
    if not resolved_pass_field:
        resolved_pass_field = guess_field(data, ("pass", "pwd"))

    if resolved_user_field:
        data[resolved_user_field] = login.username
    if resolved_pass_field:
        data[resolved_pass_field] = login.password

    if "prov" not in data and data.get("defaultProv"):
        data["prov"] = data["defaultProv"]
    if "province" in data and not data["province"] and data.get("prov"):
        data["province"] = data["prov"]

    if auto_province and login.username:
        resolved = resolve_province_fields(login.username, certify_rules)
        if resolved:
            logger.debug(
                "Resolved province fields user=%s prov=%s province=%s",
                mask_value(login.username),
                resolved.get("prov", ""),
                resolved.get("province", ""),
            )
            for key, value in resolved.items():
                if value:
                    data[key] = value

    for key, value in login.extra_fields.items():
        if value:
            data[key] = value

    return data
