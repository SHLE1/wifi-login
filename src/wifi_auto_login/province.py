import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .models import ProvinceRule


logger = logging.getLogger("wifi_portal_login")


def normalize_js_regex(value: str) -> str:
    return value.replace("\\\\", "\\")


def load_certify_js_path(certify_js_path: str, project_root: Path) -> Optional[Path]:
    if certify_js_path:
        path = Path(certify_js_path).expanduser()
        if path.is_file():
            return path
        logger.warning("Configured certify_js_path not found: %s", path)

    candidates = []
    for path in project_root.rglob("certify.js"):
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
    user_re = re.compile(r'^provs\[(\d+)\]\.username\.rule\[\d+\]\.exp="([^"]+)"')

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
            entry["patterns"].append(normalize_js_regex(user_match.group(2)))

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


def resolve_province_fields(username: str, rules: list[ProvinceRule]) -> dict[str, str]:
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
