import json
from dataclasses import dataclass, field
from json import JSONDecodeError
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = PROJECT_ROOT / "config" / "settings.json"
LOG_DIR = PROJECT_ROOT / "logs"
REQUIRED_TOP_LEVEL_KEYS = ("ssid", "check_url", "portal", "login")
LOGIN_MODES = ("auto", "direct", "form")


class ConfigError(RuntimeError):
    pass


@dataclass
class HttpConfig:
    timeout_seconds: int = 8
    user_agent: str = ""


@dataclass
class PortalConfig:
    portal_base_url: str = ""
    auth_path: str = "/authServlet"
    login_path: str = ""
    index_path: str = ""
    probe_url: str = ""
    certify_js_path: str = ""


@dataclass
class LoginConfig:
    mode: str = "auto"
    auto_province: bool = False
    username: str = ""
    password: str = ""
    username_field: str = ""
    password_field: str = ""
    extra_fields: dict[str, str] = field(default_factory=dict)


@dataclass
class CaptchaConfig:
    enabled: bool = False
    max_attempts: int = 1
    min_length: int = 0
    max_length: int = 0
    threshold: int = 0
    whitelist: str = ""
    retry_delay: float = 0.3


@dataclass
class DebugConfig:
    save_response: bool = False
    response_dir: str = "logs/portal_responses"
    max_response_bytes: int = 32768


@dataclass
class CookiesConfig:
    enabled: bool = False
    values: dict[str, str] = field(default_factory=dict)


@dataclass
class AppConfig:
    ssid: str = ""
    check_url: str = ""
    log_level: str = "INFO"
    portal: PortalConfig = field(default_factory=PortalConfig)
    login: LoginConfig = field(default_factory=LoginConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    captcha: CaptchaConfig = field(default_factory=CaptchaConfig)
    debug: DebugConfig = field(default_factory=DebugConfig)
    cookies: CookiesConfig = field(default_factory=CookiesConfig)


def _as_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _as_dict(value, key: str) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"Config field '{key}' must be a JSON object")
    return value


def _section(raw: dict, key: str) -> dict:
    value = raw.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"Config field '{key}' must be a JSON object")
    return value


def _parse(raw: dict) -> AppConfig:
    portal_raw = _section(raw, "portal")
    login_raw = _section(raw, "login")
    http_raw = _section(raw, "http")
    captcha_raw = _section(raw, "captcha")
    debug_raw = _section(raw, "debug")
    cookies_raw = _section(raw, "cookies")

    mode = login_raw.get("mode", "auto")
    if mode not in LOGIN_MODES:
        raise ConfigError(f"Config field 'login.mode' must be one of: {', '.join(LOGIN_MODES)}")

    try:
        return AppConfig(
            ssid=raw.get("ssid", ""),
            check_url=raw.get("check_url", ""),
            log_level=raw.get("log_level", "INFO"),
            portal=PortalConfig(
                portal_base_url=portal_raw.get("portal_base_url", ""),
                auth_path=portal_raw.get("auth_path", "/authServlet"),
                login_path=portal_raw.get("login_path", ""),
                index_path=portal_raw.get("index_path", ""),
                probe_url=portal_raw.get("probe_url", ""),
                # legacy placement: also accepted under "login"
                certify_js_path=portal_raw.get("certify_js_path")
                or login_raw.get("certify_js_path")
                or "",
            ),
            login=LoginConfig(
                mode=mode,
                auto_province=_as_bool(login_raw.get("auto_province")),
                username=login_raw.get("username", ""),
                password=login_raw.get("password", ""),
                username_field=login_raw.get("username_field", ""),
                password_field=login_raw.get("password_field", ""),
                extra_fields=_as_dict(login_raw.get("extra_fields"), "login.extra_fields"),
            ),
            http=HttpConfig(
                timeout_seconds=int(http_raw.get("timeout_seconds", 8)),
                user_agent=http_raw.get("user_agent", ""),
            ),
            captcha=CaptchaConfig(
                enabled=_as_bool(captcha_raw.get("enabled")),
                max_attempts=int(captcha_raw.get("max_attempts", 1)),
                min_length=int(captcha_raw.get("min_length", 0)),
                max_length=int(captcha_raw.get("max_length", 0)),
                threshold=int(captcha_raw.get("threshold", 0)),
                whitelist=captcha_raw.get("whitelist", ""),
                retry_delay=float(captcha_raw.get("retry_delay", 0.3)),
            ),
            debug=DebugConfig(
                save_response=_as_bool(debug_raw.get("save_response")),
                response_dir=debug_raw.get("response_dir", "logs/portal_responses"),
                max_response_bytes=int(debug_raw.get("max_response_bytes", 32768)),
            ),
            cookies=CookiesConfig(
                enabled=_as_bool(cookies_raw.get("enabled")),
                values=_as_dict(cookies_raw.get("values"), "cookies.values"),
            ),
        )
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"Invalid config value: {exc}") from exc


def load_config(config_path: Path = CONFIG_PATH) -> AppConfig:
    try:
        with config_path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError as exc:
        raise ConfigError(
            f"Config file not found: {config_path}. Copy config/settings.example.json to config/settings.json first."
        ) from exc
    except JSONDecodeError as exc:
        raise ConfigError(
            f"Config file is not valid JSON: {config_path} (line {exc.lineno}, column {exc.colno})"
        ) from exc

    if not isinstance(raw, dict):
        raise ConfigError("Config root must be a JSON object")

    missing_keys = [key for key in REQUIRED_TOP_LEVEL_KEYS if key not in raw]
    if missing_keys:
        raise ConfigError(f"Config file missing required keys: {', '.join(missing_keys)}")

    return _parse(raw)
