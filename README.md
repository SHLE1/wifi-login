# WiFi Login

macOS 下自动登录**** WLAN Portal 的脚本。

## 功能

- 自动检测是否连接到指定 WiFi（如 ****）
- 自动获取 Portal 页面的 paramStr 会话令牌
- 自动识别验证码（使用 Tesseract OCR）
- 支持 launchd 服务，网络变化时自动触发

## 安装

### 1. 克隆仓库

```bash
git clone https://github.com/SHLE1/wifi-login.git
cd wifi-login
```

### 2. 安装依赖

使用 [uv](https://github.com/astral-sh/uv)（推荐，默认创建 `.venv`）：

```bash
uv venv
uv pip install -r requirements.txt
```

或使用 pip：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. 安装 Tesseract

```bash
brew install tesseract
```

### 4. 配置

复制示例配置并填入你的凭据：

```bash
cp config/settings.example.json config/settings.json
```

编辑 `config/settings.json`，填入：
- `username`: 你的WLAN 用户名
- `password`: 你的密码
- `ssid`: 目标 WiFi 名称

## 使用

### 手动运行

```bash
uv run python scripts/wifi_portal_login.py
```

### 隐私与脱敏提示

- 仓库内仅保留示例配置与占位符，真实账号/SSID/路径请放在本地文件中
- `config/settings.json` 含凭据（已在 `.gitignore`），不要提交或分享
- `scripts/wifi_login_trigger.sh` 与 launchd 配置文件使用占位符，需按本机路径与 SSID 替换

### 设置自动运行（macOS launchd）

1. 编辑 `scripts/wifi_login_trigger.sh`，修改 `PROJECT_DIR` 为你的项目路径

2. 创建 launchd plist 文件 `~/Library/LaunchAgents/com.example.wifi-login.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.wifi-login</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/wifi-login/scripts/wifi_login_trigger.sh</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>/Library/Preferences/SystemConfiguration</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
```

3. 加载服务：

```bash
launchctl load ~/Library/LaunchAgents/com.example.wifi-login.plist
```

4. 管理命令：

```bash
# 查看状态
launchctl list | grep wifi-login

# 手动触发
launchctl start com.example.wifi-login

# 停止服务
launchctl unload ~/Library/LaunchAgents/com.example.wifi-login.plist
```

## 配置说明

| 字段 | 说明 |
|------|------|
| `ssid` | 目标 WiFi 名称 |
| `portal.portal_base_url` | Portal 服务器地址 |
| `portal.probe_url` | 用于探测 Portal 的 URL |
| `login.username` | 登录用户名 |
| `login.password` | 登录密码 |
| `login.extra_fields` | 额外表单字段（如省份信息） |
| `captcha.enabled` | 是否启用验证码识别 |
| `captcha.threshold` | 验证码二值化阈值 |
| `debug.save_response` | 是否保存响应快照（调试用） |
| `log_level` | 日志级别（INFO/DEBUG） |

## 适配其他 Portal

本项目针对*** WLAN Portal 开发，如需适配其他运营商或地区：

1. 使用浏览器开发者工具抓取 Portal 登录流程
2. 修改 `config/settings.json` 中的 URL 和字段名
3. 如有特殊登录逻辑，可能需要修改 `scripts/wifi_portal_login.py`

## 项目结构

```
wifi-login/
├── config/
│   ├── settings.json          # 配置文件（包含凭据，已 gitignore）
│   ├── settings.example.json  # 示例配置
│   └── logging_config.py      # 日志配置
├── scripts/
│   ├── wifi_portal_login.py   # 主登录脚本
│   └── wifi_login_trigger.sh  # launchd 触发脚本
├── logs/                      # 日志目录
├── requirements.txt
└── README.md
```

## 技术说明

- 使用手动重定向跟踪捕获 Portal 的 paramStr 令牌
- 优先使用表单中最新的 paramStr（与服务器会话匹配）
- 支持验证码 OCR 自动识别
- 通过 WatchPaths 监听网络配置变化自动触发

## License

MIT
