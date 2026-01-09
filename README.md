# WiFi Portal 自动登录

macOS 下自动登录公共 WiFi Captive Portal 的脚本工具。

## 功能特性

- **自动检测** - 检测是否连接到指定 WiFi 网络
- **Portal 发现** - 自动获取 Portal 页面的 paramStr 会话令牌
- **验证码识别** - 使用 Tesseract OCR 自动识别验证码
- **省份识别** - 根据用户名自动匹配省份信息
- **后台服务** - 支持 launchd 服务，网络变化时自动触发

## 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/SHLE1/wifi-login.git
cd wifi-login

# 2. 安装依赖
uv venv && uv pip install -r requirements.txt

# 3. 安装 Tesseract OCR
brew install tesseract

# 4. 配置
cp config/settings.example.json config/settings.json
# 编辑 config/settings.json，填入你的凭据

# 5. 运行
uv run python scripts/wifi_portal_login.py
```

## 安装

### 依赖安装

**使用 [uv](https://github.com/astral-sh/uv)（推荐）：**

```bash
uv venv
uv pip install -r requirements.txt
```

**使用 pip：**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 系统依赖

```bash
# macOS
brew install tesseract
```

## 配置

### 基本配置

复制示例配置并编辑：

```bash
cp config/settings.example.json config/settings.json
```

主要配置项：

| 字段 | 说明 | 示例 |
|------|------|------|
| `ssid` | 目标 WiFi 名称 | `"ChinaNet"` |
| `login.username` | 登录用户名 | `"13800138000"` |
| `login.password` | 登录密码 | `"password123"` |

### 完整配置说明

<details>
<summary>点击展开完整配置项</summary>

| 字段 | 说明 | 默认值 |
|------|------|--------|
| `ssid` | 目标 WiFi 名称 | - |
| `check_url` | 网络检测 URL | `"http://connect.rom.miui.com/generate_204"` |
| `portal.portal_base_url` | Portal 服务器地址 | - |
| `portal.probe_url` | Portal 探测 URL | `"http://captive.apple.com"` |
| `portal.login_path` | 登录页面路径 | - |
| `portal.auth_path` | 认证接口路径 | `"/authServlet"` |
| `login.username` | 登录用户名 | - |
| `login.password` | 登录密码 | - |
| `login.mode` | 登录模式 | `"auto"` |
| `login.auto_province` | 自动识别省份 | `true` |
| `login.extra_fields` | 额外表单字段 | `{}` |
| `captcha.enabled` | 启用验证码识别 | `false` |
| `captcha.threshold` | 二值化阈值 | `150` |
| `captcha.max_attempts` | 最大尝试次数 | `3` |
| `http.timeout_seconds` | HTTP 超时时间 | `8` |
| `debug.save_response` | 保存响应快照 | `false` |
| `log_level` | 日志级别 | `"INFO"` |

</details>

## 使用方法

### 手动运行

```bash
uv run python scripts/wifi_portal_login.py
```

### 自动运行（macOS launchd）

**方式一：使用安装脚本**

```bash
# 安装服务
./scripts/install_launchd.sh

# 卸载服务
./scripts/uninstall_launchd.sh
```

**方式二：手动配置**

1. 编辑 `scripts/wifi_login_trigger.sh`，修改 `PROJECT_DIR` 为你的项目路径

2. 创建 launchd 配置文件 `~/Library/LaunchAgents/com.example.wifi-login.plist`：

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

### 服务管理

```bash
# 查看状态
launchctl list | grep wifi-login

# 手动触发
launchctl start com.example.wifi-login

# 停止服务
launchctl unload ~/Library/LaunchAgents/com.example.wifi-login.plist
```

## 项目结构

```
wifi-login/
├── config/
│   ├── settings.json          # 配置文件（含凭据，已 gitignore）
│   ├── settings.example.json  # 示例配置
│   └── logging_config.py      # 日志配置模块
├── scripts/
│   ├── wifi_portal_login.py   # 主登录脚本
│   ├── wifi_login_trigger.sh  # launchd 触发脚本
│   ├── install_launchd.sh     # 服务安装脚本
│   └── uninstall_launchd.sh   # 服务卸载脚本
├── logs/                      # 日志目录
├── data/                      # 数据目录
├── output/                    # 输出目录
├── requirements.txt           # Python 依赖
├── LICENSE                    # AGPLv3 许可证
└── README.md
```

## 技术实现

### 工作流程

```
检测 WiFi SSID → 检查在线状态 → 发现 Portal → 获取 paramStr → 提交登录 → 验证结果
```

### 核心技术

- **重定向跟踪** - 手动跟踪 HTTP 重定向链，捕获 Portal 的 paramStr 令牌
- **会话管理** - 优先使用表单中最新的 paramStr（与服务器会话匹配）
- **验证码 OCR** - 图像预处理（灰度化 + 二值化）+ Tesseract 识别
- **省份识别** - 解析 certify.js 规则，根据用户名自动匹配省份

### 返回码

| 返回码 | 说明 |
|--------|------|
| 0 | 成功（已在线或登录成功） |
| 2 | WiFi 设备未找到 |
| 3 | Portal URL 未找到 |
| 4 | 登录失败 |

## 适配其他 Portal

本项目针对中国电信 WLAN Portal 开发，如需适配其他运营商：

1. 使用浏览器开发者工具抓取 Portal 登录流程
2. 修改 `config/settings.json` 中的 URL 和字段名
3. 如有特殊登录逻辑，可能需要修改 `scripts/wifi_portal_login.py`

## 隐私与安全

- `config/settings.json` 包含凭据，已在 `.gitignore` 中排除
- 日志中的敏感信息会自动脱敏
- 请勿将真实凭据提交到版本控制

## 许可证

[GNU Affero General Public License v3.0 (AGPLv3)](LICENSE)
