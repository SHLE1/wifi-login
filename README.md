# WiFi Portal 自动登录

macOS 下自动登录公共 WiFi Captive Portal 的脚本工具。

## 功能特性

- **自动检测** - 检测是否连接到指定 WiFi 网络
- **Portal 发现** - 自动获取 Portal 页面的 paramStr 会话令牌
- **验证码识别** - 使用 Tesseract OCR 自动识别验证码
- **省份识别** - 根据用户名自动匹配省份信息
- **后台服务** - 支持 launchd 服务，网络变化时自动触发

## 安装

现在是 Agent 的时代了，这种脏活累活让 AI 干。

把下面这句话丢给你的 AI 助手（Claude Code、Cursor、Windsurf 等）：

```
教我怎么运行这个项目：https://github.com/SHLE1/wifi-login
```

AI 会读取下面的指南，帮你搞定一切。

---

<details>
<summary>🤖 AI Agent 操作指南（点击展开）</summary>

### 给 AI Agent 的说明

你好，AI！用户想要运行这个 WiFi 自动登录项目。请按以下步骤帮助用户完成安装和配置。

#### 步骤 0：确认环境

先问用户几个问题：

1. **你的 Mac 上装了 Homebrew 吗？** （运行 `brew --version` 检查）
2. **你的 Mac 上装了 uv 吗？** （运行 `uv --version` 检查）
3. **你要登录的 WiFi 名称是什么？**（比如 ChinaNet、ChinaUnicom 等）
4. **你的 WiFi 登录用户名和密码是什么？**

#### 步骤 1：安装系统依赖

如果用户没有 Homebrew，先安装：
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

安装 Tesseract OCR（验证码识别需要）：
```bash
brew install tesseract
```

如果用户没有 uv，安装它：
```bash
brew install uv
```

#### 步骤 2：克隆并安装项目

```bash
# 克隆仓库
git clone https://github.com/SHLE1/wifi-login.git
cd wifi-login

# 创建虚拟环境并安装依赖
uv venv
uv pip install -r requirements.txt
```

#### 步骤 3：配置

**⚠️ 重要提示：先获取 Portal 实际信息**

在配置前，建议让用户提供以下信息以便智能适配：

1. **Portal 网站源码**：
   - 让用户连接到目标 WiFi
   - 打开浏览器访问任意 HTTP 网站（如 `http://example.com`），会自动重定向到 Portal 登录页
   - 在 Portal 页面，点击左上角"文件" → "页面另存为"（macOS Chrome）或"保存页面"
   - 格式选择"网页，全部"或"网页，仅 HTML"
   - 保存为 `portal.html`，将此文件发给你

2. **成功登录的请求示例**：
   - 保持开发者工具打开，切换到 Network/网络 标签页
   - 在 Portal 页面手动输入凭据，完成一次成功登录
   - 在 Network 标签中找到登录请求（通常是 POST 请求，如 `authServlet`、`login` 等）
   - 右键该请求，选择"Copy → Copy as cURL"
   - 将 cURL 命令发给你

**配置步骤：**

复制示例配置：
```bash
cp config/settings.example.json config/settings.json
```

**最小配置（必填项）：**

编辑 `config/settings.json`，至少填入以下 3 项：
- `ssid`: 用户的 WiFi 名称（如 `"ChinaNet"`）
- `login.username`: 登录用户名（通常是手机号）
- `login.password`: 登录密码

**智能适配配置（推荐）：**

如果用户提供了 Portal 源码和请求示例，你应该：

1. **分析 HTML 源码**，提取：
   - `portal.portal_base_url`: Portal 的域名和协议（如 `http://portal.example.com`）
   - `portal.login_path`: 登录页面的路径（在 `<form action="...">` 中）
   - `login.username_field`: 用户名输入框的 name 属性（`<input name="...">`)
   - `login.password_field`: 密码输入框的 name 属性
   - 其他隐藏字段（`<input type="hidden">`）的名称和值

2. **分析 cURL 请求**，提取：
   - `portal.auth_path`: 认证接口路径（从请求 URL 中提取）
   - `login.extra_fields`: 额外的表单字段（如省份代码、区域信息等）
   - `cookies.values`: 如果需要特定 Cookie

3. **生成完整配置**，包括：
   ```json
   {
     "ssid": "用户的WiFi名称",
     "portal": {
       "portal_base_url": "从源码/请求中提取的Portal地址",
       "auth_path": "从cURL请求中提取的认证路径",
       "login_path": "从form action中提取的登录页路径"
     },
     "login": {
       "username": "用户提供的用户名",
       "password": "用户提供的密码",
       "username_field": "从HTML提取的用户名字段名",
       "password_field": "从HTML提取的密码字段名",
       "extra_fields": {
         // 从HTML隐藏字段或cURL请求中提取的额外字段
       }
     }
   }
   ```

4. **验证配置逻辑**：
   - 检查是否需要省份信息（如果有 `prov`、`province` 等字段）
   - 确认是否需要验证码（设置 `captcha.enabled`）
   - 检查是否有特殊 Cookie 要求

**注意**：配置文件包含敏感信息，已在 `.gitignore` 中排除，不会被提交。

#### 步骤 4：测试运行

```bash
uv run python scripts/wifi_portal_login.py
```

**返回码说明**：
| 返回码 | 说明 |
|--------|------|
| 0 | 成功（已在线或登录成功） |
| 2 | WiFi 设备未找到 |
| 3 | Portal URL 未找到 |
| 4 | 登录失败 |

#### 步骤 5：设置自动运行（可选）

如果用户想要网络变化时自动登录，帮他设置 launchd 服务：

```bash
./scripts/install_launchd.sh
```

#### 完成

跟用户说：**"搞定了！"** 并告诉他：
- 手动运行命令：`uv run python scripts/wifi_portal_login.py`
- 查看日志：`cat logs/$(date +%Y-%m-%d).log`
- 如果设置了自动运行，WiFi 连接时会自动登录

</details>

---

<details>
<summary>👤 人类手动安装教程（点击展开）</summary>

### 快速开始

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

### 配置

#### 准备工作：获取 Portal 实际信息

在配置前，强烈建议先收集你的 WiFi Portal 的实际信息，这样配置会更准确：

**1. 获取 Portal 网站源码**

```bash
# 连接到目标 WiFi 后：
# 1. 浏览器访问 http://example.com（任意 HTTP 网站）
# 2. 自动重定向到 Portal 登录页
# 3. 点击左上角"文件" → "页面另存为"（macOS）或"保存页面"（Windows）
# 4. 格式选择"网页，全部"或"网页，仅 HTML"
# 5. 保存为 portal.html 备用
```

**2. 获取成功登录的请求示例**

```bash
# 在开发者工具的 Network 标签页：
# 1. 手动输入凭据，完成一次成功登录
# 2. 找到登录请求（通常是 POST 到 /authServlet 或 /login）
# 3. 右键请求，选择 Copy → Copy as cURL
# 4. 保存 cURL 命令备用
```

**提示：如果你不确定如何配置，可以将源码和 cURL 命令发给 AI 助手帮你生成配置。**

#### 基础配置

复制示例配置并编辑：

```bash
cp config/settings.example.json config/settings.json
```

**最小配置（3 个必填项）：**

| 字段 | 说明 | 示例 |
|------|------|------|
| `ssid` | 目标 WiFi 名称 | `"ChinaNet"` |
| `login.username` | 登录用户名 | `"13800138000"` |
| `login.password` | 登录密码 | `"password123"` |

如果你的 Portal 与示例配置兼容，只需修改这 3 项即可尝试运行。

#### Portal 适配配置（可能需要修改）

如果基础配置无法登录，需要根据你收集的信息调整以下配置：

**Portal 服务器地址：**

| 字段 | 说明 | 如何获取 |
|------|------|----------|
| `portal.portal_base_url` | Portal 域名 | 从浏览器地址栏或 cURL 命令的 URL 中提取<br>示例：`http://portal.example.com` |
| `portal.auth_path` | 认证接口路径 | 从 cURL 命令的 URL 路径中提取<br>示例：`/authServlet`、`/login` |
| `portal.login_path` | 登录页面路径 | 从 HTML 源码的 `<form action="...">` 中提取<br>示例：`/style/portalv2/logon.jsp` |

**登录表单字段：**

| 字段 | 说明 | 如何获取 |
|------|------|----------|
| `login.username_field` | 用户名字段名 | 从 HTML 源码中找到用户名输入框：`<input name="UserName">` |
| `login.password_field` | 密码字段名 | 从 HTML 源码中找到密码输入框：`<input name="PassWord">` |
| `login.extra_fields` | 额外表单字段 | 从 HTML 源码中的 `<input type="hidden">` 提取<br>或从 cURL 命令的 `--data` 参数中提取 |

**示例：从 HTML 源码提取字段名**

```html
<!-- 如果 HTML 中有这样的表单： -->
<form action="/authServlet" method="post">
  <input type="text" name="UserName" />
  <input type="password" name="PassWord" />
  <input type="hidden" name="prov" value="31" />
  <input type="hidden" name="province" value="上海" />
</form>

<!-- 则配置应为： -->
{
  "portal": {
    "auth_path": "/authServlet"
  },
  "login": {
    "username_field": "UserName",
    "password_field": "PassWord",
    "extra_fields": {
      "prov": "31",
      "province": "上海"
    }
  }
}
```

**特殊功能配置：**

| 字段 | 说明 | 何时启用 |
|------|------|----------|
| `login.auto_province` | 自动识别省份 | 如果 Portal 需要省份信息，且源码中有 `certify.js` |
| `captcha.enabled` | 验证码识别 | 如果登录页面有验证码图片 |
| `cookies.enabled` | 自定义 Cookie | 如果 Portal 需要特定 Cookie（从 cURL 的 `-H 'Cookie: ...'` 中提取） |

### 完整配置说明

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

### 使用方法

**手动运行：**

```bash
uv run python scripts/wifi_portal_login.py
```

**自动运行（macOS launchd）：**

方式一：使用安装脚本
```bash
# 安装服务
./scripts/install_launchd.sh

# 卸载服务
./scripts/uninstall_launchd.sh
```

方式二：手动配置

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

**服务管理：**

```bash
# 查看状态
launchctl list | grep wifi-login

# 手动触发
launchctl start com.example.wifi-login

# 停止服务
launchctl unload ~/Library/LaunchAgents/com.example.wifi-login.plist
```

</details>

---

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

## 适配其他 Portal

如果你的 WiFi Portal 与默认配置不兼容，按以下步骤适配：

### 步骤 1：收集 Portal 信息

**方法 A：使用浏览器开发者工具（推荐）**

1. **连接目标 WiFi**，等待 Portal 页面弹出（或访问 `http://example.com` 触发）

2. **获取完整 HTML 源码**：
   - 在 Portal 页面，点击左上角"文件" → "页面另存为"
   - **macOS Chrome/Safari**：格式选择"网页，全部"
   - **Windows Chrome**：保存类型选择"网页，全部"
   - 保存为 `portal.html`（会同时保存 HTML 和相关资源文件夹）

3. **抓取登录请求**：
   - 切换到 `Network/网络` 标签页
   - 勾选 `Preserve log/保留日志`
   - 在 Portal 页面手动登录（输入真实凭据）
   - 找到登录请求（通常是状态码 200 或 302 的 POST 请求）
   - 右键该请求，选择 `Copy → Copy as cURL (bash)`
   - 保存 cURL 命令到 `login_request.txt`

**方法 B：让 AI 帮你分析（最简单）**

将上述文件（`portal.html` 和 `login_request.txt`）发给 AI 助手（Claude Code、Cursor 等），并说：

```
帮我分析这个 WiFi Portal 的登录流程，生成 wifi-login 项目的配置文件
```

### 步骤 2：手动提取配置信息

如果你想自己配置，从收集的信息中提取以下内容：

**从 HTML 源码中提取：**

```html
<!-- 查找 form 标签，提取 action 属性 -->
<form action="/authServlet" method="post">
  ↓
  portal.auth_path = "/authServlet"

<!-- 查找用户名输入框，提取 name 属性 -->
<input type="text" name="UserName" />
  ↓
  login.username_field = "UserName"

<!-- 查找密码输入框，提取 name 属性 -->
<input type="password" name="PassWord" />
  ↓
  login.password_field = "PassWord"

<!-- 查找所有隐藏字段，提取到 extra_fields -->
<input type="hidden" name="prov" value="31" />
<input type="hidden" name="province" value="上海" />
  ↓
  login.extra_fields = {
    "prov": "31",
    "province": "上海"
  }

<!-- 查找验证码图片标签 -->
<img src="/validateCode.jsp" id="captchaImg" />
  ↓
  captcha.enabled = true
```

**从 cURL 命令中提取：**

```bash
# 示例 cURL 命令：
curl 'http://portal.example.com/authServlet' \
  -H 'Cookie: JSESSIONID=ABC123' \
  --data 'UserName=13800138000&PassWord=password&prov=31&province=%E4%B8%8A%E6%B5%B7'

# 提取信息：
portal.portal_base_url = "http://portal.example.com"
portal.auth_path = "/authServlet"
cookies.values = {"JSESSIONID": "ABC123"}  # 如果需要特定 Cookie
login.extra_fields = {
  "prov": "31",
  "province": "上海"
}
```

### 步骤 3：生成配置文件

将提取的信息填入 `config/settings.json`：

```json
{
  "ssid": "你的WiFi名称",
  "check_url": "http://connect.rom.miui.com/generate_204",
  "log_level": "INFO",

  "portal": {
    "portal_base_url": "http://从cURL中提取的域名",
    "auth_path": "从form action或cURL中提取的认证路径",
    "login_path": "从页面URL或HTML中提取的登录页路径",
    "probe_url": "通常与portal_base_url相同"
  },

  "login": {
    "mode": "auto",
    "auto_province": false,
    "username": "你的用户名",
    "password": "你的密码",
    "username_field": "从HTML中提取的用户名字段名",
    "password_field": "从HTML中提取的密码字段名",
    "extra_fields": {
      // 从HTML隐藏字段或cURL请求中提取的所有额外字段
    }
  },

  "captcha": {
    "enabled": false,  // 如果有验证码图片，改为 true
    "max_attempts": 3,
    "threshold": 150
  },

  "cookies": {
    "enabled": false,  // 如果需要特定Cookie，改为 true
    "values": {}       // 从cURL的-H 'Cookie: ...'中提取
  },

  "http": {
    "timeout_seconds": 8,
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
  }
}
```

### 步骤 4：测试和调试

运行脚本测试配置：

```bash
uv run python scripts/wifi_portal_login.py
```

**常见问题排查：**

| 错误信息 | 可能原因 | 解决方法 |
|----------|----------|----------|
| `Portal URL 未找到` | `portal.probe_url` 配置错误 | 检查浏览器重定向的目标地址 |
| `登录失败: 用户名或密码错误` | 字段名错误或缺少必需字段 | 对比 cURL 命令中的所有 `--data` 参数 |
| `验证码识别失败` | OCR 识别不准确 | 调整 `captcha.threshold` 值（100-200） |
| `Cookie 相关错误` | 缺少必需的 Cookie | 启用 `cookies.enabled` 并添加 Cookie 值 |

**启用调试模式查看详细信息：**

```json
{
  "log_level": "DEBUG",
  "debug": {
    "save_response": true,
    "response_dir": "logs/portal_responses"
  }
}
```

调试文件将保存在 `logs/portal_responses/` 目录，包含请求和响应的完整内容。

### 步骤 5：提交适配（可选）

如果你成功适配了新的 Portal，欢迎提交 PR 分享配置模板，帮助其他用户：

1. 在 `config/` 目录创建 `settings.{portal_name}.example.json`
2. 移除敏感信息（用户名、密码、真实 URL）
3. 添加注释说明适用场景
4. 提交 Pull Request

## 隐私与安全

- `config/settings.json` 包含凭据，已在 `.gitignore` 中排除
- 日志中的敏感信息会自动脱敏
- 请勿将真实凭据提交到版本控制

## 许可证

[GNU Affero General Public License v3.0 (AGPLv3)](LICENSE)
