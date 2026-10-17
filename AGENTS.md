# AGENTS.md

面向改代码的 AI 助手/维护者的工作须知。

文档分工：README.md 面向使用者（安装、配置、排障）；
本文件面向维护者（同步规则、脱敏要求、实现约束），不重复 README 的使用说明。

本仓库是 [SHLE1/wifi-auto-login](https://github.com/SHLE1/wifi-auto-login) 的**脱敏公开版**：
代码与主仓库保持一致，但不包含原作者的网络、运营商、地区、个人身份信息。

## 与主仓库的同步规则

每次主仓库更新后，把变更同步过来。同步范围 = 主仓库 git 管理的文件，但：

**不进镜像**（保留镜像自己的版本或直接排除）：

- `README.md`（镜像的公众版文档）、`LICENSE`（AGPLv3）
- `raycast-extension/`、`bin/raycast/`（个人工具链）
- `.github/`、`uv.lock`、`config/settings.json`
- `launchd/*.plist`、`bin/install-launchd.sh`、`bin/uninstall-launchd.sh`
  的文件名与 label 是镜像版独有的（`com.github.shle1.wifi-login`）

**脱敏要求**：主仓库的测试、脚本、示例配置中带有原作者的真实信息
（SSID、Portal 地址、省份码、手机号段模式、个人标识等）。
复制过来后，按**主仓库 `AGENTS.md` 里的「脱敏对照表」**逐项替换——
对照表的真实值只在主仓库记录，本仓库不出现。
替换完成后全文扫描，确认本仓库不含对照表中任何真实值。

## 常用命令

- 安装依赖：`uv sync`
- 跑测试：`cd tests && ../.venv/bin/python -m unittest discover`（纯 unittest，无 pytest 依赖）
- 手动运行：`uv run python -m wifi_auto_login.cli`
  （连着目标 SSID 时会真的发起登录；在其他 WiFi 上只走到 SSID mismatch 安全退出）

## 关键约束（改动前必读）

### SSID 获取（src/wifi_auto_login/system.py）

- macOS 15.6+ 把 SSID 当作位置信息：无「定位服务」权限的进程拿到的全是 `<redacted>`，
  `networksetup -getairportnetwork` 甚至会谎报未连接；macOS 26 起 root（`wdutil`）也拿不到
- 现行方案（均实机验证过，勿"顺手美化"）：
  1. CoreWLAN `interface().configuration().networkProfiles().firstObject().ssid()`
     （官方 API，无子进程）
  2. pyobjc 不可用时退回首选列表 hack：当前连接的网络会被排到 preferred 列表最前，取第 2 行
- `bin/wifi-login-trigger.sh` 里有同款 shell hack（`SSID_TARGET` 需用户自行修改）

### 依赖与部署

- 入口：`python -m wifi_auto_login.cli`、`scripts/wifi_portal_login.py`（兼容入口），
  `bin/` 下的 launchd 脚本——全部保持可用
- 新增依赖必须同时写进 `pyproject.toml` 和 `requirements.txt`，然后 `uv sync`
