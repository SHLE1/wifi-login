import subprocess
from typing import Optional


def run_cmd(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def run_shell(command: str) -> str:
    result = subprocess.run(
        ["/bin/zsh", "-lc", command], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def get_wifi_device() -> Optional[str]:
    shell_cmd = (
        "_get_wifi_ifname() {\n"
        "  if ! scutil <<< list |\n"
        "    awk -F/ '/Setup:.*AirPort$/{i=$(NF-1);exit} END {if(i) {print i} else {exit 1}}'; then\n"
        "    scutil <<< list | awk -F/ '/en[0-9]+/AirPort$/ {print $(NF-1);exit}'\n"
        "  fi\n"
        "}\n"
        "_get_wifi_ifname\n"
    )
    output = run_shell(shell_cmd)
    if output:
        return output

    output = run_cmd(["networksetup", "-listallhardwareports"])
    if not output:
        return None

    lines = output.splitlines()
    for idx, line in enumerate(lines):
        if "Hardware Port: Wi-Fi" in line or "Hardware Port: AirPort" in line:
            for j in range(idx + 1, min(idx + 4, len(lines))):
                if "Device:" in lines[j]:
                    return lines[j].split(":", 1)[1].strip()
    return None


def _ssid_from_corewlan() -> Optional[str]:
    """fastfetch 同款方案：读网络配置对象，不走受定位权限管控的 interface().ssid()。

    macOS 会把当前连接的网络排到 networkProfiles 最前面。
    """
    try:
        import CoreWLAN
    except ImportError:
        return None
    try:
        interface = CoreWLAN.CWWiFiClient.sharedWiFiClient().interface()
        profiles = interface.configuration().networkProfiles()
        if profiles and profiles.count():
            return profiles.firstObject().ssid()
    except Exception:
        return None
    return None


def _ssid_from_networksetup(device: str) -> Optional[str]:
    # 兜底（无 pyobjc 环境用）：macOS 15.6+ 将 SSID 视为位置信息，无定位权限的进程
    # 从 getairportnetwork / ipconfig / ioreg / CoreWLAN ssid() 拿到的全是 <redacted>。
    # 实测唯一可靠的方式：当前连接的网络会被排到“首选网络列表”最前面，取列表第 2 行
    # （第 1 行是 "Preferred networks on enX:" 表头）。此逻辑经过多轮实机验证。
    shell_cmd = (
        "en=\"$(networksetup -listallhardwareports | "
        "awk '/Wi-Fi|AirPort/{getline; print $NF}')\"; "
        "ipconfig getsummary \"$en\" | grep -Fxq \"  Active : FALSE\" || "
        "networksetup -listpreferredwirelessnetworks \"$en\" | "
        "sed -n '2s/^\\t//p'"
    )
    output = run_shell(shell_cmd)
    if output:
        return output

    shell_cmd = (
        f"networksetup -listpreferredwirelessnetworks \"{device}\" | "
        "awk 'NR==2 && sub(\"\\t\",\"\") { print; exit }'"
    )
    output = run_shell(shell_cmd)
    if output:
        return output

    output = run_cmd(["networksetup", "-getairportnetwork", device])
    if not output or "Current Wi-Fi Network" not in output:
        return None
    return output.split(":", 1)[1].strip()


def get_current_ssid(device: str) -> Optional[str]:
    ssid = _ssid_from_corewlan()
    if ssid:
        return ssid
    return _ssid_from_networksetup(device)
