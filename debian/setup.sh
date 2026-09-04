#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
# ============================================================
# NEU 校园网自动登录 - Linux 主机一键部署 (Debian 及兼容发行版)
# 适用: 任何具备无线/有线网络接口、使用 systemd + NetworkManager 的
#       Linux 主机 (Debian / Ubuntu / Raspberry Pi OS 等)
# 依赖: python3 + NetworkManager (主流发行版默认安装)
# 用法: sudo sh setup.sh
# ============================================================
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SRC="$SCRIPT_DIR/../neu_login.py"
DEST="/usr/local/bin/neu_login.py"

[ -f "$SRC" ] || SRC="$SCRIPT_DIR/neu_login.py"
[ -f "$SRC" ] || { echo "[!] 找不到 neu_login.py"; exit 1; }

echo "=== NEU 校园网自动登录部署 ==="

# 1. 安装脚本
install -m 755 "$SRC" "$DEST"
echo "[+] 脚本已安装: $DEST"

# 2. 配置NTP(系统时间错误会导致HTTPS证书校验失败;
#    ntp.neu.edu.cn 为校内服务, 认证前即可访问)
if [ -d /etc/systemd ]; then
    mkdir -p /etc/systemd/timesyncd.conf.d
    printf '[Time]\nNTP=ntp.neu.edu.cn\n' > /etc/systemd/timesyncd.conf.d/neu.conf
    timedatectl set-ntp true 2>/dev/null || true
    echo "[+] NTP已指向 ntp.neu.edu.cn (校内, 免认证可达)"
fi

# 3. 保存凭据
echo ""
echo "--- 输入统一身份认证凭据 (网页登录用的学号密码) ---"
printf "学号: "
read -r UNAME
printf "密码: "
read -r PWD_
python3 "$DEST" -u "$UNAME" -p "$PWD_" --save

# 4. 连接WiFi(开放网络) 并自动连接
# 注意: 不要显式设置 wifi-sec.key-mgmt none —— NetworkManager 会将 [wifi-security]
#       段解释为 WEP 并索要密钥, 导致激活失败 "Secrets were required, but not provided"
#       (实测 NM 1.52.1 / Debian 13); 纯开放网络的正确表示是 profile 中不存在该段。
#       因此先删除同名旧 profile 再重建: 旧版脚本写入的 key-mgmt none 无法通过 modify 修复
if command -v nmcli >/dev/null 2>&1; then
    echo ""
    printf "--- 要现在配置并连接 NEU-2.4G 吗? [Y/n] "
    read -r ANS
    case "$ANS" in
        n|N) ;;
        *)
            WLAN_IF=$(nmcli -t -f DEVICE,TYPE device status | grep ':wifi' | head -n1 | cut -d: -f1)
            if [ -n "$WLAN_IF" ]; then
                nmcli connection delete NEU-2.4G 2>/dev/null || true
                nmcli connection add type wifi ifname "$WLAN_IF" con-name NEU-2.4G ssid NEU-2.4G 2>/dev/null || true
                nmcli connection modify NEU-2.4G connection.autoconnect yes connection.autoconnect-priority 10
                nmcli connection up NEU-2.4G || echo "[!] 连接失败, 稍后可手动: nmcli connection up NEU-2.4G"
            else
                echo "[!] 未发现无线网卡 (检查: nmcli device; 内核日志: dmesg)"
            fi
            ;;
    esac
fi

# 5. 自动登录: 事件驱动(秒级) + 定时器巡检(每5分钟, 作为可靠性保障), 均无常驻进程
install -m 644 "$SCRIPT_DIR/neu-login-check.service" /etc/systemd/system/neu-login-check.service
install -m 644 "$SCRIPT_DIR/neu-login-check.timer" /etc/systemd/system/neu-login-check.timer
systemctl daemon-reload
systemctl enable --now neu-login-check.timer
echo "[+] 已启用定时巡检 (每5分钟, 无常驻进程)"

if [ -d /etc/NetworkManager/dispatcher.d ]; then
    install -m 755 "$SCRIPT_DIR/90-neu-login" /etc/NetworkManager/dispatcher.d/90-neu-login
    systemctl reload NetworkManager 2>/dev/null || systemctl restart NetworkManager 2>/dev/null || true
    echo "[+] 已安装事件驱动登录 (WiFi连接时秒级触发)"
fi

# 6. 立即登录测试
echo ""
echo "--- 登录测试 ---"
python3 "$DEST" || echo "[!] 登录未成功, 运行 python3 $DEST --test 排查"

echo ""
echo "=== 部署完成 ==="
echo "常用命令:"
echo "  python3 $DEST --status   查看在线状态"
echo "  python3 $DEST --logout   注销下线"
echo "  python3 $DEST --test     链路自检"
echo "  日志: journalctl -u neu-login-check -t neu-login"
