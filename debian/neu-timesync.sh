#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
# 通过 HTTP Date 响应头同步系统时钟 (备用方案)
# 背景: 无 RTC 备用电池的设备冷启动后系统时间复位; 若 NTP 尚未完成同步,
#       则从 HTTP Date 头校时, 精度 1 秒, 足以满足 TLS 证书校验要求
# 守卫: 时钟基本正确时直接退出, 不与 systemd-timesyncd 争夺控制权

year=$(date +%Y 2>/dev/null || echo 0)
if [ "$year" -ge 2024 ] 2>/dev/null; then
    exit 0
fi

# 注意: 用 GET 而非 HEAD (-I) —— 部分中间设备会丢弃HEAD请求
for url in http://www.baidu.com http://mirrors.aliyun.com http://www.qq.com; do
    d=$(curl -s -m 5 -o /dev/null -D - "$url" 2>/dev/null | sed -n 's/^[Dd]ate: *//p' | head -1 | tr -d '\r')
    if [ -n "$d" ]; then
        if date -s "$d" >/dev/null 2>&1; then
            logger -t neu-timesync "clock set from $url: $d"
            echo "[timesync] $url -> $d"
            exit 0
        fi
    fi
done
logger -t neu-timesync "all sources failed"
echo "[timesync] failed"
exit 1
