# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
# ============================================================
# NEU 校园网自动登录 - ESP32 MicroPython 版
# 东北大学 NEU-2.4G/NEU (Srun深澜门户 + CAS统一身份认证RSA登录)
#
# 特性:
#   - 零依赖: 仅用 MicroPython 内置模块 (network/socket/ssl/binascii)
#   - 纯Python实现 RSA-2048 PKCS#1 v1.5 加密 (pow大整数运算, 无需加密库)
#   - 自带 HTTP 客户端: Cookie / chunked传输 / 302处理 / TLS(SNI)
#   - 安全(P0-3): TLS 默认强制校验证书链+主机名 (内置 CA_CERT_PEM), 校验失败
#     直接抛异常绝不静默降级; 仅显式 ALLOW_INSECURE_TLS=True 才关闭校验
#     (同时禁用公钥在线刷新, 防伪AP换钥窃取明文密码)
#   - 断线自动重连 + 周期巡检 + 幽灵会话自愈, 适合作为常驻认证设备独立运行
#   - 可库化集成: import 时不自动启动, 业务代码调用 ensure_online() 联网保障
#   - 同一文件可在 CPython 上直接运行测试 (python neu_login_esp32.py check)
#   - 兼容旧固件: int.bit_length/to_bytes/from_bytes 缺失时自动回退到纯 Python 实现
#   - 省内存: 响应体按 Content-Length 一次性预分配(避免增量扩容产生内存碎片),
#     不做 bytes() 二次拷贝, 巡检探测只读前几KB, 全程 gc.collect() 纪律
#
# 使用方式A 独立运行(作为常驻认证设备):
#   1. 修改下方 CONFIG 区填入学号密码
#   2. 上传到 ESP32 (ampy put / Thonny / mpremote), 命名为 main.py 开机自启
#   3. 板载LED: 亮=在线, 灭=掉线
#
# 使用方式B 作为库集成到自己的业务 main.py:
#   1. 本文件以任意模块名上传(如 neu_wifi.py), 不命名为 main.py
#   2. 在你的 main.py 中:
#        import neu_wifi as neu
#        neu.wifi_connect()                            # 或自行管理WiFi
#        ok, msg = neu.ensure_online("学号", "密码")    # 主循环安全点调用
#   3. 内存纪律: 登录瞬时堆占用大(TLS+RSA-2048), 业务代码务必在主循环里
#      顺序调用 ensure_online(), 勿与登录并发、勿在中断回调中调用;
#      业务较重的应用建议选带 PSRAM 的模组
#
# TLS 证书校验 (P0-3 安全修复, 默认开启):
#   - 默认用内置 CA_CERT_PEM (GlobalSign Root CA - R3 根证书 +
#     GlobalSign GCC R3 DV TLS CA 2020 中间证书) 校验证书链**与主机名**;
#     主机名校验依赖 wrap_socket(server_hostname=host) 的官方语义, 且
#     CERT_REQUIRED 要求设备时间正确(需 NTP / mpremote rtc --set)。
#     证书不匹配/主机名不符/链校验不可用 -> 直接失败, 绝不降级为不校验
#   - 注意: 两条 wrap 路径(SSLContext 与旧 ssl.wrap_socket)都必须传
#     server_hostname; 只有确实完成校验证书的连接才会置 _TLS_VERIFIED
#   - CA 更新 (校园网证书链轮换时): 重新抓取 pass.neu.edu.cn:443 证书链
#       openssl s_client -showcerts -connect pass.neu.edu.cn:443 </dev/null
#     输出依次为: 叶证书 -> 中间证书 -> 根证书; 只需把"中间证书"和
#     "根证书"两个 -----BEGIN CERTIFICATE----- 块按顺序替换文件中的
#     CA_CERT_PEM (MicroPython 单文件部署, CA 必须内联, 不能外挂文件)
#   - ALLOW_INSECURE_TLS (CONFIG 区): 默认 False = 强制校验。只有旧固件完全
#     不支持 cadata、且明确接受中间人风险时才可显式设为 True:
#       * 每次建立 TLS 连接都会打印 WARNING
#       * 同时完全禁用 login_neu.js 公钥在线刷新 (get_key(refresh=True) 抛错):
#         否则伪AP可先让 CAS POST 返回 500 触发 KEY_ROTATED, 再用伪造的
#         login_neu.js 换掉公钥, 从而拿到 RSA 加密前的明文密码
#       * 设为 True 后若服务端公钥真轮换, 登录会失败并提示手动更新 PUBKEY_B64
#   - SSO 白名单 (P0-4): 门户是明文 HTTP, CAS 跳转地址必须是
#     https://pass.neu.edu.cn, ticket 回跳必须是 ipgw.neu.edu.cn,
#     否则视为中间人直接中止(不发送 RSA 密文)
#
# 时间要求 (CERT_REQUIRED 前提, 无 RTC 设备必读):
#   ESP32 无电池 RTC, 断电后时钟复位为 2000 年 -> 证书校验因"尚未生效"直接失败。
#   run_forever() 开机自动校时, 顺序为:
#     1) HTTP Date: 认证前访问 HTTP_TIME_HOSTS(默认 ipgw.neu.edu.cn),
#        读响应头 Date 设 RTC —— 校园网认证前门户 HTTP 可达
#        (实测 ESP32-C3: 认证前 NTP UDP/123 会 ETIMEDOUT, HTTP Date 可用)
#     2) NTP: 上一步失败时用 NTP_HOST(ntp.neu.edu.cn) 兜底
#   库模式请先调用 ensure_time()/sync_time(); 设备端自检 (REPL):
#       import neulib as m
#       m.wifi_connect()
#       print(m.self_check())    # 检查: TLS模式/CA/时间/主机名校验/剩余堆
#   self_check() 会对 pass.neu.edu.cn 做两次真实握手: 正确域名应成功、
#   错误域名必须失败; 若返回 FAIL: hostname-not-verified 说明该固件
#   未校验主机名, 请勿使用(或改用证书指纹锁定方案)。
#
# 部署建议 (内存紧张设备, 如 ESP32-C3 / 无 PSRAM):
#   设备端现场编译本文件(~48KB 源码)会恶化堆碎片, 导致 mbedtls 在 TLS 握手
#   解析证书链时报 OSError(-10368, 'MBEDTLS_ERR_X509_ALLOC_FAILED')。
#   请用 tools/build_mpy.py 预编译成 .mpy 后上传(设备只加载字节码):
#       pip install mpy-cross==<与固件同版本>   # 设备 print(sys.version) 查看
#       python tools/build_mpy.py --mpy-cross <path>
#       mpremote cp dist/neu_login_esp32.mpy :neulib.mpy
#   实测: 同一块 ESP32-C3, .py 部署握手失败, .mpy 部署证书链+主机名校验正常。
#
# 合规: 仅供使用者本人账号的自动登录与个人学习研究使用,
#       禁止用于对校园网的任何攻击或滥用 (详见仓库 README 免责声明)
#
# 认证链路 (与浏览器流程一致):
#   GET ipgw/v1/srun_portal_sso -> CAS地址
#   ★ 给 service 参数追加 ac_id (浏览器登录流程的行为)
#     不带 ac_id 则只建 radius 记录、AC不放行 => "幽灵会话"
#     ac_id=AC(接入控制器)编号, 不同网段编号可能不同, 运行时从劫持URL自动检测
#   GET pass.neu.edu.cn/tpass/login -> lt令牌+JSESSIONID
#   POST rsa=RSA2048(学号+密码) & ul & pl & lt & execution & _eventId
#   302+ticket -> GET ipgw/v1/srun_portal_sso?ticket=...
#   GET ipgw/srun_portal_success?ac_id=16 -> 浏览器流程收尾, 完成AC放行
#   巡检: 在线状态 + 真实联网探测双校验, 幽灵会话自动注销重建
# ============================================================

import sys
import time
import gc
import json
import socket
import os
import ssl
import binascii

_IS_UPY = sys.implementation.name == "micropython"
__version__ = "1.2.0"

# ==================== CONFIG ====================
WIFI_SSID = "NEU-2.4G"      # 开放网络, 无需密码
USERNAME = ""               # 统一身份认证学号 (即网页登录使用的学号)
PASSWORD = ""               # 统一身份认证密码
AC_ID = 16                 # 默认AC编号; 实际运行时从劫持URL自动检测
CHECK_INTERVAL = 30         # 在线巡检间隔(秒)
LED_PIN = 2                 # 板载LED引脚, 不需要则设为 None
DEBUG = False               # 置 True 打印各步骤服务器原始响应(仅排查用); 正常运行保持 False
NTP_HOST = "ntp.neu.edu.cn" # NTP 校时服务器(校内); 注意校园网认证前 UDP/123 常被拦
NTP_TIMEOUT = 8             # NTP 超时(秒)
HTTP_TIME_HOSTS = ("ipgw.neu.edu.cn", "202.118.1.87")
                            # 认证前可达的 HTTP 校时源: 读响应 Date 头(优先于 NTP,
                            # 实测认证前 NTP UDP/123 会 ETIMEDOUT, 门户 HTTP 可达)
MIN_VALID_YEAR = 2024       # 设备时间早于该年份视为未对时(证书校验会失败)
HEARTBEAT_CHECKS = 4        # 每 N 次巡检(默认30s/次)打印一次心跳日志; 0=关闭
                            # (无人值守时用于确认主循环仍在运行)
AUTH_COOLDOWN_SEC = 1800    # A24: 凭据被拒后暂停 CAS 的时长(秒), 避免错误密码
                            # 每 30s 重试(约120次/小时)触发统一身份认证锁号/风控
LIMIT_COOLDOWN_SEC = 600    # A24: E2620(账号在线设备数超限)后暂停 CAS 的时长(秒)
MAX_BACKOFF = 1800          # A24: 暂时性失败指数退避上限(秒): 30→60→…→1800
ALLOW_INSECURE_TLS = False  # !安全开关! 默认False=强制校验证书; 仅调试/旧固件应急才可
                            # 显式设为布尔 True: 不校验链路, 每次建连打印警告, 且
                            # 同时禁用公钥在线刷新 (详见文件头 TLS 章节)
# ================================================

# ==================== TLS CA 证书 (校验证书链用) ====================
# 来源: pass.neu.edu.cn:443 真实证书链 (2026-10 抓取, 链路验证 Verify return code: 0)
#   叶证书 CN=*.neu.edu.cn -> GlobalSign GCC R3 DV TLS CA 2020 (中间证书)
#   -> GlobalSign Root CA - R3 (根证书)。下面内联 中间证书 + 根证书。
# 更新方法 (证书链轮换后):
#   openssl s_client -showcerts -connect pass.neu.edu.cn:443 </dev/null
#   把输出中"中间证书"和"根证书"两个块按原顺序替换下方常量即可。
# 注意: MicroPython 单文件部署, CA 必须内联, 不能外挂文件。
CA_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIEsDCCA5igAwIBAgIQd70OB0LV2enQSdd00CpvmjANBgkqhkiG9w0BAQsFADBM
MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xv
YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDA3MjgwMDAwMDBaFw0y
OTAzMTgwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
IG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIEdDQyBSMyBEViBUTFMgQ0EgMjAy
MDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKxnlJV/de+OpwyvCXAJ
IcxPCqkFPh1lttW2oljS3oUqPKq8qX6m7K0OVKaKG3GXi4CJ4fHVUgZYE6HRdjqj
hhnuHY6EBCBegcUFgPG0scB12Wi8BHm9zKjWxo3Y2bwhO8Fvr8R42pW0eINc6OTb
QXC0VWFCMVzpcqgz6X49KMZowAMFV6XqtItcG0cMS//9dOJs4oBlpuqX9INxMTGp
6EASAF9cnlAGy/RXkVS9nOLCCa7pCYV+WgDKLTF+OK2Vxw3RUJ/p8009lQeUARv2
UCcNNPCifYX1xIspvarkdjzLwzOdLahDdQbJON58zN4V+lMj0msg+c0KnywPIRp3
BMkCAwEAAaOCAYUwggGBMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEF
BQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUDZjA
c3+rvb3ZR0tJrQpKDKw+x3wwHwYDVR0jBBgwFoAUj/BLf6guRSSuTVD6Y5qL3uLd
G7wwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xv
YmFsc2lnbi5jb20vcm9vdHIzMDsGCCsGAQUFBzAChi9odHRwOi8vc2VjdXJlLmds
b2JhbHNpZ24uY29tL2NhY2VydC9yb290LXIzLmNydDA2BgNVHR8ELzAtMCugKaAn
hiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjMuY3JsMEcGA1UdIARA
MD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWdu
LmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAy8j/c550ea86oCkf
r2W+ptTCYe6iVzvo7H0V1vUEADJOWelTv07Obf+YkEatdN1Jg09ctgSNv2h+LMTk
KRZdAXmsE3N5ve+z1Oa9kuiu7284LjeS09zHJQB4DJJJkvtIbjL/ylMK1fbMHhAW
i0O194TWvH3XWZGXZ6ByxTUIv1+kAIql/Mt29PmKraTT5jrzcVzQ5A9jw16yysuR
XRrLODlkS1hyBjsfyTNZrmL1h117IFgntBA5SQNVl9ckedq5r4RSAU85jV8XK5UL
REjRZt2I6M9Po9QL7guFLu4sPFJpwR1sPJvubS2THeo7SxYoNDtdyBHs7euaGcMa
D/fayQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----
"""
# ================================================

DETECTED_AC_ID = None       # 运行时检测到的本网段AC编号 (见 detect_ac_id)
_COOLDOWN_UNTIL = None      # A24 认证冷却截止时刻(time.time()); None=无冷却
_COOLDOWN_KIND = None       # A24 冷却原因: "auth" / "limit"

PORTAL = "ipgw.neu.edu.cn"
CAS_JS_URL = "https://pass.neu.edu.cn/tpass/comm/neu/js/login_neu.js"
# 跳转白名单 (P0-4): 门户是明文 HTTP, 返回的 Redirect 必须校验后才能发送凭据
CAS_HOST = "pass.neu.edu.cn"

# RSA公钥 (内置默认值; 学校轮换密钥时在 TLS 校验生效的前提下自动在线更新,
# 不校验模式 ALLOW_INSECURE_TLS=True 下禁止在线更新, 只能手动改这里)
PUBKEY_B64 = ("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnjA28DLKXZzxbKmo9/1WkVLf1mr+wtL"
              "XLXt6sC4WiBCtsbzF5ewm7ARZeAdS3iZtqlYPn6IcUoOw42H8nAK/tfFcIb6dZ1K0atn0U39oWCGPz"
              "YuKtLJeMuNZiDXVuAXtojrckOjLW9B3gUnaNGLuIx0fYe66l0o9WjU2cGLNZQfiIxs2h00z1EA9I"
              "dSnVxiVQWSD+lsP3JZXh2TT287la4Y4603SQNKTK/QvXfcmccwTEd1IW6HwGxD6QrkInBiHisKW"
              "xmveN7UDSaQRZ/J97G0YC32pD38WT53izXeK0p/kU/X37VP555um1wVWFvPIuc9I7gMP1+hq5a+X"
              "6c++tQIDAQAB")

_MAX_BODY = 40000  # 单次响应体上限(CAS页19KB/JS 17KB, 留余量)

# ---------- CPython 兼容垫片(仅测试用, ESP32上不生效) ----------
if not _IS_UPY:
    class _SockShim:
        def __init__(self, s):
            self._s = s
        def connect(self, addr):
            self._s.connect(addr)
        def settimeout(self, t):
            self._s.settimeout(t)
        def write(self, data):
            self._s.sendall(data)
            return len(data)
        def read(self, n=1024):
            return self._s.recv(n)
        def readline(self):
            buf = bytearray()
            while True:
                c = self._s.recv(1)
                if not c:
                    break
                buf += c
                if c == b"\n":
                    break
            return bytes(buf)
        def close(self):
            try:
                self._s.close()
            except Exception:
                pass


# ---------- TLS 证书校验 (P0-3) ----------
# 证书链+主机名校验是否真正生效 (内部标志): get_key(refresh=True) 的门禁,
# 防止在未校验链路上拉取公钥被伪AP换钥。
# 主机名校验由 wrap_socket(server_hostname=host) 保证 (MicroPython 官方文档语义);
# CERT_REQUIRED 还要求设备时间正确(需 NTP / mpremote rtc --set)。
_TLS_VERIFIED = False

_TLS_ERR_HINT = ("请升级 MicroPython 固件或配置 CA (需要支持 SSLContext/"
                 "load_verify_locations(cadata=..) 或 ssl.wrap_socket(cadata=..))")


def _pem_ders(pem):
    """PEM 文本 -> DER 列表 (仅本地解析, 不联网; check 自检用)"""
    ders = []
    rest = pem
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    while True:
        i = rest.find(begin)
        if i < 0:
            break
        j = rest.find(end, i)
        if j < 0:
            break
        b64 = rest[i + len(begin):j].replace("\r", "").replace("\n", "")
        ders.append(binascii.a2b_base64(b64.encode()))
        rest = rest[j + len(end):]
    return ders


def _der_tlv(buf, i):
    """读一个 DER TLV: 返回 (tag, value_start, value_len, next_index)"""
    tag = buf[i]
    l, j = _der_len(buf, i + 1)
    return tag, j, l, j + l


def _der_subject_cn(der):
    """从 DER 证书中取 subject 的 CN (最小 ASN.1 遍历, 仅 check 排障用)"""
    try:
        _, pos, _, _ = _der_tlv(der, 0)            # Certificate -> tbsCertificate
        _, pos, _, _ = _der_tlv(der, pos)          # tbsCertificate -> 内部字段
        if der[pos] == 0xA0:                       # [0] version
            _, _, _, pos = _der_tlv(der, pos)
        for _ in range(4):                         # serial, sigalg, issuer, validity
            _, _, _, pos = _der_tlv(der, pos)
        _, si, sl, _ = _der_tlv(der, pos)          # subject Name (SEQUENCE)
        end = si + sl
        pos = si
        while pos < end:                           # RDN SET
            _, si, sl, pos = _der_tlv(der, pos)
            se = si + sl
            while si < se:
                _, ai, _, nxt = _der_tlv(der, si)      # AttributeTypeAndValue
                _, oi, ol, ai = _der_tlv(der, ai)      # OID
                oid = der[oi:oi + ol]
                _, vi, vl, _ = _der_tlv(der, ai)       # value
                if oid == b"\x55\x04\x03":             # 2.5.4.3 commonName
                    return bytes(der[vi:vi + vl]).decode()
                si = nxt
        return None
    except Exception:
        return None


def _ca_subjects():
    """CA_CERT_PEM 中各证书的 subject CN 列表 (check 自检/真机排障用, 不联网)"""
    out = []
    try:
        ders = _pem_ders(CA_CERT_PEM)
    except Exception:
        return out
    for der in ders:
        cn = _der_subject_cn(der)
        out.append(cn if cn else "?")
    return out


def _ca_loadable():
    """本地验证 CA_CERT_PEM 能被 ssl 解析 (不联网; 返回 bool)"""
    try:
        proto = getattr(ssl, "PROTOCOL_TLS_CLIENT", None)
        if proto is None or not hasattr(ssl, "SSLContext"):
            return False
        ctx = ssl.SSLContext(proto)
        ctx.load_verify_locations(cadata=CA_CERT_PEM)
        return True
    except Exception:
        return False


def _tls_mode():
    """当前 TLS 模式: 'verified' (默认强制校验) / 'INSECURE' (显式关闭校验)"""
    return "INSECURE" if ALLOW_INSECURE_TLS is True else "verified"


def _ssl_wrap_verified(sock, host):
    """校验证书链+主机名后建立 TLS; 任何失败都向上抛, 绝不降级为不校验

    主机名校验依赖 server_hostname: MicroPython 官方文档明确
    "server_hostname ... sets the hostname to check against the received
    server certificate" (同时用于 SNI), 因此所有 wrap 路径都必须传非空 host。
    CERT_REQUIRED 还要求设备时间正确(需 NTP / mpremote rtc --set)。
    """
    if not host:
        raise RuntimeError("TLS 校验缺少 server_hostname, 拒绝建立连接")
    err = None
    proto = getattr(ssl, "PROTOCOL_TLS_CLIENT", None)
    ctx = None
    if proto is not None and hasattr(ssl, "SSLContext"):
        try:
            ctx = ssl.SSLContext(proto)
            ctx.verify_mode = ssl.CERT_REQUIRED
            try:
                ctx.check_hostname = True
            except AttributeError:
                # MicroPython 的 SSLContext 没有该属性; 主机名由下面的
                # server_hostname 参数校验(官方文档语义), 因此不算降级。
                pass
            ctx.load_verify_locations(cadata=CA_CERT_PEM)
        except (AttributeError, TypeError, ValueError) as ex:
            # 该固件的 SSLContext 不支持 cadata/verify_mode: 改用旧 API
            # (旧 API 同样传 server_hostname + cadata, 仍是校验模式, 不是降级)
            err = ex
            ctx = None
    if ctx is not None:
        # 从这里开始(证书校验/握手)的任何异常必须向上抛, 不得回退重试
        try:
            return ctx.wrap_socket(sock, server_hostname=host)
        except TypeError as ex:
            # 仅 API 签名不兼容: 给出清晰升级提示 (仍是失败, 不降级不重试)
            raise RuntimeError("TLS 握手 API 不兼容: %s; %s" % (ex, _TLS_ERR_HINT))
    cr = getattr(ssl, "CERT_REQUIRED", None)
    if hasattr(ssl, "wrap_socket") and cr is not None:
        try:
            # 旧 API: server_hostname 同样用于主机名校验(MicroPython 文档)
            return ssl.wrap_socket(sock, cert_reqs=cr, cadata=CA_CERT_PEM,
                                   server_hostname=host)
        except TypeError as ex:
            err = ex
    raise RuntimeError("TLS 证书校验不可用: %s; %s" % (err, _TLS_ERR_HINT))


def _ssl_wrap_insecure(sock, host):
    """不校验证书建 TLS (仅供 ALLOW_INSECURE_TLS=True 的显式逃生阀使用)"""
    proto = getattr(ssl, "PROTOCOL_TLS_CLIENT", None)
    if proto is not None and hasattr(ssl, "SSLContext"):
        try:
            ctx = ssl.SSLContext(proto)
            try:
                ctx.check_hostname = False
            except Exception:
                pass
            try:
                ctx.verify_mode = getattr(ssl, "CERT_NONE", 0)
            except Exception:
                pass
            return ctx.wrap_socket(sock, server_hostname=host)
        except (AttributeError, TypeError, ValueError):
            pass
    try:
        return ssl.wrap_socket(sock, server_hostname=host)
    except TypeError:
        return ssl.wrap_socket(sock)


def _ssl_wrap(sock, host):
    """TLS 建连封装

    默认: 用内置 CA_CERT_PEM 强制校验证书链+主机名, 失败抛异常, 绝不降级。
    仅当 CONFIG 区 ALLOW_INSECURE_TLS 被显式设为布尔 True 时才不校验
    (每次建连打印警告), 此时 get_key(refresh=True) 被禁用。
    """
    global _TLS_VERIFIED
    _TLS_VERIFIED = False
    if ALLOW_INSECURE_TLS is True:
        print("[tls] WARNING: ALLOW_INSECURE_TLS=True, 不校验证书 (%s), "
              "链路可被中间人劫持; 公钥在线刷新已禁用" % host)
        return _ssl_wrap_insecure(sock, host)
    tls = _ssl_wrap_verified(sock, host)
    _TLS_VERIFIED = True
    return tls


def _open(host, port, use_ssl, timeout=12):
    addr = socket.getaddrinfo(host, port)[0][-1]
    s = socket.socket()
    s.settimeout(timeout)
    s.connect(addr)
    if use_ssl:
        s = _ssl_wrap(s, host)
    if not _IS_UPY:
        s = _SockShim(s)
    return s


# ==================== RSA (PKCS#1 v1.5) ====================

# ---- MicroPython int 方法兼容垫片 ----
# MicroPython 的 int 没有 bit_length; 较旧固件连 to_bytes/from_bytes 也没有

def _int_bytelen(x):
    """大整数占多少字节 (等价 (x.bit_length()+7)//8)"""
    k = 0
    while x:
        x >>= 8
        k += 1
    return k


def _int_to_bytes_py(x, k):
    out = bytearray(k)
    i = k - 1
    while x and i >= 0:
        out[i] = x & 0xFF
        x >>= 8
        i -= 1
    return bytes(out)


def _bytes_to_int_py(b):
    v = 0
    for x in b:
        v = (v << 8) | x
    return v


def _int_to_bytes(x, k):
    try:
        return x.to_bytes(k, "big")
    except (AttributeError, TypeError):
        return _int_to_bytes_py(x, k)


def _bytes_to_int(b):
    try:
        return int.from_bytes(b, "big")
    except (AttributeError, TypeError):
        return _bytes_to_int_py(b)


def _rand_nonzero():
    while True:
        try:
            b = os.urandom(1)[0]
        except Exception:
            import random
            b = random.getrandbits(8)
        if b:
            return b


def _der_len(der, i):
    b = der[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    v = 0
    for x in der[i:i + n]:
        v = (v << 8) | x
    return v, i + n


def parse_spki(b64key):
    """解析 SubjectPublicKeyInfo -> (n, e)"""
    der = binascii.a2b_base64(b64key)
    i = 0
    if der[i] != 0x30:
        raise ValueError("spki")
    _, i = _der_len(der, i + 1)
    if der[i] != 0x30:
        raise ValueError("algid")
    l, i = _der_len(der, i + 1)
    i += l
    if der[i] != 0x03:
        raise ValueError("bitstr")
    _, i = _der_len(der, i + 1)
    i += 1
    if der[i] != 0x30:
        raise ValueError("rsapub")
    _, i = _der_len(der, i + 1)
    if der[i] != 0x02:
        raise ValueError("n")
    l, i = _der_len(der, i + 1)
    n = _bytes_to_int(der[i:i + l])
    i += l
    if der[i] != 0x02:
        raise ValueError("e")
    l, i = _der_len(der, i + 1)
    e = _bytes_to_int(der[i:i + l])
    return n, e


def rsa_encrypt(n, e, data):
    """RSA ES-PKCS1-v1_5, 等价浏览器 JSEncrypt.encrypt()"""
    k = _int_bytelen(n)
    if len(data) > k - 11:
        raise ValueError("too long")
    ps = bytearray()
    while len(ps) < k - len(data) - 3:
        ps.append(_rand_nonzero())
    em = b"\x00\x02" + bytes(ps) + b"\x00" + data
    m = _bytes_to_int(em)
    return _int_to_bytes(pow(m, e, n), k)


def _b64enc(data):
    out = binascii.b2a_base64(data)
    if out.endswith(b"\n"):
        out = out[:-1]
    if out.endswith(b"\r"):
        out = out[:-1]
    return out.decode()


_KEY_CACHE = None


def get_key(client=None, refresh=False):
    """获取RSA公钥(n,e)

    默认: 返回内置 PUBKEY_B64 (解析后缓存), 不联网。
    refresh=True: 从 login_neu.js 在线拉取新公钥, 安全约束 (P0-3):
      - 仅当 TLS 证书校验真正生效 (_TLS_VERIFIED) 时才允许;
      - ALLOW_INSECURE_TLS=True (不校验链路) 时完全禁用, 防止伪AP换钥。
    """
    global _KEY_CACHE
    if not refresh and _KEY_CACHE:
        return _KEY_CACHE
    if refresh:
        if ALLOW_INSECURE_TLS is True:
            raise RuntimeError("公钥在线刷新已禁用: ALLOW_INSECURE_TLS=True 时 TLS "
                               "不校验证书, 攻击者可替换公钥; 请手动更新 PUBKEY_B64")
        if not _TLS_VERIFIED:
            raise RuntimeError("公钥在线刷新已禁用: 当前 TLS 未处于校验证书模式")
        if not client:
            raise RuntimeError("公钥在线刷新需要已建立的 HTTPClient")
        st, hs, data = client.request(CAS_JS_URL)
        i = data.find(b'publicKeyStr = "')
        if i < 0:
            raise RuntimeError("key not found in js")
        i += len('publicKeyStr = "')
        j = data.find(b'"', i)
        _KEY_CACHE = parse_spki(data[i:j].decode())
        return _KEY_CACHE
    _KEY_CACHE = parse_spki(PUBKEY_B64)
    return _KEY_CACHE


# ==================== HTTP 客户端 ====================

class HTTPClient:
    def __init__(self):
        # {host: {name: value}} 按域名隔离
        # 防止 CAS(pass.neu) 的 JSESSIONID Cookie 被发送至门户(ipgw)请求
        self.cookies = {}

    def _store_cookie(self, host, val):
        kv = val.split(";")[0]
        if "=" in kv:
            k, _, v = kv.partition("=")
            jar = self.cookies.get(host)
            if jar is None:
                jar = {}
                self.cookies[host] = jar
            jar[k.strip()] = v.strip()

    def request(self, url, method="GET", body=None, headers=None, timeout=12,
                max_body=_MAX_BODY):
        proto, _, rest = url.partition("://")
        proto = proto.lower()      # 必须归一化: 否则 "HTTPS://" 会被当明文 80 端口
        hp, _, path = rest.partition("/")
        path = "/" + path
        if ":" in hp:
            host, _, ports = hp.partition(":")
            port = int(ports)
        else:
            host = hp
            port = 443 if proto == "https" else 80

        gc.collect()
        sock = _open(host, port, proto == "https", timeout)

        hdrs = {"Host": host, "User-Agent": "ESP32-NEU-Login/1.1",
                "Accept": "*/*", "Connection": "close"}
        jar = self.cookies.get(host)
        if jar:
            ck = ""
            for k, v in jar.items():
                if ck:
                    ck += "; "
                ck += k + "=" + v
            hdrs["Cookie"] = ck
        if headers:
            hdrs.update(headers)
        if body is not None:
            if isinstance(body, str):
                body = body.encode()
            hdrs["Content-Length"] = str(len(body))

        req = method + " " + path + " HTTP/1.1\r\n"
        for k, v in hdrs.items():
            req += k + ": " + v + "\r\n"
        req += "\r\n"
        sock.write(req.encode())
        if body:
            sock.write(body)

        line = sock.readline()
        if not line:
            sock.close()
            raise OSError("no response")
        try:
            status = int(line.split()[1])
        except (ValueError, IndexError):
            status = 0

        hs = {}
        while True:
            line = sock.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            k, _, v = line.partition(b":")
            key = k.decode().strip().lower()
            val = v.decode().strip()
            if key == "set-cookie":
                self._store_cookie(host, val)
            hs[key] = val

        data = self._read_body(sock, hs, max_body)
        try:
            sock.close()
        except Exception:
            pass
        gc.collect()
        return status, hs, data

    def _read_body(self, sock, hs, max_body):
        """读响应体, 省内存策略:
        - 已知长度: 按上限一次性预分配, 逐块填入 (无增量扩容, 无整体拷贝)
        - 返回 bytearray 而非 bytes (find/decode/切片全兼容, 省一份拷贝)"""
        te = hs.get("transfer-encoding", "")
        if "chunked" in te:
            out = bytearray()
            while len(out) < max_body:
                line = sock.readline()
                if not line:
                    break
                try:
                    size = int(line.split(b";")[0].strip().decode(), 16)
                except (ValueError, UnicodeError):
                    break
                if size == 0:
                    break
                while size > 0:
                    chunk = sock.read(min(size, 4096))
                    if not chunk:
                        break
                    out += chunk
                    size -= len(chunk)
                sock.readline()  # chunk尾CRLF
            return out
        cl = hs.get("content-length")
        if cl:
            n = int(cl)
            if n > max_body:
                n = max_body
            out = bytearray(n)
            got = 0
            while got < n:
                chunk = sock.read(min(n - got, 4096))
                if not chunk:
                    break
                out[got:got + len(chunk)] = chunk
                got += len(chunk)
            return out if got == n else out[:got]
        out = bytearray()
        while len(out) < max_body:
            chunk = sock.read(min(max_body - len(out), 4096))
            if not chunk:
                break
            out += chunk
        return out


# ==================== 认证流程 ====================

_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"


def urlquote(s):
    out = ""
    for c in s:
        if c in _SAFE:
            out += c
        else:
            for b in c.encode("utf-8"):
                out += "%%%02X" % b
    return out


def urlunquote(s):
    out = bytearray()
    i = 0
    while i < len(s):
        if s[i] == "%":
            try:
                out.append(int(s[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out += s[i].encode()
        i += 1
    return out.decode()


def _dbg(msg):
    if DEBUG:
        print(msg)


def _cur_acid():
    return DETECTED_AC_ID or AC_ID


def _num_after(s, marker):
    i = s.find(marker)
    if i < 0:
        return None
    i += len(marker)
    j = i
    while j < len(s) and s[j].isdigit():
        j += 1
    return int(s[i:j]) if j > i else None


def detect_ac_id(client=None):
    """从AC劫持URL提取本网段真实AC编号 (ac_id)

    ac_id 是接入控制器(AC)编号, 不同网段可能由不同AC管辖。
    用错编号时: radius 建记录但真正的AC不执行放行 => 幽灵会话/verify-fail。
    劫持URL格式: ...location.href='http://202.118.1.87/index_<N>.html?...'
    门户前端同样从 URL 读取 acid
    """
    global DETECTED_AC_ID
    c = client or HTTPClient()
    try:
        st, hs, data = c.request("http://connect.rom.miui.com/generate_204",
                                  timeout=6, max_body=4096)
    except Exception:
        return None
    body = data.decode() if data else ""
    if st == 204 and not body:
        return DETECTED_AC_ID       # 在线无劫持, 保持原值
    # 劫持有两种形态: 302 跳转(标志在 location 头, body 为空) / 200 注入页(标志在 body)
    text = body + " " + hs.get("location", "")
    ac = _num_after(text, "ac_id=")
    if ac is None:
        ac = _num_after(text, "index_")
    if ac:
        DETECTED_AC_ID = ac
        i = text.find("wlanacname=")
        if i >= 0:
            j = text.find("&", i)
            acname = text[i + 11:j] if j >= 0 else text[i + 11:]
        else:
            acname = "?"
        _dbg("[dbg] 本网段AC编号=%d (AC:%s) 劫持URL已捕获" % (ac, acname))
        return ac
    return None


def check_online(client=None):
    c = client or HTTPClient()
    try:
        st, hs, data = c.request("http://" + PORTAL + "/cgi-bin/rad_user_info", timeout=6)
        s = data.decode() if data else ""
        _dbg("[dbg] rad_user_info HTTP %d body=%r" % (st, s[:60]))
        f = s.split(",")
        if s and not s.startswith(",") and "not_online" not in s and len(f) > 8:
            return f
    except Exception as ex:
        _dbg("[dbg] rad_user_info exc=%s" % ex)
    return None


def fix_service_url(redirect):
    """给 CAS service 参数追加 ac_id (复刻浏览器登录流程)
    不追加则只建 radius 记录、AC 不放行 => 幽灵会话"""
    tag = "service="
    i = redirect.rfind(tag)
    if i < 0:
        return redirect
    basic = redirect[:i + len(tag)]
    service = urlunquote(redirect[i + len(tag):])
    if not service or "ac_id=" in service:
        return redirect
    service += ("&" if "?" in service else "?") + "ac_id=%d" % _cur_acid()
    return basic + urlquote(service)


def _url_authority(u):
    """极简 URL 解析: 返回 (scheme, host, port, userinfo)

    MicroPython 自带模块里没有 urllib.parse, 这里只解析白名单校验需要的部分。
    格式非法时抛 ValueError(由调用方转成"疑似中间人"错误)。
    """
    i = u.find("://")
    if i <= 0:
        raise ValueError("missing-scheme")
    scheme = u[:i]          # 保持原样: 白名单要求严格小写, 避免大小写绕过
    rest = u[i + 3:]
    end = len(rest)
    for ch in ("/", "?", "#"):
        j = rest.find(ch)
        if 0 <= j < end:
            end = j
    authority = rest[:end]
    userinfo = ""
    if "@" in authority:
        userinfo, _, authority = authority.rpartition("@")
    port = None
    if authority.startswith("["):
        raise ValueError("ipv6-unsupported")
    if ":" in authority:
        h, _, ps = authority.rpartition(":")
        if not ps.isdigit():
            raise ValueError("bad-port")
        port = int(ps)
        authority = h
    if not authority:
        raise ValueError("empty-host")
    return scheme, authority.lower(), port, userinfo


def _validate_cas_redirect(redirect):
    """P0-4(ESP32): 明文 HTTP 门户返回的 Redirect 必须白名单校验后再发送凭据

    不校验时, 攻击者可把 CAS 登录引到自己域名, 拿到 RSA(学号+密码) 密文后
    转发给真实 CAS 换取 ticket, 以受害者账号建立会话(与 CPython 版同源问题)。
    """
    if not isinstance(redirect, str) or not redirect or len(redirect) > 4096:
        raise ValueError("SSO 重定向格式异常")
    try:
        scheme, host, port, userinfo = _url_authority(redirect)
    except ValueError as ex:
        raise ValueError("SSO 重定向地址格式非法(疑似中间人): %s" % ex)
    if scheme != "https" or host != CAS_HOST or port not in (None, 443) or userinfo:
        raise ValueError("SSO 重定向地址异常(疑似中间人), 已中止登录: " + redirect[:80])


def _validate_ticket_url(ticket_url):
    """CAS 认证成功后的回跳必须落在门户自己的域名上"""
    if not isinstance(ticket_url, str) or "ticket=" not in ticket_url:
        raise ValueError("CAS 回跳地址缺少 ticket")
    try:
        scheme, host, port, userinfo = _url_authority(ticket_url)
    except ValueError as ex:
        raise ValueError("CAS 回跳地址格式非法(疑似中间人): %s" % ex)
    scheme_ok = ((scheme == "http" and port in (None, 80))
                 or (scheme == "https" and port in (None, 443)))
    if not scheme_ok or host != PORTAL or userinfo:
        raise ValueError("CAS 回跳地址异常(疑似中间人): " + ticket_url[:80])


def probe_internet(client=None, timeout=8):
    """真实联网探测: 'ok' | 'hijacked' | 'unknown'
    幽灵会话 = 账面在线但 AC 未放行, HTTP 出网被劫持到认证门户
    只读响应前4KB: 劫持页都很小, 而百度真实首页200KB+, 读全文会撑爆内存"""
    c = client or HTTPClient()
    for url in ("http://connect.rom.miui.com/generate_204", "http://www.baidu.com/"):
        try:
            st, hs, data = c.request(url, timeout=timeout, max_body=4096)
        except Exception:
            continue
        loc = hs.get("location", "")
        body = data[:2000].decode() if data else ""
        if "202.118.1.87" in loc or "srun_portal" in loc or "neu.edu.cn" in loc:
            return "hijacked"
        if "top.self.location.href" in body or "202.118.1.87" in body:
            return "hijacked"
        if st == 204 or (st == 200 and "date" in hs):
            return "ok"
    return "unknown"


def logout(client=None, info=None):
    """注销当前会话 (幽灵会话重建 / 换设备时用)"""
    c = client or HTTPClient()
    if info is None:
        info = check_online(c)
    if not info:
        return "not-online"
    q = ("callback=srun&action=logout&ip=" + urlquote(info[8]) +
         "&username=" + urlquote(info[0]) +
         "&time=" + str(int(time.time() * 1000)) + "&ac_id=%d" % _cur_acid())
    try:
        st, hs, data = c.request("http://" + PORTAL + "/cgi-bin/srun_portal?" + q, timeout=8)
    except Exception as ex:
        return "logout-fail:" + str(ex)
    body = data.decode() if data else ""
    return "logged-out" if "ok" in body[:200] else "resp:" + body[:40]


def get_sso_redirect(c):
    try:
        st, hs, data = c.request("http://" + PORTAL + "/v1/srun_portal_sso?ac_id=%d&theme=pro" % _cur_acid())
        j = json.loads(data.decode())
        return j.get("Redirect")
    except Exception:
        return None


def _find_lt(html):
    tag = b'name="lt" value="'
    i = html.find(tag)
    if i < 0:
        return None
    i += len(tag)
    j = html.find(b'"', i)
    if j < 0:
        return None
    return html[i:j].decode()


def _find_error(html):
    """提取 CAS 错误提示 (id=errormsg 的 span, 如 '账号不存在！'/'密码错误')"""
    i = html.find(b'id="errormsg"')
    if i < 0:
        return None
    j = html.find(b">", i)
    k = html.find(b"<", j)
    if j < 0 or k < 0:
        return None
    msg = html[j + 1:k].decode().strip()
    return msg if msg else None


def cas_login(c, username, password, service_url, n, e):
    """CAS登录, 成功返回(ticket回调URL, None), 失败返回(None, 错误码)"""
    st, hs, data = c.request(service_url)
    lt = _find_lt(data)
    data = None  # 立即释放约19KB登录页缓冲, 为后续 POST 的 TLS 握手预留堆内存
    if not lt:
        return None, "no-lt(http %d)" % st

    cipher = _b64enc(rsa_encrypt(n, e, (username + password).encode()))
    form = ("rsa=" + urlquote(cipher) +
            "&ul=" + str(len(username)) +
            "&pl=" + str(len(password)) +
            "&lt=" + urlquote(lt) +
            "&execution=e1s1&_eventId=submit&t_un=&t_pd=&t_c=")
    st, hs, data = c.request(service_url, method="POST", body=form,
                             headers={"Content-Type": "application/x-www-form-urlencoded",
                                      "Referer": service_url})

    if st == 500:
        return None, "KEY_ROTATED"     # 服务端解密失败 => 公钥已轮换
    if st in (301, 302, 303, 307):
        loc = hs.get("location", "")
        if "ticket" in loc:
            try:
                _validate_ticket_url(loc)
            except ValueError as ex:
                return None, "bad-ticket-url: " + str(ex)
            return loc, None
        if "login" in loc or "logout" in loc:
            return None, "WRONG_CREDENTIAL"
        return None, "no-ticket"
    # 200 => 认证失败
    err = _find_error(data)
    if err:
        return None, "CAS: " + err
    return None, "WRONG_CREDENTIAL"


def complete_sso(c, ticket_url):
    """第三步: 携带 ticket 回门户校验, 并访问成功页完成 AC 放行

    返回 (kind, msg): kind ∈ {"ok","limit","transient","auth"}。
    - "limit"     : 门户响应含 E2620 = 账号在线设备数超限 (A24: 必须停止重试)
    - "auth"      : ticket 回跳地址非法 = 安全中止(疑似中间人), 不写凭据冷却
    - "transient" : 门户校验网络异常/非 2xx (不致命, 由后续在线验证判定)
    - "ok"        : 成功页收尾失败不致命, 仍返回 ok (与原语义一致)
    """
    try:
        _validate_ticket_url(ticket_url)      # P0-4: 回跳地址白名单
    except ValueError as ex:
        _dbg("[dbg] ticket reject: %s" % ex)
        return "auth", "ticket-reject:" + str(ex)
    i = ticket_url.find("?")
    q = ticket_url[i + 1:] if i >= 0 else ""
    kind = "ok"
    msg = ""
    data = None
    st = 0
    try:
        st, hs, data = c.request("http://" + PORTAL + "/v1/srun_portal_sso?" + q)
    except Exception as ex:
        _dbg("[dbg] sso-validate exc=%s" % ex)
        kind = "transient"
        msg = "sso-validate-exc:" + str(ex)
    if data and data.find(b"E2620") >= 0:
        # A24: 设备数超限 => 上层写 LIMIT_COOLDOWN_SEC 冷却, 期间不再请求 SSO
        kind = "limit"
        msg = "E2620: 账号在线设备数超限"
    elif kind == "ok" and st >= 400:
        kind = "transient"
        msg = "sso-validate HTTP %d" % st
    if DEBUG:
        try:
            body = data[:200].decode() if data else ""
        except Exception:
            body = ""
        _dbg("[dbg] sso-validate HTTP %d %s" % (st, body))
    # 浏览器流程收尾: 认证成功后跳 srun_portal_success, 完成 AC 放行
    try:
        c.request("http://" + PORTAL + "/srun_portal_success?ac_id=%d" % _cur_acid())
    except Exception:
        pass
    return kind, msg


# ---------- A24: 认证失败分类 / 冷却 / 指数退避 ----------
# 背景: 原实现里错误密码每 CHECK_INTERVAL(30s) 就重试一次 CAS(约120次/小时),
# 极易触发统一身份认证的锁号/风控。现在失败按 kind 分类: 凭据类写入冷却
# (冷却期内 _login_impl 开头直接返回, 零网络请求), 暂时性失败指数退避,
# 登录成功立即清除冷却。

def _now():
    """当前时间戳(秒, 仅冷却计算用); 时钟异常时退化为 0, 保证永不抛"""
    try:
        return time.time()
    except Exception:
        return 0


def _cooldown_remaining():
    """冷却剩余秒数; 0=不在冷却期 (只读, 无副作用)"""
    if _COOLDOWN_UNTIL is None:
        return 0
    left = _COOLDOWN_UNTIL - _now()
    return left if left > 0 else 0


def _set_cooldown(kind, secs):
    """开启认证冷却: 冷却期内 _login_impl 直接返回, 不发起任何 CAS 请求"""
    global _COOLDOWN_UNTIL, _COOLDOWN_KIND
    _COOLDOWN_UNTIL = _now() + secs
    _COOLDOWN_KIND = kind


def _clear_cooldown():
    """清除认证冷却 (登录成功时调用; 测试也用它复位)"""
    global _COOLDOWN_UNTIL, _COOLDOWN_KIND
    _COOLDOWN_UNTIL = None
    _COOLDOWN_KIND = None


def _next_backoff(cur):
    """暂时性失败的下一轮等待秒数 (纯函数, 便于测试): 30→60→…→MAX_BACKOFF"""
    nxt = cur * 2
    if nxt < CHECK_INTERVAL:
        nxt = CHECK_INTERVAL
    if nxt > MAX_BACKOFF:
        nxt = MAX_BACKOFF
    return nxt


def _fail_kind(err):
    """失败信息 -> kind (纯函数, 便于测试)

    auth     : CAS 明确拒绝凭据 (WRONG_CREDENTIAL / "CAS: ..." 错误页),
               或 sso-reject 安全中止 (疑似中间人, 不写凭据冷却)
    limit    : E2620 账号在线设备数超限 (complete_sso 返回 "limit:")
    config   : KEY_ROTATED 且无法自动恢复 (需人工更新 PUBKEY_B64)
    transient: 其余网络/流程暂时性失败 (no-lt/no-redirect/no-ticket/
               time-invalid/verify-fail/网络异常等), 指数退避后重试
    """
    if not err:
        return "transient"
    if err == "WRONG_CREDENTIAL" or err[:5] == "CAS: ":
        return "auth"
    if err[:10] == "sso-reject":
        return "auth"
    if err[:6] == "limit:":
        return "limit"
    if err == "KEY_ROTATED" or err[:11] == "key-rotated":
        return "config"
    return "transient"


def _login_impl(username, password):
    """登录实现 (公共 API 内部使用), 返回 (ok, msg, kind)

    kind ∈ {"ok","auth","limit","config","transient"} (见 _fail_kind)。
    A24: 冷却期内直接返回 ("cooldown:<kind>"), 不发起任何网络请求 —— 尤其
    绝不提交 CAS 凭据, 从根上避免错误密码高频重试导致账号被锁。
    """
    left = _cooldown_remaining()
    if left > 0:
        k = _COOLDOWN_KIND or "auth"
        return False, "cooldown:" + k, k

    c = HTTPClient()
    info = check_online(c)
    if info:
        # 双重校验: 账面在线但流量被劫持 => 幽灵会话, 注销重建
        probe = probe_internet(c)
        if probe == "ok":
            _clear_cooldown()
            return True, "online:" + info[0] + "@" + info[8], "ok"
        if probe == "hijacked":
            print("[login] ghost session, rebuild")
            try:
                logout(c, info)
            except Exception:
                pass
        else:
            _clear_cooldown()
            return True, "online:" + info[0] + "@" + info[8] + " probe-unknown", "ok"

    # 关键: 检测本网段真实AC编号 (不同网段由不同AC管辖, 编号错则放行失败)
    detect_ac_id(c)

    redirect = get_sso_redirect(c)
    if not redirect:
        return False, "no-redirect", "transient"
    try:
        _validate_cas_redirect(redirect)      # P0-4: 明文 HTTP 返回的地址先过白名单
        redirect = fix_service_url(redirect)
        _validate_cas_redirect(redirect)
    except ValueError as ex:
        # 安全中止: 未发送任何凭据, 归为 auth 以便提示"疑似中间人", 但不写
        # 凭据冷却(换网/重启后应允许立即重试)
        return False, "sso-reject:" + str(ex), "auth"

    n, e = get_key()
    # 证书校验前提: 设备时间必须正确, 否则 CAS 的 TLS 握手必然失败
    # (ESP32 无电池 RTC, 断电重启后需先 NTP 校时)
    if _tls_mode() == "verified" and not time_ok():
        tok, tmsg = ensure_time()
        if not tok:
            return False, ("time-invalid: 设备时间不可用于 TLS 证书校验, "
                           "请先 NTP 校时或 mpremote rtc --set (%s)" % tmsg), "transient"
    ticket_url, err = cas_login(c, username, password, redirect, n, e)
    if err == "KEY_ROTATED":
        # 服务端解密失败 => 公钥可能已轮换; 仅校验证书链路允许在线刷新
        if ALLOW_INSECURE_TLS is True:
            return False, "key-rotated: 需手动更新内置 PUBKEY_B64 (不校验模式下在线刷新已禁用)", "config"
        try:
            n, e = get_key(c, refresh=True)
            ticket_url, err = cas_login(c, username, password, redirect, n, e)
        except Exception as ex:
            return False, "key-refresh-fail:" + str(ex), "transient"
    if not ticket_url:
        err = err or "cas-fail"
        kind = _fail_kind(err)
        if kind == "auth":
            # A24: 凭据被拒 -> 冷却 AUTH_COOLDOWN_SEC; 冷却期内零 CAS 请求
            _set_cooldown("auth", AUTH_COOLDOWN_SEC)
        return False, err, kind
    _dbg("[dbg] ticket %s" % ticket_url[:80])

    sso_kind, sso_msg = complete_sso(c, ticket_url)
    if sso_kind == "limit":
        # A24: E2620 设备数超限 -> 冷却 LIMIT_COOLDOWN_SEC (PC端踢闲置设备)
        _set_cooldown("limit", LIMIT_COOLDOWN_SEC)
        return False, "limit: " + sso_msg, "limit"
    if sso_kind == "auth":
        return False, "sso-reject:" + sso_msg, "auth"
    # transient: 门户校验失败不致命, 继续在线轮询判定 (与原语义一致)

    # 网关放行可能延迟, 轮询: 在线状态 + 真实联网双确认
    for _ in range(5):
        info = check_online(c)
        if info:
            probe = probe_internet(c)
            if probe == "hijacked":
                return False, "ghost-after-login", "transient"
            _clear_cooldown()
            return True, "login-ok:" + info[0] + "@" + info[8], "ok"
        time.sleep(2)
    return False, "verify-fail", "transient"


def login(username, password):
    """登录 (公共 API): 返回 (ok, msg), 签名与返回结构保持不变

    A24: 失败分类/冷却/退避由 _login_impl 内部处理; 凭据被拒后会进入冷却,
    冷却期内再次调用直接返回 (False, "cooldown:auth"), 不发起 CAS 请求。
    """
    ok, msg, _kind = _login_impl(username, password)
    return ok, msg


# ==================== 设备时间 (CERT_REQUIRED 前提) ====================
# ESP32 无电池 RTC: 断电后时钟复位为 2000 年, 而 CERT_REQUIRED 会因
# "证书尚未生效" 直接失败。因此开机必须先 NTP 校时, 否则自动登录不可用。

def _time_year():
    try:
        return time.localtime()[0]
    except Exception:
        return 0


def time_ok():
    """设备时间是否可用于证书校验 (年份在合理区间)"""
    y = _time_year()
    return MIN_VALID_YEAR <= y <= 2099


_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def _days_from_civil(y, m, d):
    """公历日期 -> 自 1970-01-01 起的天数 (Howard Hinnant 算法)"""
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    mp = m - 3 if m > 2 else m + 9
    doy = (153 * mp + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _parse_http_date(raw):
    """'Wed, 04 Nov 2026 12:42:28 GMT' -> (y, mo, d, h, mi, s) 或 None"""
    try:
        parts = raw.replace(",", " ").split()
        d = int(parts[1])
        mo = _MONTHS[parts[2]]
        y = int(parts[3])
        hms = parts[4].split(":")
        return (y, mo, d, int(hms[0]), int(hms[1]), int(hms[2]))
    except Exception:
        return None


def _set_rtc_utc(parts):
    """把 UTC 时间写入 RTC; datetime 元组顺序: (年,月,日,星期,时,分,秒,亚秒)"""
    try:
        from machine import RTC
    except ImportError:
        return False
    try:
        days = _days_from_civil(parts[0], parts[1], parts[2])
        wd = (days + 3) % 7          # 1970-01-01 是星期四, Monday=0
        RTC().datetime((parts[0], parts[1], parts[2], wd,
                        parts[3], parts[4], parts[5], 0))
        return True
    except Exception:
        return False


def sync_time_http(client=None, hosts=None):
    """用 HTTP Date 响应头校时 (认证前 NTP/UDP123 常被拦, 门户 HTTP 可达)

    HTTPClient 已把响应头键统一小写, 因此读 hs.get("date")。
    返回 (ok, msg)。
    """
    c = client or HTTPClient()
    for host in (hosts or HTTP_TIME_HOSTS):
        try:
            st, hs, data = c.request("http://" + host + "/", timeout=8, max_body=1024)
        except Exception as ex:
            _dbg("[dbg] http-date %s: %s" % (host, ex))
            continue
        parsed = _parse_http_date(hs.get("date"))
        if not parsed:
            continue
        if _set_rtc_utc(parsed) and time_ok():
            return True, "http-date(%s)" % host
    return False, "http-date-fail"


def sync_time_ntp(host=None, timeout=None):
    """NTP 校时兜底 (依赖固件 ntptime; 认证前 UDP/123 可能被拦)"""
    host = host or NTP_HOST
    timeout = timeout or NTP_TIMEOUT
    try:
        import ntptime
    except ImportError:
        return False, "no-ntptime (固件缺少 ntptime 模块)"
    try:
        try:
            ntptime.host = host
        except Exception:
            pass
        try:
            ntptime.timeout = timeout
        except Exception:
            pass
        ntptime.settime()
    except Exception as ex:
        return False, "ntp-fail(%s): %s" % (host, ex)
    if not time_ok():
        return False, "ntp-set-but-time-invalid(year=%d)" % _time_year()
    return True, "ntp-ok(%s)" % host


def sync_time():
    """校时: 先 HTTP Date(认证前可达), 再 NTP 兜底。返回 (ok, msg)"""
    ok, msg = sync_time_http()
    if ok:
        return True, msg
    nok, nmsg = sync_time_ntp()
    if nok:
        return True, nmsg
    return False, "http-date-fail; " + nmsg


def ensure_time():
    """确保设备时间可用于 TLS: 已正常则跳过, 否则 NTP 校时。返回 (ok, msg)"""
    if time_ok():
        return True, "time-ok"
    ok, msg = sync_time()
    if ok:
        print("[time] 校时成功: %s" % msg)
    else:
        print("[time] 校时失败: %s (HTTP Date/NTP 均不可用; 可 mpremote rtc --set 后重试)"
              % msg)
    return ok, msg


# ---------- 设备端自检 (REPL 调用) ----------

def _dial_tcp(host, port=443, timeout=10):
    addr = socket.getaddrinfo(host, port)[0][-1]
    s = socket.socket()
    s.settimeout(timeout)
    s.connect(addr)
    return s


def _check_hostname_verification():
    """真机自证主机名校验: 正确域名应握手成功, 错误域名必须失败

    返回 'ok' / 'FAIL: hostname-not-verified' / 'tls-fail: ...' / 'skipped(insecure)'
    """
    if _tls_mode() == "INSECURE":
        return "skipped(insecure)"
    gc.collect()
    s = None
    try:
        s = _dial_tcp(CAS_HOST)
        t = _ssl_wrap_verified(s, CAS_HOST)
        s = None
        try:
            t.close()
        except Exception:
            pass
    except Exception as ex:
        return "tls-fail: %s" % ex
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass
    gc.collect()
    s2 = None
    try:
        s2 = _dial_tcp(CAS_HOST)
        _ssl_wrap_verified(s2, "wrong.invalid")
        return "FAIL: hostname-not-verified"
    except Exception:
        return "ok"
    finally:
        if s2:
            try:
                s2.close()
            except Exception:
                pass


def self_check():
    """设备端自检: TLS 模式 / CA / 时间 / 主机名校验 / 剩余堆

    用法 (设备 REPL, 模块上传为 neulib.py):
        import neulib as m
        m.wifi_connect()
        print(m.self_check())          # 打印摘要并返回 dict
    """
    gc.collect()
    mem = -1
    try:
        mem = gc.mem_free() // 1024
    except AttributeError:
        pass
    out = {
        "tls_mode": _tls_mode(),
        "ca_subjects": _ca_subjects(),
        "ca_loadable": _ca_loadable(),
        "time": time.localtime()[:6],
        "time_ok": time_ok(),
        "hostname_check": _check_hostname_verification(),
        "mem_free_kb": mem,
    }
    print("[self_check] tls=%s ca_loadable=%s time_ok=%s hostname=%s mem=%dkB"
          % (out["tls_mode"], out["ca_loadable"], out["time_ok"],
             out["hostname_check"], out["mem_free_kb"]))
    return out


# ==================== 业务集成 API ====================

def ensure_online(username=None, password=None):
    """协作式联网保障: 业务代码在主循环的安全点调用 (见文件头"使用方式B")

    已在线且联网探测正常 → 立即返回(开销仅两次小请求);
    掉线或幽灵会话 → 自动重登。返回 (ok, msg)。
    凭据不传则用 CONFIG 区的 USERNAME/PASSWORD。
    安全承诺: 本函数永不抛异常 (网络/解析/内存异常均转为 (False, msg))。
    """
    try:
        u = username or USERNAME
        p = password or PASSWORD
        if not u or not p:
            return False, "no-credentials (传入参数或填CONFIG区USERNAME/PASSWORD)"
        c = HTTPClient()
        info = check_online(c)
        if info and probe_internet(c) != "hijacked":
            return True, "online:" + info[0] + "@" + info[8]
        return login(u, p)
    except MemoryError:
        gc.collect()
        return False, "MemoryError: 堆内存耗尽, 已 gc, 下一轮重试"
    except Exception as ex:
        try:
            return False, "exc:" + str(ex)
        except Exception:
            return False, "exc"


# ==================== WiFi 与主循环 (仅ESP32) ====================

def _ts():
    # MicroPython 无 time.strftime, 手工格式化 HH:MM:SS
    t = time.localtime()
    return "%02d:%02d:%02d" % (t[3], t[4], t[5])


def _memk():
    """空闲堆KB数 (CPython无此函数返回-1, 便于同文件在PC上测试)"""
    try:
        return gc.mem_free() // 1024
    except AttributeError:
        return -1


def _mems():
    m = _memk()
    return " mem:%dkB" % m if m >= 0 else ""


_led = None
if _IS_UPY and LED_PIN is not None:
    try:
        from machine import Pin
        _led = Pin(LED_PIN, Pin.OUT)
    except Exception:
        _led = None


def led(on):
    if _led:
        try:
            _led.value(1 if on else 0)
        except Exception:
            pass


def wifi_connect(ssid=WIFI_SSID, timeout=25):
    import network
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    if not sta.isconnected():
        print("[wifi] connecting", ssid)
        sta.connect(ssid)
        t0 = time.time()
        while not sta.isconnected():
            if time.time() - t0 > timeout:
                return None
            time.sleep(0.5)
    print("[wifi] connected IP:", sta.ifconfig()[0])
    return sta


def _login_safe(username, password):
    """run_forever 用: 调用 _login_impl 并把异常收敛为 (ok, msg, kind), 永不抛"""
    try:
        return _login_impl(username, password)
    except MemoryError:
        gc.collect()
        return False, "MemoryError: 堆内存耗尽, 已 gc", "transient"
    except Exception as ex:
        try:
            return False, "exc:" + str(ex), "transient"
        except Exception:
            return False, "exc", "transient"


def _report_fail(kind, msg):
    """run_forever 失败处置: 打印原因与建议, 返回 True=继续 / False=停止主循环

    A24: 冷却由 _login_impl 保证期间不发起 CAS; 本函数只负责提示, 不改状态。
    """
    if kind == "auth":
        if _cooldown_remaining() > 0:
            print("[auth] 凭据被拒, 暂停 CAS %d 分钟以免账号被锁; "
                  "请核对密码后重启设备" % (AUTH_COOLDOWN_SEC // 60))
        else:
            # sso-reject 属安全中止: 未发送凭据 => 不写凭据冷却, 只提示疑似中间人
            print("[auth] 安全中止: 疑似中间人, 未发送凭据; 请检查网络 (%s)" % msg)
        return True
    if kind == "limit":
        print("[limit] E2620 账号在线设备数超限, 暂停 CAS %d 分钟; PC端执行 "
              "'python3 neu_login.py --devices' 查看, '--kick IP' 踢闲置设备"
              % (LIMIT_COOLDOWN_SEC // 60))
        return True
    if kind == "config":
        print("[cfg] KEY_ROTATED: 公钥与 CAS 服务端不匹配且无法自动恢复; 若为"
              " ALLOW_INSECURE_TLS=True 需手动更新 PUBKEY_B64; 已停止自动登录")
        return False
    print("[retry] 暂时性失败: %s (指数退避重试)" % msg)
    return True


def run_forever():
    if not USERNAME or not PASSWORD:
        print("[cfg] ERROR: 请先在文件顶部 CONFIG 填入 USERNAME / PASSWORD")
        return
    delay = CHECK_INTERVAL
    while True:
        sta = wifi_connect()
        if not sta:
            time.sleep(5)
            continue
        gc.collect()
        print("[boot] v%s, heap free%s" % (__version__, _mems()))
        ensure_time()          # 证书校验前提: 无 RTC 设备上电后必须 NTP 校时
        ok, msg, kind = _login_safe(USERNAME, PASSWORD)
        print("[%s] %s %s%s" % (_ts(), "OK " if ok else "ERR", msg, _mems()))
        led(ok)
        if ok:
            delay = CHECK_INTERVAL
        else:
            if not _report_fail(kind, msg):
                led(False)
                return
            delay = CHECK_INTERVAL       # 首次重试仍按 CHECK_INTERVAL, 之后指数退避
        checks = 0
        last_note = 0
        while sta.isconnected():
            time.sleep(delay)
            gc.collect()
            checks += 1
            try:
                info = check_online()
                ghost = False
                if info and probe_internet() == "hijacked":
                    # 双重校验: 账面在线 + 真实联网, 捕获幽灵会话
                    print("[watch] ghost session, rebuild%s" % _mems())
                    ghost = True
                if info and not ghost:
                    online = True
                    delay = CHECK_INTERVAL      # 已在线: 复位暂时性退避
                else:
                    online = False
                    left = _cooldown_remaining()
                    if left > 0:
                        # A24: 冷却期内只做在线状态检查与心跳, 绝不发起 CAS
                        now = _now()
                        if now - last_note >= 300:
                            last_note = now
                            print("[watch] 冷却中(%s), 剩余%d分, 跳过 CAS%s"
                                  % (_COOLDOWN_KIND, left // 60, _mems()))
                    else:
                        if not ghost:
                            print("[watch] offline, relogin%s" % _mems())
                        ok, msg, kind = _login_safe(USERNAME, PASSWORD)
                        print("[%s] %s %s%s" % (_ts(), "OK " if ok else "ERR", msg, _mems()))
                        led(ok)
                        if ok:
                            delay = CHECK_INTERVAL
                        else:
                            if not _report_fail(kind, msg):
                                led(False)
                                return
                            if kind == "transient" or (
                                    kind == "auth" and _cooldown_remaining() <= 0):
                                # 暂时性失败 / sso-reject(无凭据冷却) 均指数退避
                                delay = _next_backoff(delay)
                            else:
                                delay = CHECK_INTERVAL
                if HEARTBEAT_CHECKS and checks % HEARTBEAT_CHECKS == 0:
                    print("[%s] heartbeat %s%s" % (
                        _ts(), "online" if online else "offline", _mems()))
            except MemoryError:
                # 堆内存耗尽(碎片化): 立即回收, 下一轮巡检重试 (常驻场景必须自愈)
                gc.collect()
                print("[%s] OOM, gc 已回收 mem:%dkB, 下一轮重试" % (_ts(), _memk()))
            except Exception as ex:
                gc.collect()
                print("[watch] err:", ex, _mems())
        led(False)
        print("[wifi] lost, reconnecting")


# ==================== 入口 ====================

if __name__ != "__main__":
    # 被作为库 import: 不自动启动, 由业务代码调用 ensure_online()/login() 等
    pass
elif _IS_UPY:
    run_forever()
else:
    # CPython 测试模式:
    #   python neu_login_esp32.py check           链路自检
    #   python neu_login_esp32.py login 学号 密码  完整登录
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        print("0. TLS模式:", _tls_mode())
        subs = _ca_subjects()
        print("   CA主体: %s (%d张证书, PEM %d字节)" % (
            " / ".join(subs) if subs else "解析失败", len(subs), len(CA_CERT_PEM)))
        print("   CA加载: %s" % ("OK" if _ca_loadable() else "失败"))
        print("   校验内容: 证书链(内置 CA) + 主机名(server_hostname, 需设备时间正确)")
        print("   设备时间: %s (time_ok=%s)" % (time.localtime()[:6], time_ok()))
        if ALLOW_INSECURE_TLS is True:
            print("   !!! 警告: ALLOW_INSECURE_TLS=True, 不校验证书且公钥在线刷新已禁用 !!!")
        c = HTTPClient()
        info = check_online(c)
        print("1. 在线状态:", info[0] + "@" + info[8] if info else "不在线")
        redirect = get_sso_redirect(c)
        print("2. SSO入口:", (redirect[:55] + "...") if redirect else "失败")
        if redirect:
            try:
                _validate_cas_redirect(redirect)     # 自检同样走白名单
            except ValueError as ex:
                print("   拒绝: %s" % ex)
                redirect = None
        ok_lt = False
        if redirect:
            st, hs, data = c.request(redirect)
            ok_lt = _find_lt(data) is not None
            print("3. CAS页面: HTTP %d, %d bytes, lt令牌 %s" % (st, len(data), "OK" if ok_lt else "缺失"))
        n, e = get_key()
        cipher = rsa_encrypt(n, e, b"selftest")
        print("4. RSA加密: %dbit e=%d, 密文%d字节 %s" % (n.bit_length(), e, len(cipher), "OK" if len(cipher) == 256 else "失败"))
        print("自检结论:", "通过" if (redirect and ok_lt and len(cipher) == 256) else "异常")
    elif len(sys.argv) > 3 and sys.argv[1] == "login":
        ok, msg = login(sys.argv[2], sys.argv[3])
        print("登录结果:", "成功" if ok else "失败", "-", msg)
    elif len(sys.argv) > 1 and sys.argv[1] == "probe":
        print("真实联网探测:", probe_internet())
    elif len(sys.argv) > 1 and sys.argv[1] == "logout":
        print("注销:", logout())
    else:
        print("ESP32 MicroPython 版 NEU 自动登录")
        print("CPython测试: python %s check | login 学号 密码 | probe | logout" % sys.argv[0])
        print("ESP32部署: 填好CONFIG后上传为 main.py")
