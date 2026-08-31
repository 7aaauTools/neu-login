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
__version__ = "1.0"

# ==================== CONFIG ====================
WIFI_SSID = "NEU-2.4G"      # 开放网络, 无需密码
USERNAME = ""               # 统一身份认证学号 (即网页登录使用的学号)
PASSWORD = ""               # 统一身份认证密码
AC_ID = 16                 # 默认AC编号; 实际运行时从劫持URL自动检测
CHECK_INTERVAL = 30         # 在线巡检间隔(秒)
LED_PIN = 2                 # 板载LED引脚, 不需要则设为 None
DEBUG = False               # 置 True 打印各步骤服务器原始响应(仅排查用); 正常运行保持 False
# ================================================

DETECTED_AC_ID = None       # 运行时检测到的本网段AC编号 (见 detect_ac_id)

PORTAL = "ipgw.neu.edu.cn"
CAS_JS_URL = "https://pass.neu.edu.cn/tpass/comm/neu/js/login_neu.js"

# RSA公钥 (内置默认值; 学校轮换密钥时自动在线更新)
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


def _ssl_wrap(sock, host):
    """MicroPython 各版本 SSL API 兼容封装 (不校验证书, 校园网场景够用)"""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            ctx.check_hostname = False
        except Exception:
            pass
        try:
            ctx.verify_mode = ssl.CERT_NONE
        except Exception:
            pass
        return ctx.wrap_socket(sock, server_hostname=host)
    except (AttributeError, TypeError, ValueError):
        pass
    try:
        return ssl.wrap_socket(sock, server_hostname=host)
    except TypeError:
        return ssl.wrap_socket(sock)


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
    """获取RSA公钥(n,e); refresh=True时从 login_neu.js 在线拉取"""
    global _KEY_CACHE
    if not refresh and _KEY_CACHE:
        return _KEY_CACHE
    if refresh and client:
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

        hdrs = {"Host": host, "User-Agent": "ESP32-NEU-Login/1.0",
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
    若门户拒绝建会话, DEBUG 模式会打印原因 (E2620=账号在线设备数超限)"""
    i = ticket_url.find("?")
    q = ticket_url[i + 1:] if i >= 0 else ""
    try:
        st, hs, data = c.request("http://" + PORTAL + "/v1/srun_portal_sso?" + q)
        if DEBUG:
            body = data[:200].decode() if data else ""
            _dbg("[dbg] sso-validate HTTP %d %s" % (st, body))
            if "E2620" in body:
                _dbg("[dbg] E2620: 超出账号允许在线设备数! PC端执行"
                     " 'python3 neu_login.py --devices' 查看, '--kick IP' 踢闲置设备")
    except Exception as ex:
        _dbg("[dbg] sso-validate exc=%s" % ex)
    # 浏览器流程收尾: 认证成功后跳 srun_portal_success, 完成 AC 放行
    try:
        c.request("http://" + PORTAL + "/srun_portal_success?ac_id=%d" % _cur_acid())
    except Exception:
        pass


def login(username, password):
    c = HTTPClient()
    info = check_online(c)
    if info:
        # 双重校验: 账面在线但流量被劫持 => 幽灵会话, 注销重建
        probe = probe_internet(c)
        if probe == "ok":
            return True, "online:" + info[0] + "@" + info[8]
        if probe == "hijacked":
            print("[login] ghost session, rebuild")
            try:
                logout(c, info)
            except Exception:
                pass
        else:
            return True, "online:" + info[0] + "@" + info[8] + " probe-unknown"

    # 关键: 检测本网段真实AC编号 (不同网段由不同AC管辖, 编号错则放行失败)
    detect_ac_id(c)

    redirect = get_sso_redirect(c)
    if not redirect:
        return False, "no-redirect"
    redirect = fix_service_url(redirect)

    n, e = get_key()
    ticket_url, err = cas_login(c, username, password, redirect, n, e)
    if err == "KEY_ROTATED":
        try:
            n, e = get_key(c, refresh=True)
            ticket_url, err = cas_login(c, username, password, redirect, n, e)
        except Exception as ex:
            return False, "key-refresh-fail:" + str(ex)
    if not ticket_url:
        return False, err or "cas-fail"
    _dbg("[dbg] ticket %s" % ticket_url[:80])

    complete_sso(c, ticket_url)
    # 网关放行可能延迟, 轮询: 在线状态 + 真实联网双确认
    for _ in range(5):
        info = check_online(c)
        if info:
            probe = probe_internet(c)
            if probe == "hijacked":
                return False, "ghost-after-login"
            return True, "login-ok:" + info[0] + "@" + info[8]
        time.sleep(2)
    return False, "verify-fail"


# ==================== 业务集成 API ====================

def ensure_online(username=None, password=None):
    """协作式联网保障: 业务代码在主循环的安全点调用 (见文件头"使用方式B")

    已在线且联网探测正常 → 立即返回(开销仅两次小请求);
    掉线或幽灵会话 → 自动重登。返回 (ok, msg)。
    凭据不传则用 CONFIG 区的 USERNAME/PASSWORD。
    """
    u = username or USERNAME
    p = password or PASSWORD
    if not u or not p:
        return False, "no-credentials (传入参数或填CONFIG区USERNAME/PASSWORD)"
    c = HTTPClient()
    info = check_online(c)
    if info and probe_internet(c) != "hijacked":
        return True, "online:" + info[0] + "@" + info[8]
    return login(u, p)


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


def run_forever():
    if not USERNAME or not PASSWORD:
        print("[cfg] ERROR: 请先在文件顶部 CONFIG 填入 USERNAME / PASSWORD")
        return
    while True:
        sta = wifi_connect()
        if not sta:
            time.sleep(5)
            continue
        gc.collect()
        print("[boot] v%s, heap free%s" % (__version__, _mems()))
        try:
            ok, msg = login(USERNAME, PASSWORD)
        except Exception as ex:
            ok, msg = False, "exc:" + str(ex)
        print("[%s] %s %s%s" % (_ts(), "OK " if ok else "ERR", msg, _mems()))
        led(ok)
        while sta.isconnected():
            time.sleep(CHECK_INTERVAL)
            gc.collect()
            try:
                info = check_online()
                if info:
                    # 双重校验: 账面在线 + 真实联网, 捕获幽灵会话
                    if probe_internet() == "hijacked":
                        print("[watch] ghost session, rebuild%s" % _mems())
                        ok, msg = login(USERNAME, PASSWORD)
                        print("[%s] %s %s%s" % (_ts(), "OK " if ok else "ERR", msg, _mems()))
                        led(ok)
                else:
                    print("[watch] offline, relogin%s" % _mems())
                    ok, msg = login(USERNAME, PASSWORD)
                    print("[%s] %s %s%s" % (_ts(), "OK " if ok else "ERR", msg, _mems()))
                    led(ok)
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
        c = HTTPClient()
        info = check_online(c)
        print("1. 在线状态:", info[0] + "@" + info[8] if info else "不在线")
        redirect = get_sso_redirect(c)
        print("2. SSO入口:", (redirect[:55] + "...") if redirect else "失败")
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
