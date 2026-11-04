#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
"""东北大学校园网自动登录脚本 (NEU-2.4G / NEU / 有线网通用)

零依赖: 仅使用 Python 标准库, CPython 3.6+ (Windows/Linux 通用, 含树莓派等嵌入式设备)

合规: 仅供使用者本人账号的自动登录与个人学习研究使用,
      禁止用于对校园网的任何攻击或滥用 (详见仓库 README 免责声明)

认证链路:
    1. 门户 ipgw.neu.edu.cn = Srun 深澜 V1.18 (本地协议已禁用, 强制 CAS)
    2. GET  /v1/srun_portal_sso           -> 拿 CAS 跳转地址
       ★ 浏览器会给 service 参数追加 ac_id (AC编号)
         —— 不带 ac_id 则只建 radius 记录、AC不放行, 产生"幽灵会话"
    3. GET  pass.neu.edu.cn/tpass/login    -> 拿 lt 令牌 + JSESSIONID Cookie
    4. POST rsa=RSA2048(PKCS1v1.5, 学号+密码) & ul & pl & lt & execution=e1s1
    5. 302 携带 ticket -> GET /v1/srun_portal_sso?ac_id=16&ticket=...
    6. GET  /srun_portal_success?ac_id=16  -> 浏览器流程的最后收尾
    7. GET  /cgi-bin/rad_user_info         -> 验证在线
       ★ 另做真实联网探测(检测门户劫持), 幽灵会话自动注销重建

    登录被拒 E2620 = 账号在线设备数超限 (浏览器会弹"在线设备管理"),
    脚本提供等价命令:
    python neu_login.py --devices          # 列出账号所有在线设备
    python neu_login.py --kick 172.26.x.x  # 踢指定IP设备下线

用法:
    python neu_login.py -u 学号 -p 密码           # 登录 (学号=统一身份认证账号)
    python neu_login.py -u 学号 -p 密码 --save    # 登录并保存凭据
    python neu_login.py                           # 用已保存凭据登录
    python neu_login.py --status                  # 查看在线状态/流量
    python neu_login.py --logout                  # 注销下线
    python neu_login.py --test                    # 链路+RSA自检(无需凭据)
    python neu_login.py --watch                   # 断线自动重连守护
    python neu_login.py --devices                 # 列出账号在线设备
    python neu_login.py --kick IP                 # 踢指定设备下线

退出码:
    0 = 成功/已在线
    2 = 网络/证书类暂时性失败(可重试, 守护会退避)
    3 = 凭据/账号/设备数/配置错误(重试无意义)
    1 = --test 自检失败
守护策略:
    网络类失败按 15s→900s 指数退避(10 分钟最多 3 次登录尝试);
    认证被拒会立即停止并进入 30 分钟冷却, 避免把账号试到锁定;
    设备数超限(E2620)同为 exit 3 但不写冷却(--kick 后直接重试)。
TLS:
    默认校验证书, 证书错误不再自动降级(旧行为可被中间人利用);
    设备时钟不准时请先校准时间, 仅在确认网络可信时使用 --insecure
    (使用 --insecure 时会同时禁用公钥在线刷新)。
"""

import argparse
import base64
import hashlib
import http.client
import http.cookiejar
import json
import os
import re
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.1.1"

PORTAL = "http://ipgw.neu.edu.cn"
CAS_LOGIN_JS = "https://pass.neu.edu.cn/tpass/comm/neu/js/login_neu.js"
AC_ID = 16

# 跳转白名单 (P0-4): 门户是明文 HTTP, 返回的 Redirect 必须校验后才能发送凭据
CAS_HOST = "pass.neu.edu.cn"
PORTAL_HOST = "ipgw.neu.edu.cn"

# 退出码约定 (P0-2): 供 systemd / NetworkManager dispatcher 判断是否值得重试
EXIT_OK, EXIT_TRANSIENT, EXIT_AUTH = 0, 2, 3
# 认证被拒后暂停 CAS 尝试的时长(秒), 防止错误密码/账号受限时把账号试到锁定
AUTH_FAIL_GUARD_SEC = 1800
# 守护模式失败退避区间(秒)
WATCH_MIN_INTERVAL, WATCH_MAX_INTERVAL = 15, 900
# 限流兜底: 任意 10 分钟内最多发起多少次 CAS 认证
CAS_ATTEMPT_WINDOW, CAS_ATTEMPT_MAX = 600, 3
# --insecure 会置 False; 默认必须校验证书 (P1-1: 不再自动降级)
TLS_VERIFY = True

# 凭据存放: Windows=脚本同目录; Linux root(systemd 服务场景)=/etc/neu; Linux 普通用户=~/.config/neu
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.name == "nt":
    CRED_FILE = os.path.join(_SCRIPT_DIR, ".neu_credentials.json")
elif os.geteuid() == 0:
    CRED_FILE = "/etc/neu/credentials.json"
else:
    CRED_FILE = os.path.join(os.path.expanduser("~/.config/neu"), "credentials.json")

# RSA 公钥 (内置默认值; 学校轮换密钥时脚本自动在线更新)
PUBKEY_B64 = ("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnjA28DLKXZzxbKmo9/1WkVLf1mr+wtL"
              "XLXt6sC4WiBCtsbzF5ewm7ARZeAdS3iZtqlYPn6IcUoOw42H8nAK/tfFcIb6dZ1K0atn0U39oWCGPz"
              "YuKtLJeMuNZiDXVuAXtojrckOjLW9B3gUnaNGLuIx0fYe66l0o9WjU2cGLNZQfiIxs2h00z1EA9I"
              "dSnVxiVQWSD+lsP3JZXh2TT287la4Y4603SQNKTK/QvXfcmccwTEd1IW6HwGxD6QrkInBiHisKW"
              "xmveN7UDSaQRZ/J97G0YC32pD38WT53izXeK0p/kU/X37VP555um1wVWFvPIuc9I7gMP1+hq5a+X"
              "6c++tQIDAQAB")


# ============ RSA (PKCS#1 v1.5) 纯实现, 无第三方依赖 ============

def _read_der_len(der, i):
    b = der[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    return int.from_bytes(der[i:i + n], "big"), i + n


def parse_spki(b64key):
    """解析 SubjectPublicKeyInfo DER, 返回 (n, e)"""
    der = base64.b64decode(b64key)
    i = 0
    if der[i] != 0x30:
        raise ValueError("bad SPKI")
    _, i = _read_der_len(der, i + 1)
    if der[i] != 0x30:
        raise ValueError("bad AlgId")
    l, i = _read_der_len(der, i + 1)
    i += l
    if der[i] != 0x03:
        raise ValueError("bad BIT STRING")
    _, i = _read_der_len(der, i + 1)
    i += 1
    if der[i] != 0x30:
        raise ValueError("bad RSAPublicKey")
    _, i = _read_der_len(der, i + 1)
    if der[i] != 0x02:
        raise ValueError("bad n")
    l, i = _read_der_len(der, i + 1)
    n = int.from_bytes(der[i:i + l], "big")
    i += l
    if der[i] != 0x02:
        raise ValueError("bad e")
    l, i = _read_der_len(der, i + 1)
    e = int.from_bytes(der[i:i + l], "big")
    return n, e


def rsa_pkcs1v15_encrypt(n, e, data: bytes) -> bytes:
    """RSA ES-PKCS1-v1_5 加密, 等价 JSEncrypt.encrypt()"""
    k = (n.bit_length() + 7) // 8
    if len(data) > k - 11:
        raise ValueError("plaintext too long for RSA key")
    ps = bytearray()
    while len(ps) < k - len(data) - 3:
        b = os.urandom(1)[0]
        if b:
            ps.append(b)
    em = b"\x00\x02" + bytes(ps) + b"\x00" + data
    m = int.from_bytes(em, "big")
    return pow(m, e, n).to_bytes(k, "big")


_RSA_KEY_CACHE = None


def get_rsa_key(refresh=False):
    """返回 (n, e); refresh=True 时从 login_neu.js 重新拉取公钥

    安全约束: --insecure(不校验 TLS) 时禁止在线刷新 —— 否则中间人可下发
    伪造公钥, 把密码加密到攻击者密钥上(与 ESP32 版策略一致)。
    """
    global _RSA_KEY_CACHE
    if not refresh and _RSA_KEY_CACHE:
        return _RSA_KEY_CACHE
    if refresh:
        if not TLS_VERIFY:
            raise RuntimeError(
                "公钥在线刷新已禁用: --insecure 下 TLS 不校验证书, 攻击者可替换公钥; "
                "请去掉 --insecure 或手动更新 PUBKEY_B64")
        opener, _ = make_opener()
        _, body, _ = fetch(opener, CAS_LOGIN_JS)
        m = re.search(r'publicKeyStr\s*=\s*"([A-Za-z0-9+/=]+)"', body)
        if not m:
            raise RuntimeError("未能从 login_neu.js 提取公钥")
        _RSA_KEY_CACHE = parse_spki(m.group(1))
        return _RSA_KEY_CACHE
    _RSA_KEY_CACHE = parse_spki(PUBKEY_B64)
    return _RSA_KEY_CACHE


# ============ HTTP 基础设施 ============

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PortalError(Exception):
    """网络层失败: 不可达/超时/DNS/连接重置, 与业务失败区分"""


class TLSError(PortalError):
    """TLS 握手或证书校验失败: 通常是设备时钟不准或被劫持, 自动重试无意义"""


class SSOValidationError(PortalError):
    """SSO/CAS 返回的跳转地址不在白名单内, 疑似中间人攻击"""


def make_opener(verify=None):
    if verify is None:
        verify = TLS_VERIFY
    cj = http.cookiejar.CookieJar()
    # ProxyHandler({}): 强制直连。若使用系统代理, 劫持探测和登录流量都会被代理干扰
    handlers = [urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cj), _NoRedirect()]
    if not verify:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers), cj


def fetch(opener, url, data=None, timeout=12, referer=None):
    """发起 HTTP(S) 请求, 返回 (status, body, headers)

    网络层异常统一收敛为 PortalError/TLSError: login()/--watch 依赖这一点,
    避免 URLError/socket.timeout 穿透导致守护进程直接退出 (P0-1)。
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    if referer:
        headers["Referer"] = referer
    if data is not None and isinstance(data, str):
        data = data.encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:          # 服务端有响应: 交给业务层按状态码处理
        return e.code, e.read().decode("utf-8", errors="replace"), dict(e.headers)
    except http.client.HTTPException as e:       # 截断响应/坏状态行等协议级错误
        raise PortalError("%s: %s" % (url, e)) from e
    except OSError as e:                         # URLError/timeout/连接重置/DNS 失败
        if _is_cert_verify_error(e):
            raise TLSError(
                "TLS 证书校验失败 (%s); 设备时钟可能不准, 请先校准时间(NTP); "
                "确认网络可信后仍需要时可用 --insecure (有中间人风险)" % e) from e
        raise PortalError("%s: %s" % (url, e)) from e


def _is_cert_verify_error(exc):
    """严格的证书验证失败判定

    只有真正的证书校验失败才转为 TLSError(需要校准时钟/人工确认);
    其它 TLS 握手错误按普通网络错误处理, 避免误判导致守护永久停止。
    """
    msg = str(exc).lower()
    for marker in ("certificate_verify_failed", "certificate verify failed",
                   "sslcertverificationerror", "self-signed certificate",
                   "unable to get local issuer certificate"):
        if marker in msg:
            return True
    cls = getattr(ssl, "SSLCertVerificationError", None)
    reason = getattr(exc, "reason", None)
    return bool(cls) and isinstance(reason, cls)


def _hget(headers, name, default=""):
    """大小写不敏感地读取响应头 (HTTP 头字段名不区分大小写)"""
    if not headers:
        return default
    value = headers.get(name)
    if value is not None:
        return value
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            return v
    return default


# ============ 业务流程 ============

def status():
    """查询当前在线状态

    返回 dict, state = "online" | "offline" | "unreachable":
    区分"确实未登录"与"门户不可达", 后者不应被当成掉线而触发重登。
    """
    opener, _ = make_opener()
    try:
        _, body, _ = fetch(opener, f"{PORTAL}/cgi-bin/rad_user_info", timeout=5)
    except Exception as e:
        return {"online": False, "state": "unreachable", "error": str(e)}
    if not body or "not_online" in body or body.startswith(","):
        return {"online": False, "state": "offline"}
    f = body.split(",")
    if len(f) < 10:
        return {"online": False, "state": "unreachable", "error": "rad_user_info 字段异常"}
    try:
        return {
            "online": True, "state": "online", "username": f[0],
            "login_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(f[1]))),
            "ip": f[8], "traffic_bytes": int(f[3]) if f[3].isdigit() else 0,
        }
    except (ValueError, IndexError, OSError, OverflowError):
        # 字段格式漂移(如时间戳变毫秒)时不能抛异常, 否则 --watch 会被直接杀死
        return {"online": False, "state": "unreachable", "error": "rad_user_info 解析失败"}


def get_sso_redirect():
    """第一步: 门户 SSO 入口 -> CAS 跳转地址"""
    opener, _ = make_opener()
    _, body, _ = fetch(opener, f"{PORTAL}/v1/srun_portal_sso?ac_id={_cur_acid()}&theme=pro")
    try:
        sso = json.loads(body)
    except json.JSONDecodeError:
        return {"code": -1, "message": f"门户响应异常: {body[:100]}"}
    if not isinstance(sso, dict):
        return {"code": -1, "message": "门户响应格式异常"}
    return sso


def _urlsplit_checked(url, what):
    """urlsplit + 端口解析异常统一转成 SSOValidationError

    urlsplit().port 对非法端口(如 :abc / :99999)会抛 ValueError,
    若不转换会被 login() 当成 transient 网络错误无限重试。
    """
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError as ex:
        raise SSOValidationError("%s 格式非法(疑似中间人): %s" % (what, url[:120])) from ex
    return u, port


def _validate_cas_redirect(redirect):
    """P0-4: 门户走明文 HTTP, 返回的 Redirect 必须白名单校验后再发送凭据

    不校验时, 开放 WiFi 上的同网段攻击者可把 CAS 登录引到自己服务器:
    拿到 RSA 密文后转发给真实 CAS 换取 ticket, 以受害者账号建立会话。
    """
    if not isinstance(redirect, str) or not redirect or len(redirect) > 4096:
        raise SSOValidationError("SSO 重定向格式异常")
    u, port = _urlsplit_checked(redirect, "SSO 重定向地址")
    if (u.scheme != "https" or u.hostname != CAS_HOST
            or port not in (None, 443) or u.username or u.password):
        raise SSOValidationError("SSO 重定向地址异常(疑似中间人), 已中止登录: %s" % redirect[:120])


def _validate_ticket_url(ticket_url):
    """CAS 认证成功后的回跳必须落在门户自己的域名上"""
    if not isinstance(ticket_url, str) or "ticket=" not in ticket_url:
        raise SSOValidationError("CAS 回跳地址缺少 ticket")
    u, port = _urlsplit_checked(ticket_url, "CAS 回跳地址")
    scheme_ok = ((u.scheme == "http" and port in (None, 80))
                 or (u.scheme == "https" and port in (None, 443)))
    if not scheme_ok or u.hostname != PORTAL_HOST or u.username or u.password:
        raise SSOValidationError("CAS 回跳地址异常(疑似中间人): %s" % ticket_url[:120])


def cas_login(username, password, service_url, n=None, e=None, verify=None):
    """CAS 统一身份认证 (RSA 加密凭据)

    返回 (ticket_url, kind, msg): kind=None 成功, 否则为失败类别
    ("key_rotated" | "auth" | "config" | "transient")
    """
    if n is None or e is None:
        n, e = get_rsa_key()
    if verify is None:
        verify = TLS_VERIFY
    opener, _ = make_opener(verify)
    return _cas_login_inner(opener, username, password, service_url, n, e)


def _cas_login_inner(opener, username, password, service_url, n, e):
    # 取登录页 + lt 令牌 (需要 JSESSIONID Cookie, 服务端绑定了会话)
    code, body, _ = fetch(opener, service_url, referer=service_url)
    m = re.search(r'name="lt" value="(.+?)"', body)
    if not m:
        title = re.search(r"<title>(.+?)</title>", body)
        return None, "transient", "CAS 页面无 lt 令牌 (HTTP %d, title=%s)" % (
            code, title.group(1) if title else "?")
    lt = m.group(1)

    # RSA 加密 学号+密码 (PKCS#1 v1.5, 与浏览器 JSEncrypt 一致)
    if not username.isascii() or not password.isascii():
        return None, "auth", "凭据含非ASCII字符, 无法计算长度"
    cipher = base64.b64encode(rsa_pkcs1v15_encrypt(n, e, (username + password).encode())).decode()
    form = urllib.parse.urlencode({
        "rsa": cipher, "ul": str(len(username)), "pl": str(len(password)),
        "lt": lt, "execution": "e1s1", "_eventId": "submit",
        "t_un": "", "t_pd": "", "t_c": "",
    })
    code, body, headers = fetch(opener, service_url, data=form, referer=service_url)

    if code == 500:
        return None, "key_rotated", "CAS 解密失败(HTTP 500)"      # 服务端解密失败 => 公钥已轮换
    if code in (301, 302, 303, 307):
        location = _hget(headers, "Location")
        if "ticket" in location:
            _validate_ticket_url(location)
            return location, None, None
        if "logout" in location or "login" in location:
            return None, "auth", "用户名或密码错误"
        return None, "transient", "CAS 跳转未携带 ticket"
    # 200 => 认证失败, 提取页面错误信息
    title = re.search(r"<title>(.+?)</title>", body)
    title = title.group(1) if title else ""
    err = re.search(r'id="errormsg"[^>]*>\s*([^<]{2,60})', body)
    if err:
        return None, "auth", f"CAS 拒绝: {err.group(1).strip()}"
    if "统一身份认证" in title:
        return None, "auth", "用户名或密码错误"
    if title == "智慧东大":
        return None, "config", "账号需要重置密码"
    if title == "系统提示":
        return None, "config", "账号被封禁或受限"
    return None, "transient", f"CAS 登录失败 (HTTP {code}, title={title})"


def complete_sso(ticket_url):
    """第三步: 携带 ticket 回门户校验, 并访问成功页完成 AC 放行

    返回 (result, kind, msg): kind=None 表示门户已受理
    """
    _validate_ticket_url(ticket_url)
    opener, _ = make_opener()
    parsed = urllib.parse.urlparse(ticket_url)
    url = f"{PORTAL}/v1/srun_portal_sso?{parsed.query}"
    _, body, _ = fetch(opener, url)
    # 浏览器流程收尾: 认证成功后跳转 srun_portal_success (失败不致命)
    try:
        fetch(opener, f"{PORTAL}/srun_portal_success?ac_id={_cur_acid()}")
    except PortalError:
        pass
    try:
        result = json.loads(body)
    except json.JSONDecodeError:
        result = {"code": -1, "message": f"门户响应异常: {body[:100]}"}
    if "E2620" in body:
        return result, "limit", (
            "账号在线设备数超限(最多3台): 用 --devices 查看, --kick <IP> 下线闲置设备; "
            "释放名额后直接重新运行即可, 不会有冷却")
    if isinstance(result, dict) and result.get("error") not in (None, "ok"):
        return result, "transient", f"门户校验失败: {result.get('error')}"
    return result, None, None


def login(username, password):
    """完整链: 在线检查(含幽灵检测) -> SSO入口 -> CAS(RSA) -> ticket校验 -> 真实性验证

    返回 (ok, msg, kind): kind ∈ {"ok","auth","transient","config","limit"}
    本函数保证**不向调用方抛网络异常**(P0-1), 便于 --watch 与部署系统安全重试。
    """
    stage = "init"
    try:
        st = status()
        if st.get("online"):
            probe = probe_internet()
            if probe == "ok":
                clear_auth_failure()
                return True, f"已在线: {st['username']} (IP {st['ip']}), 无需登录", "ok"
            if probe == "hijacked":
                print("[!] 检测到幽灵会话(账面在线但流量被门户劫持), 注销重建...")
                try:
                    logout()
                except Exception:
                    pass
            # unknown: 探测不可判, 保守视为在线
            if probe == "unknown":
                return True, f"已在线: {st['username']} (IP {st['ip']}), 联网探测不可判", "ok"

        # P0-2: 认证刚被拒过时不立刻再试, 防止错误密码/账号受限被无限重试到锁定
        if recent_auth_failure():
            return False, (
                "最近一次统一身份认证被拒, 已暂停 CAS 尝试 %d 分钟以防账号被锁; "
                "请确认密码/账号状态后重试" % (AUTH_FAIL_GUARD_SEC // 60)), "auth"

        # 检测本网段真实AC编号 (不同网段由不同AC管辖, 编号错则放行失败)
        stage = "detect_ac_id"
        detect_ac_id()

        stage = "sso_entry"
        sso = get_sso_redirect()
        redirect = sso.get("Redirect")
        if not redirect:
            return False, f"获取 SSO 入口失败: {sso.get('message', sso)}", "transient"
        stage = "sso_validate"
        _validate_cas_redirect(redirect)          # P0-4: 明文 HTTP 返回的地址先过白名单
        redirect = fix_service_url(redirect)
        _validate_cas_redirect(redirect)

        stage = "rsa_key"
        n, e = get_rsa_key()
        stage = "cas_login"
        ticket_url, kind, err = cas_login(username, password, redirect, n, e)

        if kind == "key_rotated":
            if not TLS_VERIFY:
                # --insecure 下公钥刷新已禁用(否则中间人可换钥), 只能人工处理
                return False, (
                    "服务端解密失败, 但 --insecure 下禁止在线刷新公钥; "
                    "请去掉 --insecure 重试, 或手动更新内置 PUBKEY_B64"), "config"
            print("[!] 服务端解密失败, 公钥可能已轮换, 自动拉取新公钥重试...")
            try:
                n, e = get_rsa_key(refresh=True)
                print(f"[i] 新公钥: {n.bit_length()}bit")
            except Exception as ex:
                return False, f"公钥更新失败: {ex}", "transient"
            ticket_url, kind, err = cas_login(username, password, redirect, n, e)

        if kind is not None or not ticket_url:
            if kind == "auth":          # 只有凭据被拒才需要 30 分钟冷却
                mark_auth_failure()
            return False, err or "CAS 登录失败", kind or "transient"

        stage = "sso_complete"
        result, kind, err = complete_sso(ticket_url)
        if kind in ("auth", "config", "limit"):
            if kind == "auth":          # 设备数超限/账号受限不应写凭据冷却
                mark_auth_failure()
            return False, err or "门户拒绝建立会话", kind
        if kind == "transient":
            return False, err or "门户校验失败", "transient"

        # 网关放行可能有延迟, 轮询确认 (rad_user_info + 真实联网双重验证)
        stage = "verify"
        for _ in range(4):
            st = status()
            if st.get("online"):
                probe = probe_internet()
                if probe == "ok":
                    clear_auth_failure()
                    return True, f"登录成功: {st['username']} (IP {st['ip']})", "ok"
                if probe == "hijacked":
                    return False, "会话已建立但流量仍被劫持 (幽灵会话, 下轮巡检将自动重建)", "transient"
                return True, f"登录成功: {st['username']} (IP {st['ip']}), 联网探测不可判", "ok"
            time.sleep(1.5)
        return False, "ticket 校验后仍未在线 (检查账号是否超3设备限制/欠费)", "transient"
    except TLSError as ex:
        # 证书/时钟问题按网络类错误退避重试(等 NTP 自愈), 不永久停止守护
        return False, str(ex), "transient"
    except SSOValidationError as ex:
        # 疑似中间人: 不自动重试
        return False, str(ex), "auth"
    except PortalError as ex:
        return False, f"网络不可达({stage}): {ex}", "transient"
    except Exception as ex:                      # 兜底: login() 永不抛异常
        return False, f"未预期错误({stage}): {ex!r}", "transient"


# ============ 失败分类 / 退避 / 限流 (P0-1, P0-2) ============

_AUTH_FAIL_FILE = None      # 测试可覆盖; 生产环境与凭据同目录


def _auth_state_paths():
    """认证失败状态文件候选路径 (凭据目录优先, 不可写时回退到临时目录)

    非 root 只用 -u/-p 且未 --save 时 ~/.config/neu 可能不存在,
    此时必须能回退, 否则防锁号守卫静默失效(fail-open)。
    回退路径按 uid 区分, 避免同机其他用户预置同名文件造成冷却 DoS。
    """
    if _AUTH_FAIL_FILE:
        return [_AUTH_FAIL_FILE]
    paths = []
    d = os.path.dirname(CRED_FILE)
    if d:
        paths.append(os.path.join(d, ".authfail"))
    uid = getattr(os, "getuid", lambda: "user")()
    paths.append(os.path.join(tempfile.gettempdir(), "neu-login-%s.authfail" % uid))
    return paths


def _auth_state_file():
    paths = _auth_state_paths()
    return paths[0]


def _write_auth_state(path):
    """以 0600 + O_NOFOLLOW 写入时间戳(防符号链接截断/越权写)"""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, str(int(time.time())).encode())
    finally:
        os.close(fd)


def mark_auth_failure():
    """记录一次"认证被拒", 供后续进程/巡检快速跳过, 避免把账号试到锁定"""
    global _AUTH_FAIL_FILE
    for path in _auth_state_paths():
        try:
            _write_auth_state(path)
            _AUTH_FAIL_FILE = path      # 记住可写位置, 同进程后续读写一致
            return
        except OSError:
            continue


def clear_auth_failure():
    for path in _auth_state_paths():
        try:
            os.remove(path)
        except OSError:
            pass


def recent_auth_failure():
    """认证被拒后 AUTH_FAIL_GUARD_SEC 秒内返回 True"""
    now = time.time()
    for path in _auth_state_paths():
        try:
            with open(path, encoding="utf-8") as f:
                ts = int(f.read(64).strip())     # 限制读取长度, 防超大文件 DoS
        except (OSError, ValueError):
            continue
        if 0 <= now - ts < AUTH_FAIL_GUARD_SEC:
            return True
    return False


class _RateLimiter:
    """滑动窗口限流: 兜底防止任何逻辑分支把 CAS 重试打成风暴"""

    def __init__(self, max_events, window):
        self.max_events = max_events
        self.window = window
        self.events = []

    def allow(self, now=None):
        now = time.time() if now is None else now
        self.events = [t for t in self.events if now - t < self.window]
        if len(self.events) >= self.max_events:
            return False
        self.events.append(now)
        return True

    def next_wait(self, now=None):
        """还需等待多少秒才能再次放行; 未达上限返回 0"""
        now = time.time() if now is None else now
        self.events = [t for t in self.events if now - t < self.window]
        if len(self.events) < self.max_events:
            return 0
        return max(0, int(self.events[0] + self.window - now) + 1)


def _exit_code(kind):
    """把 login() 的失败类别映射为进程退出码 (0/2/3)"""
    if kind == "ok":
        return EXIT_OK
    return EXIT_AUTH if kind in ("auth", "config", "limit") else EXIT_TRANSIENT


def _rate_limited_login(cred, limiter, sleep):
    wait = limiter.next_wait()
    if wait:
        print("[!] 10 分钟内 CAS 尝试已达上限, 等待 %ds 再试" % wait)
        sleep(wait)
    limiter.allow()
    return login(cred["username"], cred["password"])


def watch_loop(cred, sleep=None):
    """断线自动重连守护主循环, 返回进程退出码

    - 网络异常不再杀死守护, 失败按 15s→900s 指数退避;
    - 认证被拒/账号受限时立即停止(exit 3), 避免无限重试把账号锁死;
    - sleep 参数仅供测试注入, 生产环境使用 time.sleep。
    """
    if sleep is None:
        sleep = time.sleep
    interval = WATCH_MIN_INTERVAL
    limiter = _RateLimiter(CAS_ATTEMPT_MAX, CAS_ATTEMPT_WINDOW)
    print("[*] 断线守护模式 v%s (Ctrl+C 退出), 检测间隔 %ds, 失败退避上限 %ds"
          % (__version__, WATCH_MIN_INTERVAL, WATCH_MAX_INTERVAL))
    try:
        while True:
            ok, msg, kind = True, "", "ok"
            try:
                st = status()
                if st.get("online"):
                    if probe_internet() == "hijacked":
                        print("[%s] 幽灵会话! 重建..." % time.strftime("%H:%M:%S"))
                        ok, msg, kind = _rate_limited_login(cred, limiter, sleep)
                    else:
                        print("[%s] 在线: %s" % (time.strftime("%H:%M:%S"), st.get("username", "")))
                        interval = WATCH_MIN_INTERVAL   # 恢复在线后复位退避
                        sleep(interval)
                        continue
                elif st.get("state") == "unreachable":
                    print("[%s] 门户不可达: %s" % (time.strftime("%H:%M:%S"), st.get("error", "")))
                    ok, msg, kind = False, "门户不可达", "transient"
                else:
                    print("[%s] 掉线! 重连..." % time.strftime("%H:%M:%S"))
                    if wait_portal():
                        ok, msg, kind = _rate_limited_login(cred, limiter, sleep)
                    else:
                        ok, msg, kind = False, "门户不可达", "transient"
                print("[%s] %s %s" % (time.strftime("%H:%M:%S"), "[+]" if ok else "[!]", msg))
            except Exception as ex:              # 任何未预期异常都不允许杀死守护
                print("[!] %s 未预期异常: %r" % (time.strftime("%H:%M:%S"), ex))
                ok, msg, kind = False, "未预期异常", "transient"
            if not ok and kind in ("auth", "config", "limit"):
                if kind == "limit":
                    print("[!] 账号在线设备数超限, 已停止守护; 用 --devices/--kick 释放名额后重启即可(无冷却)")
                elif kind == "config":
                    print("[!] 账号状态异常(需重置密码/受限), 已停止守护; 处理后重新启动")
                else:
                    print("[!] 凭据被拒, 已停止守护并冷却 %d 分钟以免账号被锁"
                          % (AUTH_FAIL_GUARD_SEC // 60))
                return _exit_code(kind)
            sleep(interval)
            interval = WATCH_MIN_INTERVAL if ok else min(interval * 2, WATCH_MAX_INTERVAL)
    except KeyboardInterrupt:                    # Ctrl+C 在 sleep 期间也要优雅退出
        print("\n[*] 退出守护模式")
        return EXIT_OK


def logout():
    opener, _ = make_opener()
    _, body, _ = fetch(opener, f"{PORTAL}/cgi-bin/rad_user_info", timeout=5)
    if not body or "not_online" in body or body.startswith(","):
        return "当前不在线"
    f = body.split(",")
    if len(f) < 10:
        return "当前不在线"
    params = urllib.parse.urlencode({
        "callback": "srun", "action": "logout", "ip": f[8], "username": f[0],
        "time": int(time.time() * 1000), "ac_id": _cur_acid(),
    })
    _, body, _ = fetch(opener, f"{PORTAL}/cgi-bin/srun_portal?{params}")
    text = body.strip()
    if text.startswith("srun("):
        text = text[5:-1]
    try:
        r = json.loads(text)
        return "已注销" if r.get("error") == "ok" else f"注销响应: {r.get('error')}"
    except json.JSONDecodeError:
        return "已注销"


def wait_portal(timeout=300):
    start = time.time()
    while time.time() - start < timeout:
        try:
            opener, _ = make_opener()
            fetch(opener, f"{PORTAL}/cgi-bin/rad_user_info", timeout=3)
            return True
        except Exception:
            time.sleep(2)
    return False


# ============ 账号多设备管理 ============

def list_devices(username, password):
    """列出账号所有在线设备: /v1/srun_portal_online

    超过设备数上限时登录被拒(E2620), 需先踢掉闲置设备
    """
    params = urllib.parse.urlencode({
        "user_name": username,
        "password": hashlib.md5(password.encode()).hexdigest(),
    })
    opener, _ = make_opener()
    _, body, _ = fetch(opener, f"{PORTAL}/v1/srun_portal_online?{params}")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"error": f"响应异常: {body[:120]}"}


def kick_device(username, password, ip):
    """踢指定 IP 设备下线: /cgi-bin/rad_user_dm (unbind=1)

    sign = sha1(time + username + ip + unbind + time)
    """
    t = str(int(time.time()))
    sign = hashlib.sha1((t + username + ip + "1" + t).encode()).hexdigest()
    params = urllib.parse.urlencode({
        "callback": "srun", "ip": ip, "username": username,
        "time": t, "unbind": 1, "sign": sign,
    })
    opener, _ = make_opener()
    _, body, _ = fetch(opener, f"{PORTAL}/cgi-bin/rad_user_dm?{params}")
    text = body.strip()
    if text.startswith("srun("):
        text = text[5:-1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": f"响应异常: {text[:120]}"}


# ============ 真实联网探测与幽灵会话检测 ============

DETECTED_AC_ID = None       # 运行时检测到的本网段AC编号 (见 detect_ac_id)


def _cur_acid():
    return DETECTED_AC_ID or AC_ID


def detect_ac_id():
    """从AC劫持URL提取本网段真实AC编号 (ac_id)

    ac_id 是接入控制器(AC)编号, 不同网段可能由不同AC管辖。
    用错编号时: radius 建记录但真正的AC不执行放行 => 幽灵会话/登录失败。
    劫持URL格式: ...location.href='http://202.118.1.87/index_<N>.html?...'
    门户前端同样从 URL 读取 acid
    """
    global DETECTED_AC_ID
    opener, _ = make_opener()
    try:
        code, body, headers = fetch(opener, "http://connect.rom.miui.com/generate_204", timeout=6)
    except Exception:
        return None
    if code == 204 and not body:
        return DETECTED_AC_ID       # 在线无劫持, 保持原值
    # 劫持有两种形态: 302 跳转(标志在 Location 头, body 为空) / 200 注入页(标志在 body)
    text = body + " " + _hget(headers, "Location")
    for marker in ("ac_id=", "index_"):
        m = re.search(marker + r"(\d+)", text)
        if m:
            DETECTED_AC_ID = int(m.group(1))
            if DETECTED_AC_ID != AC_ID:
                print(f"[i] 检测到本网段AC编号: {DETECTED_AC_ID} (默认{AC_ID}), 已自动适配")
            return DETECTED_AC_ID
    return None


def probe_internet(timeout=5):
    """探测真实联网状态, 返回 'ok' | 'hijacked' | 'unknown'

    幽灵会话: rad_user_info 显示在线, 但 AC 并未放行,
    HTTP 访问外网会被重定向到 202.118.1.87 认证门户。
    劫持有两种形态: 302 跳转(看 Location 头) / 200 页面注入(看 body), 均检测。
    """
    opener, _ = make_opener()
    for url in ("http://www.baidu.com/", "http://connect.rom.miui.com/generate_204"):
        try:
            code, body, headers = fetch(opener, url, timeout=timeout)
        except Exception:
            continue
        loc = _hget(headers, "Location")
        if "202.118.1.87" in loc or "srun_portal" in loc or "neu.edu.cn" in loc:
            return "hijacked"
        if "top.self.location.href" in body or "202.118.1.87" in body:
            return "hijacked"
        if code == 204 or (code == 200 and _hget(headers, "Date")):
            return "ok"
    return "unknown"


def fix_service_url(redirect):
    """给 CAS service 参数追加 ac_id (复刻浏览器登录流程)

    不追加 ac_id 时门户只建立 radius 会话记录, 不通知 AC 放行 => 幽灵会话
    """
    basic, sep, service_enc = redirect.rpartition("service=")
    if not sep or not service_enc:
        return redirect
    service = urllib.parse.unquote(service_enc)
    if "ac_id=" in service:
        return redirect
    service += ("&" if "?" in service else "?") + f"ac_id={_cur_acid()}"
    return basic + "service=" + urllib.parse.quote(service, safe="")


# ============ 凭据管理 ============

def save_credentials(username, password):
    d = os.path.dirname(CRED_FILE)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(CRED_FILE, "w", encoding="utf-8") as f:
        json.dump({"username": username, "password": password}, f)
    os.chmod(CRED_FILE, 0o600)
    print(f"[i] 凭据已保存到 {CRED_FILE} (权限600, 明文, 注意安全)")


def load_credentials():
    if os.path.exists(CRED_FILE):
        with open(CRED_FILE, encoding="utf-8") as f:
            return json.load(f)
    return None


# ============ 自检 ============

def self_test():
    print(f"[*] 链路自检开始 (v{__version__}, TLS 校验{'开启' if TLS_VERIFY else '关闭(--insecure)'})")
    results = []

    def run(name, fn):
        try:
            print("    %d. %s: %s" % (len(results) + 1, name, fn()))
            results.append(True)
        except Exception as ex:
            print("    %d. %s: 失败 (%s)" % (len(results) + 1, name, ex))
            results.append(False)
        return results[-1]

    def s1():
        st = status()
        if st.get("online"):
            return "在线 " + st.get("username", "")
        if st.get("state") == "unreachable":
            raise PortalError(st.get("error", "门户不可达"))
        return "不在线(未登录状态,正常)"

    def s2():
        sso = get_sso_redirect()
        redirect = sso.get("Redirect")
        if not redirect:
            raise PortalError("获取失败: %s" % (sso.get("message", sso),))
        _validate_cas_redirect(redirect)          # 自检也验证白名单
        return "OK"

    def s3():
        sso = get_sso_redirect()
        redirect = sso.get("Redirect") or ""
        _validate_cas_redirect(redirect)
        opener, _ = make_opener()
        _, body, _ = fetch(opener, redirect)
        if 'name="lt"' not in body:
            raise PortalError("CAS 页面缺少 lt 令牌 (可能改版)")
        return "OK"

    def s4():
        n, e = get_rsa_key()
        cipher = rsa_pkcs1v15_encrypt(n, e, b"selftest")
        if len(cipher) != 256:
            raise ValueError("RSA 密文长度异常: %d" % len(cipher))
        return "OK (%dbit, e=%d)" % (n.bit_length(), e)

    def s5():
        if not TLS_VERIFY:
            return "已跳过 (--insecure 下公钥在线刷新被禁用)"
        n, e = get_rsa_key()
        n2, e2 = get_rsa_key(refresh=True)
        return "OK, 与内置一致" if (n2, e2) == (n, e) else "公钥已变化, 已缓存新公钥"

    run("门户在线查询", s1)
    run("SSO 入口获取", s2)
    run("CAS 登录页 lt 令牌", s3)
    run("RSA 加密", s4)
    run("公钥在线刷新", s5)
    all_ok = all(results) and len(results) == 5
    print(f"[{'+' if all_ok else '!'}] 自检{'通过, 可执行自动登录' if all_ok else '存在异常'}")
    return all_ok


def _dispatch(args, ap):
    """执行具体子命令, 返回进程退出码
    0=成功/在线, 2=网络/证书类暂时性失败(可重试), 3=凭据/账号/设备数/配置错误(重试无意义);
    --test 自检失败返回 1(不属于部署系统的重试语义)。
    """
    if args.test:
        return EXIT_OK if self_test() else 1

    if args.status:
        st = status()
        if st.get("online"):
            print(f"[+] 在线: {st['username']}  IP: {st['ip']}")
            print(f"    登录时间: {st['login_time']}")
            print(f"    账号累计流量: {st['traffic_bytes']/1024/1024:.1f}MB")
        elif st.get("state") == "unreachable":
            print(f"[-] 无法连接门户: {st.get('error', '')}")
            return EXIT_TRANSIENT
        else:
            print("[-] 当前不在线")
        return EXIT_OK

    if args.logout:
        print(f"[*] {logout()}")
        return EXIT_OK

    if args.devices or args.kick:
        if args.username and args.password:
            cred = {"username": args.username, "password": args.password}
        else:
            cred = load_credentials()
            if not cred:
                ap.error("请提供 -u 学号 -p 密码, 或先用 --save 保存凭据")
        if args.devices:
            r = list_devices(cred["username"], cred["password"])
            devs = r.get("data") or []
            if devs:
                print(f"[i] 账号在线设备 {len(devs)} 台:")
                for i, d in enumerate(devs, 1):
                    print(f"    {i}. IP {d.get('ip')}"
                          f"  {d.get('os_name', '')} (client_type={d.get('client_type', '')})"
                          f"  登录于 {d.get('add_time', '')}")
                    print(f"       踢下线: python neu_login.py --kick {d.get('ip')}")
            else:
                print(f"[-] 无在线设备, 响应: {r}")
        if args.kick:
            r = kick_device(cred["username"], cred["password"], args.kick)
            ok = r.get("error") == "ok"
            print(f"[{'+' if ok else '!'}] 踢 {args.kick}: {r}")
            if ok:
                clear_auth_failure()     # 用户已释放设备名额, 解除凭据冷却
            return EXIT_OK if ok else EXIT_TRANSIENT
        return EXIT_OK

    if args.username and args.password:
        cred = {"username": args.username, "password": args.password}
        if args.save:
            save_credentials(args.username, args.password)
            clear_auth_failure()         # 用户更新了凭据, 解除旧凭据的冷却
    else:
        cred = load_credentials()
        if not cred:
            ap.error("请提供 -u 学号 -p 密码, 或先用 --save 保存凭据")

    if args.watch:
        return watch_loop(cred)

    print(f"[*] NEU 自动登录 v{__version__}")
    ok, msg, kind = login(cred["username"], cred["password"])
    print(f"{'[+]' if ok else '[!]'} {msg}")
    return _exit_code("ok" if ok else kind)


def main():
    ap = argparse.ArgumentParser(description="东北大学校园网自动登录 (CAS统一身份认证/RSA)")
    ap.add_argument("-u", "--username", help="统一身份认证学号")
    ap.add_argument("-p", "--password", help="统一身份认证密码")
    ap.add_argument("--save", action="store_true", help="保存凭据到本地(.neu_credentials.json)")
    ap.add_argument("--status", action="store_true", help="查看在线状态与流量")
    ap.add_argument("--logout", action="store_true", help="注销下线")
    ap.add_argument("--test", action="store_true", help="链路+RSA自检(无需凭据)")
    ap.add_argument("--watch", action="store_true", help="断线自动重连守护模式")
    ap.add_argument("--devices", action="store_true", help="列出账号所有在线设备")
    ap.add_argument("--kick", metavar="IP", help="踢指定IP的设备下线 (先 --devices 查看)")
    ap.add_argument("--insecure", action="store_true",
                    help="跳过 TLS 证书校验(仅设备时钟无法校准等极端场景; 存在中间人风险)")
    ap.add_argument("--version", action="version", version=f"%(prog)s v{__version__}")
    args = ap.parse_args()

    global TLS_VERIFY
    if args.insecure:
        TLS_VERIFY = False
        print("[!] --insecure: 已关闭 TLS 证书校验(中间人风险); "
              "公钥在线刷新已禁用", file=sys.stderr)

    try:
        code = _dispatch(args, ap)
    except PortalError as ex:
        print(f"[!] 网络不可达: {ex}")
        code = EXIT_TRANSIENT
    except KeyboardInterrupt:
        print("\n[*] 已中断")
        code = EXIT_TRANSIENT
    except Exception as ex:                       # 兜底: 不给用户裸 traceback
        print(f"[!] 未预期错误: {ex!r}")
        code = EXIT_TRANSIENT
    sys.exit(code)


if __name__ == "__main__":
    main()
