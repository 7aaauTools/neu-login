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
"""

import argparse
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

__version__ = "1.0"

PORTAL = "http://ipgw.neu.edu.cn"
CAS_LOGIN_JS = "https://pass.neu.edu.cn/tpass/comm/neu/js/login_neu.js"
AC_ID = 16

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
    """返回 (n, e); refresh=True 时从 login_neu.js 重新拉取公钥"""
    global _RSA_KEY_CACHE
    if not refresh and _RSA_KEY_CACHE:
        return _RSA_KEY_CACHE
    if refresh:
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


def make_opener(verify=True):
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
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace"), dict(e.headers)


def _is_ssl_cert_error(exc):
    msg = str(exc)
    reason = getattr(exc, "reason", None)
    return isinstance(reason, ssl.SSLError) or "CERTIFICATE" in msg or "SSL" in msg


# ============ 业务流程 ============

def status():
    """查询当前在线状态 (返回 srun 侧账号信息)"""
    opener, _ = make_opener()
    try:
        _, body, _ = fetch(opener, f"{PORTAL}/cgi-bin/rad_user_info", timeout=5)
    except Exception as e:
        return {"online": False, "error": str(e)}
    if not body or "not_online" in body or body.startswith(","):
        return {"online": False}
    f = body.split(",")
    if len(f) < 10:
        return {"online": False}
    try:
        return {
            "online": True, "username": f[0],
            "login_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(f[1]))),
            "ip": f[8], "traffic_bytes": int(f[3]) if f[3].isdigit() else 0,
        }
    except (ValueError, IndexError):
        return {"online": False}


def get_sso_redirect():
    """第一步: 门户 SSO 入口 -> CAS 跳转地址"""
    opener, _ = make_opener()
    _, body, _ = fetch(opener, f"{PORTAL}/v1/srun_portal_sso?ac_id={_cur_acid()}&theme=pro")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"code": -1, "message": f"门户响应异常: {body[:100]}"}


def cas_login(username, password, service_url, n=None, e=None, verify=True):
    """CAS 统一身份认证 (RSA加密凭据), 成功返回带 ticket 的回调 URL"""
    if n is None or e is None:
        n, e = get_rsa_key()
    try:
        opener, _ = make_opener(verify)
        return _cas_login_inner(opener, username, password, service_url, n, e)
    except (urllib.error.URLError, ssl.SSLError) as ex:
        if verify and _is_ssl_cert_error(ex):
            print("[!] SSL 证书校验失败 (设备时钟可能不准), 改用不校验证书模式重试")
            opener, _ = make_opener(verify=False)
            return _cas_login_inner(opener, username, password, service_url, n, e)
        raise


def _cas_login_inner(opener, username, password, service_url, n, e):
    # 取登录页 + lt 令牌 (需要 JSESSIONID Cookie, 服务端绑定了会话)
    code, body, _ = fetch(opener, service_url, referer=service_url)
    m = re.search(r'name="lt" value="(.+?)"', body)
    if not m:
        title = re.search(r"<title>(.+?)</title>", body)
        return None, f"CAS 页面无 lt 令牌 (HTTP {code}, title={title.group(1) if title else '?'})"
    lt = m.group(1)

    # RSA 加密 学号+密码 (PKCS#1 v1.5, 与浏览器 JSEncrypt 一致)
    if not username.isascii() or not password.isascii():
        return None, "凭据含非ASCII字符, 无法计算长度"
    cipher = base64.b64encode(rsa_pkcs1v15_encrypt(n, e, (username + password).encode())).decode()
    form = urllib.parse.urlencode({
        "rsa": cipher, "ul": str(len(username)), "pl": str(len(password)),
        "lt": lt, "execution": "e1s1", "_eventId": "submit",
        "t_un": "", "t_pd": "", "t_c": "",
    })
    code, body, headers = fetch(opener, service_url, data=form, referer=service_url)

    if code == 500:
        return None, "__KEY_ROTATED__"  # 服务端解密失败 => 公钥已轮换
    if code in (301, 302, 303, 307):
        location = headers.get("Location", "")
        if "ticket" in location:
            return location, None
        if "logout" in location or "login" in location:
            return None, "用户名或密码错误"
        return location, "CAS 跳转未携带 ticket"
    # 200 => 认证失败, 提取页面错误信息
    title = re.search(r"<title>(.+?)</title>", body)
    title = title.group(1) if title else ""
    err = re.search(r'id="errormsg"[^>]*>\s*([^<]{2,60})', body)
    if err:
        return None, f"CAS 拒绝: {err.group(1).strip()}"
    if "统一身份认证" in title:
        return None, "用户名或密码错误"
    if title == "智慧东大":
        return None, "账号需要重置密码"
    if title == "系统提示":
        return None, "账号被封禁或受限"
    return None, f"CAS 登录失败 (HTTP {code}, title={title})"


def complete_sso(ticket_url):
    """第三步: 携带 ticket 回门户校验, 并访问成功页完成 AC 放行"""
    opener, _ = make_opener()
    parsed = urllib.parse.urlparse(ticket_url)
    url = f"{PORTAL}/v1/srun_portal_sso?{parsed.query}"
    _, body, _ = fetch(opener, url)
    # 浏览器流程收尾: 认证成功后跳转 srun_portal_success
    try:
        fetch(opener, f"{PORTAL}/srun_portal_success?ac_id={_cur_acid()}")
    except Exception:
        pass
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"code": -1, "message": f"门户响应异常: {body[:100]}"}


def login(username, password):
    """完整链: 在线检查(含幽灵检测) -> SSO入口 -> CAS(RSA) -> ticket校验 -> 真实性验证"""
    st = status()
    if st.get("online"):
        probe = probe_internet()
        if probe == "ok":
            return True, f"已在线: {st['username']} (IP {st['ip']}), 无需登录"
        if probe == "hijacked":
            print("[!] 检测到幽灵会话(账面在线但流量被门户劫持), 注销重建...")
            try:
                logout()
            except Exception:
                pass
        # unknown: 探测不可判, 保守视为在线
        if probe == "unknown":
            return True, f"已在线: {st['username']} (IP {st['ip']}), 联网探测不可判"

    # 检测本网段真实AC编号 (不同网段由不同AC管辖, 编号错则放行失败)
    detect_ac_id()

    sso = get_sso_redirect()
    redirect = sso.get("Redirect")
    if not redirect:
        return False, f"获取 SSO 入口失败: {sso.get('message', sso)}"
    redirect = fix_service_url(redirect)
    n, e = get_rsa_key()
    ticket_url, err = cas_login(username, password, redirect, n, e)

    if err == "__KEY_ROTATED__":
        print("[!] 服务端解密失败, 公钥可能已轮换, 自动拉取新公钥重试...")
        try:
            n, e = get_rsa_key(refresh=True)
            print(f"[i] 新公钥: {n.bit_length()}bit")
        except Exception as ex:
            return False, f"公钥更新失败: {ex}"
        ticket_url, err = cas_login(username, password, redirect, n, e)

    if err and not ticket_url:
        return False, err if not err.startswith("__") else "公钥轮换后仍解密失败"
    if not ticket_url:
        return False, f"CAS 异常: {err}"

    complete_sso(ticket_url)
    # 网关放行可能有延迟, 轮询确认 (rad_user_info + 真实联网双重验证)
    for _ in range(4):
        st = status()
        if st.get("online"):
            probe = probe_internet()
            if probe == "ok":
                return True, f"登录成功: {st['username']} (IP {st['ip']})"
            if probe == "hijacked":
                return False, "会话已建立但流量仍被劫持 (幽灵会话, 下轮巡检将自动重建)"
            return True, f"登录成功: {st['username']} (IP {st['ip']}), 联网探测不可判"
        time.sleep(1.5)
    return False, "ticket 校验后仍未在线 (检查账号是否超3设备限制/欠费)"


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
    text = body + " " + headers.get("Location", "")
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
        loc = headers.get("Location", "")
        if "202.118.1.87" in loc or "srun_portal" in loc or "neu.edu.cn" in loc:
            return "hijacked"
        if "top.self.location.href" in body or "202.118.1.87" in body:
            return "hijacked"
        if code == 204 or (code == 200 and headers.get("Date")):
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
    print(f"[*] 链路自检开始 (v{__version__})")
    st = status()
    print(f"    1. 门户在线查询: {'在线 ' + st.get('username', '') if st.get('online') else '不在线(未登录状态,正常)'}")
    sso = get_sso_redirect()
    redirect = sso.get("Redirect", "")
    ok2 = redirect.startswith("https://pass.neu.edu.cn")
    print(f"    2. SSO入口获取: {'OK' if ok2 else '失败: ' + str(sso)[:80]}")
    ok3 = False
    if redirect:
        opener, _ = make_opener()
        _, body, _ = fetch(opener, redirect)
        ok3 = 'name="lt"' in body
        print(f"    3. CAS登录页lt令牌: {'OK' if ok3 else '失败'}")
    n, e = get_rsa_key()
    cipher = rsa_pkcs1v15_encrypt(n, e, b"selftest")
    ok4 = len(cipher) == 256 and base64.b64encode(cipher).decode().endswith("=")
    print(f"    4. RSA加密({n.bit_length()}bit, e={e}): {'OK' if ok4 else '失败'}")
    ok5 = False
    try:
        n2, e2 = get_rsa_key(refresh=True)
        ok5 = n2 == n and e2 == e
        print(f"    5. 公钥在线刷新(防轮换): {'OK, 与内置一致' if ok5 else '公钥已变化, 已缓存新公钥'}")
    except Exception as ex:
        print(f"    5. 公钥在线刷新: 失败 ({ex})")
    all_ok = ok2 and ok3 and ok4
    print(f"[{'+' if all_ok else '!'}] 自检{'通过, 可执行自动登录' if all_ok else '存在异常'}")
    return all_ok


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
    ap.add_argument("--version", action="version", version=f"%(prog)s v{__version__}")
    args = ap.parse_args()

    if args.test:
        sys.exit(0 if self_test() else 1)

    if args.status:
        st = status()
        if st.get("online"):
            print(f"[+] 在线: {st['username']}  IP: {st['ip']}")
            print(f"    登录时间: {st['login_time']}")
            print(f"    账号累计流量: {st['traffic_bytes']/1024/1024:.1f}MB")
        else:
            print("[-] 当前不在线")
        return

    if args.logout:
        print(f"[*] {logout()}")
        return

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
            sys.exit(0 if ok else 1)
        return

    cred = None
    if args.username and args.password:
        cred = {"username": args.username, "password": args.password}
        if args.save:
            save_credentials(args.username, args.password)
    else:
        cred = load_credentials()
        if not cred:
            ap.error("请提供 -u 学号 -p 密码, 或先用 --save 保存凭据")

    if args.watch:
        print(f"[*] 断线守护模式 v{__version__} (Ctrl+C 退出), 每15秒检测")
        while True:
            try:
                st = status()
                if st.get("online"):
                    # 双重校验: 账面在线 + 真实联网, 捕获幽灵会话
                    if probe_internet() == "hijacked":
                        print(f"[{time.strftime('%H:%M:%S')}] 幽灵会话! 重建...")
                        ok, msg = login(cred["username"], cred["password"])
                        print(f"[{time.strftime('%H:%M:%S')}] {'[+]' if ok else '[!]'} {msg}")
                    else:
                        print(f"[{time.strftime('%H:%M:%S')}] 在线: {st['username']}")
                else:
                    print(f"[{time.strftime('%H:%M:%S')}] 掉线! 重连...")
                    if wait_portal():
                        ok, msg = login(cred["username"], cred["password"])
                        print(f"[{time.strftime('%H:%M:%S')}] {'[+]' if ok else '[!]'} {msg}")
                    else:
                        print(f"[{time.strftime('%H:%M:%S')}] 门户不可达, 继续等待")
                time.sleep(15)
            except KeyboardInterrupt:
                print("\n[*] 退出守护模式")
                return
    else:
        print(f"[*] NEU 自动登录 v{__version__}")
        ok, msg = login(cred["username"], cred["password"])
        print(f"{'[+]' if ok else '[!]'} {msg}")
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
