#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
"""P0-3 安全修复离线回归测试 (CPython 上运行, 假 ssl 模块桩, 不联网)

覆盖:
  * _ssl_wrap 默认设置 CERT_REQUIRED 并传入 CA_CERT_PEM (cadata)
  * 证书校验失败时异常向上抛, 绝不降级为 CERT_NONE / 无校验 wrap
  * 固件 TLS API 不可用时抛清晰异常 (含升级 MicroPython 提示)
  * 旧固件 ssl.wrap_socket(cert_reqs=..., cadata=...) 回退仍是校验模式
  * ALLOW_INSECURE_TLS 仅布尔 True 才生效; 生效时每次建连都打印 WARNING
  * ALLOW_INSECURE_TLS=True 时 get_key(refresh=True) 被拒绝
  * TLS 未处于校验模式时 get_key(refresh=True) 被拒绝
  * ensure_online 遇异常返回 (False, msg), 永不抛
  * 内联 CA_CERT_PEM 可被 CPython ssl 解析, 主体摘要正确

运行 (不联网, 无需凭据):
    python test_p0_esp32.py       # 直接运行
    pytest test_p0_esp32.py       # 也可用 pytest
"""

import contextlib
import io
import os
import ssl as _real_ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import neu_login_esp32 as m

_REDIRECT = ("https://pass.neu.edu.cn/tpass/login?service="
             "http%3A%2F%2Fipgw.neu.edu.cn%2Fsrun_portal_sso")


# ---------- 显式断言辅助 (不依赖 python -O 下会被剥离的 assert) ----------

def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _eq(got, want, what):
    if got != want:
        raise AssertionError("%s: 期望 %r, 实际 %r" % (what, want, got))


def _raises(fn, exc_type):
    """执行 fn 并期望抛 exc_type; 未抛/抛错类型都算测试失败"""
    try:
        fn()
    except exc_type as ex:
        return ex
    except Exception as ex:
        raise AssertionError("期望 %s, 实际抛 %s: %r"
                             % (exc_type.__name__, type(ex).__name__, ex))
    raise AssertionError("期望 %s, 但未抛异常" % exc_type.__name__)


@contextlib.contextmanager
def _patched(module, **attrs):
    """临时替换模块属性 (无论成败都恢复), 用于假模块/桩函数注入"""
    missing = object()
    old = {}
    try:
        for k, v in attrs.items():
            old[k] = getattr(module, k, missing)
            setattr(module, k, v)
        yield
    finally:
        for k, v in old.items():
            if v is missing:
                try:
                    delattr(module, k)
                except AttributeError:
                    pass
            else:
                setattr(module, k, v)


# ---------- 假 ssl / socket / HTTPClient 桩 ----------

class _FakeTLSSock:
    """假 TLS socket"""

    def __init__(self, tag):
        self.tag = tag
        self.closed = False

    def close(self):
        self.closed = True


class _FakeCtx:
    """假 SSLContext: 记录 verify_mode / cadata / wrap_socket 参数"""

    def __init__(self, proto, parent):
        self.proto = proto
        self.parent = parent
        self.verify_mode = None
        self.check_hostname = None
        self.loaded_cadata = None
        self.wrap_args = None

    def load_verify_locations(self, cadata=None):
        self.loaded_cadata = cadata

    def wrap_socket(self, sock, server_hostname=None):
        self.wrap_args = (sock, server_hostname)
        if self.parent.wrap_error is not None:
            raise self.parent.wrap_error
        return self.parent.tls_sock


class _FakeSSLNew:
    """假 ssl 模块 (新固件): 有 SSLContext + PROTOCOL_TLS_CLIENT"""

    CERT_NONE = "CERT_NONE"
    CERT_REQUIRED = "CERT_REQUIRED"
    PROTOCOL_TLS_CLIENT = "PROTOCOL_TLS_CLIENT"

    class SSLError(Exception):
        pass

    def __init__(self):
        self.contexts = []
        self.legacy_calls = []
        self.wrap_error = None
        self.tls_sock = _FakeTLSSock("verified")

    def SSLContext(self, proto):
        ctx = _FakeCtx(proto, self)
        self.contexts.append(ctx)
        return ctx

    def wrap_socket(self, *args, **kwargs):
        self.legacy_calls.append((args, kwargs))
        return _FakeTLSSock("legacy")


class _FakeSSLOld:
    """假 ssl 模块 (旧固件): 无 SSLContext, 只有 ssl.wrap_socket"""

    CERT_NONE = "CERT_NONE"
    CERT_REQUIRED = "CERT_REQUIRED"

    def __init__(self, raise_type_error=False):
        self.calls = []
        self.raise_type_error = raise_type_error
        self.tls_sock = _FakeTLSSock("legacy-verified")

    def wrap_socket(self, sock, **kwargs):
        self.calls.append((sock, kwargs))
        if self.raise_type_error:
            raise TypeError("unexpected keyword argument 'cadata'")
        return self.tls_sock


class _FakeClient:
    """假 HTTPClient: 记录请求并返回预设响应, 不联网"""

    def __init__(self, status=200, headers=None, data=b""):
        self.status = status
        self.headers = headers or {}
        self.data = data
        self.calls = []

    def request(self, url, **kwargs):
        self.calls.append(url)
        return self.status, self.headers, self.data


# ---------- 内联 CA 证书 ----------

def test_ca_pem_inline_format():
    pem = m.CA_CERT_PEM
    _eq(pem.count("-----BEGIN CERTIFICATE-----"), 2, "CA 证书块数")
    _eq(pem.count("-----END CERTIFICATE-----"), 2, "CA END 块数")
    _check(pem.startswith("-----BEGIN CERTIFICATE-----"),
           "CA_CERT_PEM 应以 BEGIN CERTIFICATE 开头")
    _check(pem.rstrip().endswith("-----END CERTIFICATE-----"),
           "CA_CERT_PEM 应以 END CERTIFICATE 结尾")
    _check("\r" not in pem, "源码内联 PEM 应统一为 LF 换行")
    _check(len(pem) > 2800, "CA_CERT_PEM 长度异常: %d" % len(pem))


def test_ca_pem_parsed_by_cpython_ssl():
    # 纯本地解析 (不建连接/不联网), 证明内联 PEM 真实可用
    ctx = _real_ssl.SSLContext(_real_ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=m.CA_CERT_PEM)
    stats = ctx.cert_store_stats()
    _eq(stats.get("x509_ca"), 2, "CPython ssl 应加载 2 张 CA 证书")


def test_ca_subject_summary():
    subs = m._ca_subjects()
    _eq(len(subs), 2, "CA 主体数量")
    joined = " / ".join(subs)
    _check("GlobalSign GCC R3 DV TLS CA 2020" in joined,
           "缺少中间证书主体: " + joined)
    _check("GlobalSign" in subs[1], "根证书主体异常: " + joined)


def test_tls_mode_string():
    with _patched(m, ALLOW_INSECURE_TLS=False):
        _eq(m._tls_mode(), "verified", "默认 TLS 模式")
    with _patched(m, ALLOW_INSECURE_TLS=True):
        _eq(m._tls_mode(), "INSECURE", "逃生阀 TLS 模式")


# ---------- _ssl_wrap: 默认强制校验证书 ----------

def test_ssl_wrap_default_verifies_cert_and_passes_cadata():
    fake = _FakeSSLNew()
    raw = object()
    with _patched(m, ssl=fake, ALLOW_INSECURE_TLS=False, _TLS_VERIFIED=False):
        tls = m._ssl_wrap(raw, "pass.neu.edu.cn")
        verified = m._TLS_VERIFIED
    _eq(len(fake.contexts), 1, "应创建一个 SSLContext")
    ctx = fake.contexts[0]
    _eq(ctx.proto, "PROTOCOL_TLS_CLIENT", "应使用 PROTOCOL_TLS_CLIENT")
    _eq(ctx.verify_mode, "CERT_REQUIRED", "verify_mode 必须是 CERT_REQUIRED")
    _eq(ctx.check_hostname, True, "必须开启主机名校验")
    _eq(ctx.loaded_cadata, m.CA_CERT_PEM, "必须把 CA_CERT_PEM 作为 cadata 传入")
    _eq(ctx.wrap_args, (raw, "pass.neu.edu.cn"), "wrap_socket 参数")
    _eq(fake.legacy_calls, [], "默认路径不应调用 ssl.wrap_socket")
    _check(verified is True, "校验建连成功后 _TLS_VERIFIED 应为 True")
    _eq(tls.tag, "verified", "应返回 SSLContext.wrap_socket 的结果")


def test_ssl_wrap_verify_failure_raises_no_downgrade():
    fake = _FakeSSLNew()
    fake.wrap_error = _FakeSSLNew.SSLError("certificate verify failed")
    with _patched(m, ssl=fake, ALLOW_INSECURE_TLS=False, _TLS_VERIFIED=False):
        err = _raises(lambda: m._ssl_wrap(object(), "pass.neu.edu.cn"),
                      _FakeSSLNew.SSLError)
        verified = m._TLS_VERIFIED
    _check("certificate verify failed" in str(err),
           "应保留原始证书校验错误: %r" % err)
    _eq(fake.legacy_calls, [], "校验失败绝不能回退到不校验 API")
    _check(verified is False, "校验失败后 _TLS_VERIFIED 必须为 False")


def test_ssl_wrap_clear_error_when_no_verified_api():
    # 旧固件: 既无 SSLContext, ssl.wrap_socket 也不支持 cadata
    fake = _FakeSSLOld(raise_type_error=True)
    with _patched(m, ssl=fake, ALLOW_INSECURE_TLS=False, _TLS_VERIFIED=False):
        err = _raises(lambda: m._ssl_wrap(object(), "pass.neu.edu.cn"),
                      RuntimeError)
        verified = m._TLS_VERIFIED
    msg = str(err)
    _check("请升级 MicroPython 固件或配置 CA" in msg,
           "异常必须含明确升级提示: " + msg)
    _eq(len(fake.calls), 1, "旧 API 只应尝试一次")
    _, kwargs = fake.calls[0]
    _eq(kwargs.get("cert_reqs"), "CERT_REQUIRED", "旧 API 也必须要求校验")
    _eq(kwargs.get("cadata"), m.CA_CERT_PEM, "旧 API 必须传入 CA_CERT_PEM")
    _check(verified is False, "失败后 _TLS_VERIFIED 必须为 False")


def test_ssl_wrap_clear_error_when_context_wrap_api_incompatible():
    # SSLContext 存在但 wrap_socket 签名不兼容: 只报清晰错误, 不得回退重试
    fake = _FakeSSLNew()
    fake.wrap_error = TypeError("unexpected keyword argument 'server_hostname'")
    with _patched(m, ssl=fake, ALLOW_INSECURE_TLS=False, _TLS_VERIFIED=False):
        err = _raises(lambda: m._ssl_wrap(object(), "pass.neu.edu.cn"),
                      RuntimeError)
        verified = m._TLS_VERIFIED
    _check("请升级 MicroPython 固件或配置 CA" in str(err),
           "异常必须含明确升级提示: %r" % err)
    _eq(fake.legacy_calls, [], "API 不兼容时不得回退到旧 API 重试")
    _check(verified is False, "失败后 _TLS_VERIFIED 必须为 False")


def test_ssl_wrap_legacy_firmware_still_verified():
    fake = _FakeSSLOld()
    raw = object()
    with _patched(m, ssl=fake, ALLOW_INSECURE_TLS=False, _TLS_VERIFIED=False):
        tls = m._ssl_wrap(raw, "pass.neu.edu.cn")
        verified = m._TLS_VERIFIED
    _eq(len(fake.calls), 1, "旧固件应调用一次 ssl.wrap_socket")
    sock_arg, kwargs = fake.calls[0]
    _check(sock_arg is raw, "必须包装原始 socket")
    _eq(kwargs.get("cert_reqs"), "CERT_REQUIRED", "旧固件回退也必须是校验模式")
    _eq(kwargs.get("cadata"), m.CA_CERT_PEM, "旧固件回退必须传入 CA_CERT_PEM")
    _eq(kwargs.get("server_hostname"), "pass.neu.edu.cn", "旧固件回退必须带 SNI")
    _check(verified is True, "旧固件校验成功应置 _TLS_VERIFIED=True")
    _eq(tls.tag, "legacy-verified", "返回值")


# ---------- ALLOW_INSECURE_TLS 逃生阀 ----------

def test_insecure_mode_only_by_literal_true():
    # 非布尔真值 (如 1) 不得关闭校验: 只认显式的布尔 True
    fake = _FakeSSLNew()
    with _patched(m, ssl=fake, ALLOW_INSECURE_TLS=1, _TLS_VERIFIED=False):
        m._ssl_wrap(object(), "pass.neu.edu.cn")
    _eq(fake.contexts[0].verify_mode, "CERT_REQUIRED",
        "ALLOW_INSECURE_TLS 只认布尔 True, 传 1 仍须校验证书")


def test_insecure_mode_sets_cert_none_and_warns_each_connect():
    fake = _FakeSSLNew()
    out = io.StringIO()
    with _patched(m, ssl=fake, ALLOW_INSECURE_TLS=True, _TLS_VERIFIED=False):
        with contextlib.redirect_stdout(out):
            m._ssl_wrap(object(), "pass.neu.edu.cn")
            m._ssl_wrap(object(), "pass.neu.edu.cn")
        verified = m._TLS_VERIFIED
    _eq(len(fake.contexts), 2, "应建立两次 TLS 连接")
    for ctx in fake.contexts:
        _eq(ctx.verify_mode, "CERT_NONE", "INSECURE 模式 verify_mode 应为 CERT_NONE")
        _eq(ctx.check_hostname, False, "INSECURE 模式应关闭主机名校验")
    text = out.getvalue()
    _eq(text.count("WARNING"), 2, "每次建连都必须打印警告")
    _check("ALLOW_INSECURE_TLS" in text, "警告需点名 ALLOW_INSECURE_TLS: " + text)
    _check(verified is False, "INSECURE 模式 _TLS_VERIFIED 必须为 False")


# ---------- get_key 公钥在线刷新门禁 ----------

def test_get_key_refresh_rejected_when_insecure():
    client = _FakeClient()
    with _patched(m, ALLOW_INSECURE_TLS=True, _TLS_VERIFIED=False, _KEY_CACHE=None):
        err = _raises(lambda: m.get_key(client, refresh=True), RuntimeError)
    _eq(client.calls, [], "不校验模式下不得发起公钥在线拉取")
    _check("公钥在线刷新已禁用" in str(err),
           "错误信息应说明刷新被禁用: %r" % err)


def test_get_key_refresh_rejected_when_tls_not_verified():
    client = _FakeClient()
    with _patched(m, ALLOW_INSECURE_TLS=False, _TLS_VERIFIED=False, _KEY_CACHE=None):
        err = _raises(lambda: m.get_key(client, refresh=True), RuntimeError)
    _eq(client.calls, [], "TLS 未校验时不得在线拉取公钥")
    _check("未处于校验证书模式" in str(err),
           "错误信息应说明 TLS 未校验: %r" % err)


def test_get_key_refresh_allowed_only_when_verified():
    body = (b'var x = 1;\nvar publicKeyStr = "'
            + m.PUBKEY_B64.encode() + b'";\n')
    client = _FakeClient(data=body)
    with _patched(m, ALLOW_INSECURE_TLS=False, _TLS_VERIFIED=True, _KEY_CACHE=None):
        n, e = m.get_key(client, refresh=True)
    _eq(client.calls, [m.CAS_JS_URL], "校验证书链路生效时应允许拉取 login_neu.js")
    _eq(e, 65537, "公钥 e")
    _check(n.bit_length() == 2048, "公钥应为 RSA-2048, 实际 %d bit" % n.bit_length())


def test_get_key_default_offline_builtin():
    with _patched(m, ALLOW_INSECURE_TLS=False, _KEY_CACHE=None):
        n, e = m.get_key()
    _eq(e, 65537, "内置公钥 e")
    _check(n.bit_length() == 2048, "内置公钥应为 RSA-2048")


def test_login_key_rotated_message_when_insecure():
    # KEY_ROTATED 且 INSECURE 模式: 明确报错要求手动更新 PUBKEY_B64, 不尝试刷新
    with _patched(
            m,
            ALLOW_INSECURE_TLS=True,
            _TLS_VERIFIED=False,
            check_online=lambda client=None: None,
            detect_ac_id=lambda client=None: None,
            get_sso_redirect=lambda client=None: _REDIRECT,
            fix_service_url=lambda redirect: redirect,
            cas_login=lambda *a, **k: (None, "KEY_ROTATED")):
        ok, msg = m.login("20260001", "secret")
    _check(ok is False, "KEY_ROTATED 且禁用刷新时登录应失败")
    _check("key-rotated" in msg, "错误码应可识别: " + msg)
    _check("PUBKEY_B64" in msg, "应提示手动更新 PUBKEY_B64: " + msg)


# ---------- ensure_online 永不抛异常 ----------

def test_ensure_online_returns_false_when_check_raises():
    def boom(client=None):
        raise RuntimeError("network down")

    with _patched(m, check_online=boom):
        ok, msg = m.ensure_online("u", "p")
    _check(ok is False, "check_online 抛异常时应返回 False")
    _check("network down" in msg, "错误信息应包含原因: " + msg)


def test_ensure_online_returns_false_when_login_raises():
    def boom(u, p):
        raise ValueError("parse err")

    with _patched(m, check_online=lambda client=None: None, login=boom):
        ok, msg = m.ensure_online("u", "p")
    _check(ok is False, "login 抛异常时应返回 False")
    _check("parse err" in msg, "错误信息应包含原因: " + msg)


def test_ensure_online_returns_false_on_memoryerror():
    def oom(client=None):
        raise MemoryError()

    with _patched(m, check_online=oom):
        ok, msg = m.ensure_online("u", "p")
    _check(ok is False, "MemoryError 也应被收敛为 (False, msg)")
    _check("MemoryError" in msg, "应返回 OOM 提示: " + msg)


# ---------- P0-4: SSO 跳转白名单 (ESP32 版) ----------

def test_cas_redirect_whitelist_rejects_attack_urls():
    bad = [
        "http://attacker.example/tpass/login?service=x",                  # 非 https
        "https://evil.example/tpass/login?service=x",                     # 非白名单域名
        "https://pass.neu.edu.cn@evil.example/tpass/login?service=x",      # userinfo 伪装
        "https://pass.neu.edu.cn:8443/tpass/login?service=x",              # 非标准端口
        "https://pass.neu.edu.cn:abc/tpass/login?service=x",               # 非法端口
        "https://pass.neu.edu.cn./tpass/login?service=x",                  # 尾点
        "", None,
    ]
    for url in bad:
        try:
            m._validate_cas_redirect(url)
        except ValueError:
            continue
        raise AssertionError("应拒绝 Redirect: %r" % (url,))
    m._validate_cas_redirect(_REDIRECT)          # 合法地址不抛


def test_ticket_url_whitelist():
    bad = [
        "http://attacker.example/v1/srun_portal_sso?ticket=x",
        "http://ipgw.neu.edu.cn/v1/srun_portal_sso",          # 无 ticket
        "https://pass.neu.edu.cn/v1/srun_portal_sso?ticket=x",  # 非门户主机
        "http://ipgw.neu.edu.cn:8080/v1/srun_portal_sso?ticket=x",
    ]
    for url in bad:
        try:
            m._validate_ticket_url(url)
        except ValueError:
            continue
        raise AssertionError("应拒绝 ticket 回跳: %r" % (url,))
    m._validate_ticket_url("http://ipgw.neu.edu.cn/v1/srun_portal_sso?ticket=ST-1&ac_id=16")


def test_login_rejects_foreign_redirect_before_cas():
    calls = []

    def fake_cas(*a, **k):
        calls.append(1)
        return None, "CAS-fail"

    with _patched(m,
                  check_online=lambda client=None: None,
                  detect_ac_id=lambda client=None: None,
                  get_sso_redirect=lambda client=None: "http://attacker.example/tpass/login?service=x",
                  cas_login=fake_cas):
        ok, msg = m.login("u", "p")
    _check(ok is False, "非法 Redirect 必须登录失败")
    _check("sso-reject" in msg, "应返回 sso-reject: " + msg)
    _check("中间人" in msg, "应说明疑似中间人: " + msg)
    _check(not calls, "非法 Redirect 时不得发起任何 CAS 请求(不能把密文发出去)")


def test_login_accepts_legit_redirect():
    calls = []

    def fake_cas(*a, **k):
        calls.append(1)
        return None, "CAS-fail"

    with _patched(m,
                  check_online=lambda client=None: None,
                  detect_ac_id=lambda client=None: None,
                  get_sso_redirect=lambda client=None: _REDIRECT,
                  cas_login=fake_cas):
        ok, msg = m.login("u", "p")
    _check(ok is False and msg == "CAS-fail", "合法 Redirect 应继续到 CAS 阶段: %r" % ((ok, msg),))
    _eq(len(calls), 1, "CAS 调用次数")


def test_verified_wrap_requires_server_hostname():
    _raises(lambda: m._ssl_wrap_verified(_FakeTLSSock("raw"), ""), RuntimeError)


def test_old_api_fallback_passes_server_hostname():
    fake = _FakeSSLOld()
    with _patched(m, ssl=fake):
        m._ssl_wrap_verified(_FakeTLSSock("raw"), "pass.neu.edu.cn")
    _eq(len(fake.calls), 1, "旧 API 调用次数")
    kwargs = fake.calls[0][1]
    _eq(kwargs.get("server_hostname"), "pass.neu.edu.cn",
        "旧 API 必须传 server_hostname(否则主机名不被校验)")
    _eq(kwargs.get("cert_reqs"), fake.CERT_REQUIRED, "旧 API 必须 CERT_REQUIRED")
    _check(kwargs.get("cadata") == m.CA_CERT_PEM, "旧 API 必须带内置 CA")


def test_refresh_disabled_even_if_tls_verified_when_insecure():
    # P3-4: ALLOW_INSECURE_TLS=True 且 _TLS_VERIFIED=True 的组合也必须拒绝刷新
    with _patched(m, ALLOW_INSECURE_TLS=True, _TLS_VERIFIED=True, _KEY_CACHE=None):
        _raises(lambda: m.get_key(client=object(), refresh=True), RuntimeError)


def main():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for name, t in tests:
        try:
            t()
            print("[+] %s" % name)
        except AssertionError as ex:
            failed += 1
            print("[-] %s: %s" % (name, ex))
        except Exception as ex:
            failed += 1
            print("[!] %s: %r" % (name, ex))
    print("\n%d/%d 通过" % (len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
