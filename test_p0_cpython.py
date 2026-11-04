#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
"""P0 回归测试 (离线, 不联网, 不需要凭据)

覆盖:
  P0-1 网络异常收敛: fetch -> PortalError/TLSError, login() 永不抛, --watch 不退出
  P0-2 认证失败分类与退避: auth/transient/config, 认证失败守卫, 限流, 退出码
  P0-4 SSO 跳转白名单: 非 pass.neu.edu.cn 的 Redirect 一律中止, 不发送凭据
  P1-1 证书错误不再自动降级为 verify=False

运行: python test_p0_cpython.py
"""

import contextlib
import io
import os
import ssl
import sys
import tempfile
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import neu_login

LEGIT_REDIRECT = ("https://pass.neu.edu.cn/tpass/login?service="
                  "http%3A%2F%2Fipgw.neu.edu.cn%2Fsrun_portal_sso")
TICKET_URL = "http://ipgw.neu.edu.cn/v1/srun_portal_sso?ticket=ST-1&ac_id=16"

_AUTH_FILE = os.path.join(tempfile.mkdtemp(prefix="neu-p0-"), ".authfail")
neu_login._AUTH_FAIL_FILE = _AUTH_FILE


# ---------- 测试辅助 ----------

@contextlib.contextmanager
def patched(**kw):
    """临时替换 neu_login 模块内属性, 退出时恢复"""
    old = {k: getattr(neu_login, k) for k in kw}
    try:
        for k, v in kw.items():
            setattr(neu_login, k, v)
        yield
    finally:
        for k, v in old.items():
            setattr(neu_login, k, v)


def _offline():
    return {"online": False, "state": "offline"}


def _online():
    return {"online": True, "state": "online", "username": "u1", "ip": "10.0.0.2",
            "login_time": "2026-01-01 00:00:00", "traffic_bytes": 0}


def _quiet():
    return contextlib.redirect_stdout(io.StringIO())


class _Opener:
    def __init__(self, exc):
        self.exc = exc

    def open(self, req, timeout=None):
        raise self.exc


class _FakeHTTPError(urllib.error.HTTPError):
    pass


def _http_error(code=302, body=b""):
    return urllib.error.HTTPError("http://x/", code, "err", {}, io.BytesIO(body))


def _raise_portal(*a, **kw):
    raise neu_login.PortalError("connection reset by peer")


# ---------- P0-1: 网络异常收敛 ----------

def test_fetch_wraps_network_error():
    exc = urllib.error.URLError(ConnectionRefusedError(111, "refused"))
    try:
        neu_login.fetch(_Opener(exc), "http://ipgw.neu.edu.cn/x")
    except neu_login.PortalError as ex:
        if "ipgw.neu.edu.cn" not in str(ex):
            raise AssertionError("异常缺少 URL: %s" % ex)
    else:
        raise AssertionError("网络异常应转为 PortalError, 而不是原样抛出")


def test_fetch_wraps_timeout_as_portal_error():
    try:
        neu_login.fetch(_Opener(TimeoutError("timed out")), "http://x/")
    except neu_login.PortalError:
        return
    raise AssertionError("TimeoutError 应转为 PortalError")


def test_fetch_maps_certificate_error_to_tlse():
    exc = urllib.error.URLError(ssl.SSLError("CERTIFICATE_VERIFY_FAILED"))
    try:
        neu_login.fetch(_Opener(exc), "https://pass.neu.edu.cn/x")
    except neu_login.TLSError as ex:
        if "证书" not in str(ex):
            raise AssertionError("提示应说明证书问题: %s" % ex)
    else:
        raise AssertionError("证书错误应转为 TLSError")


def test_fetch_http_error_still_returns_tuple():
    code, _, _ = neu_login.fetch(_Opener(_http_error(302)), "http://x/")
    if code != 302:
        raise AssertionError("HTTPError 应返回状态码, 实际 %r" % code)


def test_login_never_raises_and_returns_transient():
    portal = neu_login.PortalError("down")
    with patched(status=_offline, detect_ac_id=lambda: None,
                 recent_auth_failure=lambda: False,
                 get_sso_redirect=lambda: (_ for _ in ()).throw(portal)):
        with _quiet():
            ok, msg, kind = neu_login.login("u", "p")
    if ok or kind != "transient" or "down" not in msg:
        raise AssertionError("应返回 transient 且不抛异常: %r" % ((ok, msg, kind),))


def test_login_wraps_unexpected_exception():
    with patched(status=lambda: (_ for _ in ()).throw(RuntimeError("boom"))):
        with _quiet():
            ok, msg, kind = neu_login.login("u", "p")
    if ok or kind != "transient" or "boom" not in msg:
        raise AssertionError("未预期异常应兜底为 transient: %r" % ((ok, msg, kind),))


def test_status_distinguishes_unreachable():
    def boom(*a, **kw):
        raise neu_login.PortalError("no route")

    with patched(fetch=boom):
        st = neu_login.status()
    if st.get("state") != "unreachable" or st.get("online"):
        raise AssertionError("门户不可达应为 unreachable: %r" % st)


def test_status_survives_out_of_range_timestamp():
    body = "u1,999999999999999999999999999999,0,1024,0,0,0,0,10.0.0.2,x"
    with patched(fetch=lambda *a, **kw: (200, body, {})):
        st = neu_login.status()
    if st.get("online") or st.get("state") != "unreachable":
        raise AssertionError("异常时间戳不应抛异常, 应为 unreachable: %r" % st)


# ---------- P0-2: 分类 / 守卫 / 限流 / 退避 ----------

def test_login_classifies_wrong_credentials_as_auth():
    neu_login.clear_auth_failure()
    with patched(status=_offline, detect_ac_id=lambda: None,
                 get_sso_redirect=lambda: {"Redirect": LEGIT_REDIRECT},
                 cas_login=lambda *a, **kw: (None, "auth", "用户名或密码错误")):
        with _quiet():
            ok, msg, kind = neu_login.login("u", "p")
    if ok or kind != "auth" or "密码" not in msg:
        raise AssertionError("密码错误应分类为 auth: %r" % ((ok, msg, kind),))
    if not neu_login.recent_auth_failure():
        raise AssertionError("认证被拒后应写入失败守卫")
    neu_login.clear_auth_failure()


def test_auth_guard_blocks_cas_attempts():
    neu_login.mark_auth_failure()
    calls = []

    def counting_fetch(*a, **kw):
        calls.append(1)
        return (200, "", {})

    try:
        with patched(status=_offline, fetch=counting_fetch):
            with _quiet():
                ok, msg, kind = neu_login.login("u", "p")
        if ok or kind != "auth" or calls:
            raise AssertionError("守卫生效时不应发起任何请求: %r %r" % ((ok, kind), calls))
    finally:
        neu_login.clear_auth_failure()


def test_auth_guard_expires():
    neu_login.mark_auth_failure()
    try:
        path = neu_login._auth_state_file()
        with open(path, "w", encoding="utf-8") as f:
            f.write("0")                       # 很久以前
        if neu_login.recent_auth_failure():
            raise AssertionError("过期守卫不应生效")
    finally:
        neu_login.clear_auth_failure()


def test_rate_limiter():
    lim = neu_login._RateLimiter(3, 600)
    if not all(lim.allow(now=100) for _ in range(3)):
        raise AssertionError("前 3 次应放行")
    if lim.allow(now=100):
        raise AssertionError("第 4 次应被限流")
    if lim.next_wait(now=100) <= 0:
        raise AssertionError("限流时应给出等待时间")
    if not lim.allow(now=800):
        raise AssertionError("窗口过后应重新放行")


def test_exit_code_mapping():
    if neu_login._exit_code("ok") != neu_login.EXIT_OK:
        raise AssertionError("ok -> 0")
    if neu_login._exit_code("transient") != neu_login.EXIT_TRANSIENT:
        raise AssertionError("transient -> 2")
    for kind in ("auth", "config"):
        if neu_login._exit_code(kind) != neu_login.EXIT_AUTH:
            raise AssertionError("%s -> 3" % kind)


def test_watch_loop_exits_on_auth_failure():
    sleeps = []

    def fake_sleep(sec):
        sleeps.append(sec)
        raise KeyboardInterrupt

    with patched(status=_offline, wait_portal=lambda: True,
                 login=lambda u, p: (False, "凭据被拒", "auth")):
        with _quiet():
            code = neu_login.watch_loop({"username": "u", "password": "p"}, sleep=fake_sleep)
    if code != neu_login.EXIT_AUTH:
        raise AssertionError("认证失败应停止守护并返回 3, 实际 %r" % code)
    if sleeps:
        raise AssertionError("认证失败后不应再 sleep 重试: %r" % sleeps)


def test_watch_loop_backs_off_and_survives_network_errors():
    sleeps = []

    def fake_sleep(sec):
        sleeps.append(sec)
        if len(sleeps) > 2:
            raise KeyboardInterrupt

    with patched(status=lambda: {"online": False, "state": "unreachable", "error": "down"},
                 wait_portal=lambda: True,
                 login=lambda u, p: (False, "网络不可达", "transient")):
        with _quiet():
            code = neu_login.watch_loop({"username": "u", "password": "p"}, sleep=fake_sleep)
    if code != neu_login.EXIT_OK:
        raise AssertionError("KeyboardInterrupt 应优雅退出, 实际 %r" % code)
    if sleeps[:2] != [15, 30]:
        raise AssertionError("应指数退避 15 -> 30, 实际 %r" % sleeps)


def test_watch_loop_survives_unexpected_exception():
    sleeps = []

    def fake_sleep(sec):
        sleeps.append(sec)
        if len(sleeps) > 1:
            raise KeyboardInterrupt

    with patched(status=_offline, wait_portal=lambda: True,
                 login=lambda u, p: (_ for _ in ()).throw(RuntimeError("boom"))):
        with _quiet():
            code = neu_login.watch_loop({"username": "u", "password": "p"}, sleep=fake_sleep)
    if code != neu_login.EXIT_OK or len(sleeps) < 2:
        raise AssertionError("异常不应杀死守护: %r %r" % (code, sleeps))


# ---------- P0-4: SSO 白名单 ----------

def test_redirect_whitelist_rejects_attack_urls():
    bad = [
        "http://attacker.example/tpass/login?service=x",                 # 非 https
        "https://evil.example/tpass/login?service=x",                   # 非白名单域名
        "https://pass.neu.edu.cn@evil.example/tpass/login?service=x",    # userinfo 伪装
        "https://pass.neu.edu.cn:8443/tpass/login?service=x",            # 非标准端口
        "", None, "ftp://pass.neu.edu.cn/tpass/login?service=x",
    ]
    for url in bad:
        try:
            neu_login._validate_cas_redirect(url)
        except neu_login.SSOValidationError:
            continue
        raise AssertionError("应拒绝: %r" % (url,))


def test_login_aborts_before_cas_on_bad_redirect():
    called = []

    def fake_cas(*a, **kw):
        called.append(1)
        return (TICKET_URL, None, None)

    with patched(status=_offline, detect_ac_id=lambda: None,
                 get_sso_redirect=lambda: {"Redirect": "http://attacker.example/tpass/login?service=x"},
                 cas_login=fake_cas):
        with _quiet():
            ok, msg, kind = neu_login.login("u", "p")
    if ok or kind != "auth" or called:
        raise AssertionError("非法 Redirect 应在 CAS 前中止且分类 auth: %r %r" % ((ok, kind), called))
    if "中间人" not in msg:
        raise AssertionError("提示应含安全原因: %r" % msg)


def test_login_accepts_legit_redirect():
    status_calls = {"n": 0}

    def fake_status():
        status_calls["n"] += 1
        return _offline() if status_calls["n"] == 1 else _online()

    with patched(status=fake_status, detect_ac_id=lambda: None,
                 get_sso_redirect=lambda: {"Redirect": LEGIT_REDIRECT},
                 cas_login=lambda *a, **kw: (TICKET_URL, None, None),
                 complete_sso=lambda url: ({}, None, None),
                 probe_internet=lambda *a, **kw: "ok"):
        with _quiet():
            ok, msg, kind = neu_login.login("u", "p")
    if not ok or kind != "ok" or "登录成功" not in msg:
        raise AssertionError("合法跳转应能完成登录: %r" % ((ok, msg, kind),))


def test_validate_ticket_url_rejects_foreign_host():
    bad = ["http://attacker.example/v1/srun_portal_sso?ticket=x",
           "http://ipgw.neu.edu.cn/v1/srun_portal_sso",
           "https://pass.neu.edu.cn/v1/srun_portal_sso?ticket=x"]
    for url in bad:
        try:
            neu_login._validate_ticket_url(url)
        except neu_login.SSOValidationError:
            continue
        raise AssertionError("应拒绝 ticket 回跳: %r" % (url,))
    neu_login._validate_ticket_url(TICKET_URL)          # 合法地址不抛


# ---------- P1-1: 证书错误不再自动降级 ----------

def test_cert_error_does_not_downgrade_verify():
    opener_verify = []

    def fake_make_opener(verify=None):
        opener_verify.append(verify)
        return (object(), [])

    def fake_inner(*a, **kw):
        raise neu_login.TLSError("TLS 握手或证书校验失败: CERTIFICATE_VERIFY_FAILED")

    with patched(make_opener=fake_make_opener, _cas_login_inner=fake_inner,
                 status=_offline, detect_ac_id=lambda: None,
                 get_sso_redirect=lambda: {"Redirect": LEGIT_REDIRECT}):
        with _quiet():
            ok, msg, kind = neu_login.login("u", "p")
    if ok or kind != "transient" or "证书" not in msg:
        raise AssertionError("证书错误应按网络类失败退避重试(等 NTP 自愈): %r" % ((ok, msg, kind),))
    if False in opener_verify:
        raise AssertionError("证书错误后不应再以 verify=False 重试: %r" % opener_verify)


def test_cert_verification_error_only_matches_real_cert_failure():
    if not neu_login._is_cert_verify_error(
            urllib.error.URLError(ssl.SSLError("CERTIFICATE_VERIFY_FAILED"))):
        raise AssertionError("真实证书校验失败应被识别")
    if neu_login._is_cert_verify_error(urllib.error.URLError(ssl.SSLError("handshake timeout"))):
        raise AssertionError("普通 TLS 握手错误不应被当成证书失败")


def test_device_limit_kind_does_not_write_auth_guard():
    neu_login.clear_auth_failure()
    with patched(status=_offline, detect_ac_id=lambda: None,
                 get_sso_redirect=lambda: {"Redirect": LEGIT_REDIRECT},
                 cas_login=lambda *a, **kw: (TICKET_URL, None, None),
                 complete_sso=lambda url: ({"error": "E2620"}, "limit", "设备超限")):
        with _quiet():
            ok, msg, kind = neu_login.login("u", "p")
    if ok or kind != "limit":
        raise AssertionError("E2620 应分类为 limit: %r" % ((ok, msg, kind),))
    if neu_login.recent_auth_failure():
        raise AssertionError("设备数超限不应写 30 分钟凭据冷却(--kick 后应可立即重试)")
    if neu_login._exit_code("limit") != neu_login.EXIT_AUTH:
        raise AssertionError("limit 应映射为非重试退出码 3")


def test_insecure_disables_key_refresh():
    old_verify, old_cache = neu_login.TLS_VERIFY, neu_login._RSA_KEY_CACHE
    neu_login.TLS_VERIFY = False
    try:
        try:
            neu_login.get_rsa_key(refresh=True)
        except RuntimeError as ex:
            if "insecure" not in str(ex) and "禁用" not in str(ex):
                raise AssertionError("错误信息应说明原因: %s" % ex)
        else:
            raise AssertionError("--insecure 下公钥在线刷新必须被禁用")
    finally:
        neu_login.TLS_VERIFY, neu_login._RSA_KEY_CACHE = old_verify, old_cache


def test_key_rotated_under_insecure_returns_config_without_refresh():
    old_verify = neu_login.TLS_VERIFY
    neu_login.TLS_VERIFY = False
    try:
        with patched(status=_offline, detect_ac_id=lambda: None,
                     get_sso_redirect=lambda: {"Redirect": LEGIT_REDIRECT},
                     cas_login=lambda *a, **kw: (None, "key_rotated", "500")):
            with _quiet():
                ok, msg, kind = neu_login.login("u", "p")
    finally:
        neu_login.TLS_VERIFY = old_verify
    if ok or kind != "config" or "insecure" not in msg:
        raise AssertionError("--insecure 下公钥轮换应返回 config 并提示: %r" % ((ok, msg, kind),))


def test_redirect_bad_port_is_validation_error_not_transient():
    for url in ("https://pass.neu.edu.cn:abc/tpass/login?service=x",
                "https://pass.neu.edu.cn:99999/tpass/login?service=x"):
        try:
            neu_login._validate_cas_redirect(url)
        except neu_login.SSOValidationError:
            continue
        raise AssertionError("非法端口应转成 SSOValidationError: %r" % (url,))


def test_auth_guard_falls_back_when_cred_dir_missing():
    import tempfile as _tf
    old_file, old_cred = neu_login._AUTH_FAIL_FILE, neu_login.CRED_FILE
    neu_login._AUTH_FAIL_FILE = None
    neu_login.CRED_FILE = os.path.join(_tf.gettempdir(),
                                       "neu-missing-%d" % os.getpid(), "cred.json")
    try:
        neu_login.clear_auth_failure()
        neu_login.mark_auth_failure()
        if not neu_login.recent_auth_failure():
            raise AssertionError("凭据目录不存在时应回退到临时目录, 否则防锁号守卫 fail-open")
    finally:
        neu_login.clear_auth_failure()
        neu_login._AUTH_FAIL_FILE, neu_login.CRED_FILE = old_file, old_cred


def test_hget_is_case_insensitive():
    if neu_login._hget({"location": "x"}, "Location") != "x":
        raise AssertionError("小写 location 头应能读到")
    if neu_login._hget({"Location": "y"}, "location") != "y":
        raise AssertionError("大写 Location 头应能读到")
    if neu_login._hget({}, "Location", "d") != "d":
        raise AssertionError("缺失头应返回默认值")


def test_fetch_wraps_http_protocol_exception():
    import http.client as _hc

    class _BadOpener:
        def open(self, req, timeout=None):
            raise _hc.IncompleteRead(b"partial")

    try:
        neu_login.fetch(_BadOpener(), "http://x/")
    except neu_login.PortalError:
        return
    raise AssertionError("http.client.HTTPException 应收敛为 PortalError")


def test_watch_resets_interval_after_recovery():
    sleeps = []
    calls = {"n": 0}

    def fake_status():
        calls["n"] += 1
        return _offline() if calls["n"] <= 2 else _online()

    def fake_sleep(sec):
        sleeps.append(sec)
        if len(sleeps) >= 4:
            raise KeyboardInterrupt

    with patched(status=fake_status, wait_portal=lambda: True,
                 login=lambda u, p: (False, "网络不可达", "transient"),
                 probe_internet=lambda *a, **kw: "ok"):
        with _quiet():
            code = neu_login.watch_loop({"username": "u", "password": "p"}, sleep=fake_sleep)
    if code != neu_login.EXIT_OK:
        raise AssertionError("应优雅退出, 实际 %r" % code)
    if sleeps[:3] != [15, 30, 15]:
        raise AssertionError("恢复在线后应复位退避 15, 实际 %r" % sleeps)


def test_cli_test_failure_exit_code():
    with patched(self_test=lambda: False):
        code = _run_main(["--test"])
    if code != 1:
        raise AssertionError("--test 自检失败应以 1 退出, 实际 %r" % code)


def test_cli_kick_success_clears_auth_guard():
    neu_login.mark_auth_failure()
    try:
        with patched(load_credentials=lambda: {"username": "u", "password": "p"},
                     kick_device=lambda u, p, ip: {"error": "ok"}):
            code = _run_main(["--kick", "10.0.0.9"])
        if code != neu_login.EXIT_OK:
            raise AssertionError("踢设备成功应返回 0, 实际 %r" % code)
        if neu_login.recent_auth_failure():
            raise AssertionError("--kick 成功后应解除凭据冷却")
    finally:
        neu_login.clear_auth_failure()


# ---------- CLI 退出码 ----------

def _run_main(argv):
    old = sys.argv
    sys.argv = ["neu_login.py"] + argv
    try:
        with _quiet():
            neu_login.main()
    except SystemExit as ex:
        return ex.code
    finally:
        sys.argv = old


def test_cli_status_exit_code_for_unreachable_portal():
    with patched(status=lambda: {"online": False, "state": "unreachable", "error": "down"}):
        code = _run_main(["--status"])
    if code != neu_login.EXIT_TRANSIENT:
        raise AssertionError("门户不可达时 --status 应以 2 退出, 实际 %r" % code)


def test_cli_status_exit_code_offline():
    with patched(status=_offline):
        code = _run_main(["--status"])
    if code != neu_login.EXIT_OK:
        raise AssertionError("确实离线时 --status 应以 0 退出, 实际 %r" % code)


def test_cli_auth_failure_exit_code():
    cred_file = os.path.join(tempfile.mkdtemp(prefix="neu-creds-"), "cred.json")
    with open(cred_file, "w", encoding="utf-8") as f:
        f.write('{"username": "u", "password": "p"}')
    try:
        with patched(CRED_FILE=cred_file, status=_offline, detect_ac_id=lambda: None,
                     get_sso_redirect=lambda: {"Redirect": LEGIT_REDIRECT},
                     cas_login=lambda *a, **kw: (None, "auth", "用户名或密码错误")):
            code = _run_main([])
    finally:
        neu_login.clear_auth_failure()
    if code != neu_login.EXIT_AUTH:
        raise AssertionError("凭据被拒时进程应以 3 退出(不重试), 实际 %r" % code)


def main():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
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
