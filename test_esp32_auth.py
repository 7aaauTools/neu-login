#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
"""A24 ESP32 版认证失败退避/冷却 离线测试 (不联网, 不需要凭据)

背景 (A24): 原 ESP32 版认证失败无退避/冷却 —— 错误密码时 run_forever() 每
CHECK_INTERVAL(30s) 就重试一次 CAS(约 120 次/小时), 易触发统一身份认证的
锁号/风控。本次修复:
  * 公共 API 不变: login()->(ok,msg), ensure_online()->(ok,msg)
  * 内部 _login_impl()->(ok,msg,kind), kind ∈ ok/auth/limit/config/transient
  * 凭据被拒(auth) -> AUTH_COOLDOWN_SEC 冷却; E2620(limit) -> LIMIT_COOLDOWN_SEC
  * 冷却期内 _login_impl 开头直接返回, 零 CAS 请求
  * transient 指数退避 _next_backoff(): 30→60→…→MAX_BACKOFF, 成功复位
  * complete_sso() 返回 (kind,msg), E2620=>limit; 成功页收尾失败不致命

运行 (全部离线, 假 HTTPClient/桩):
    python test_esp32_auth.py      # 直接运行 (python -O 下同样通过)
"""

import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import neu_login_esp32 as m

_REDIRECT = ("https://pass.neu.edu.cn/tpass/login?service="
             "http%3A%2F%2Fipgw.neu.edu.cn%2Fsrun_portal_sso")
_TICKET = "http://ipgw.neu.edu.cn/v1/srun_portal_sso?ticket=ST-1&ac_id=16"
_INFO = ["20260001", "t", "0", "0", "0", "0", "0", "0", "10.0.0.1"]


# ---------- 显式断言 (不依赖 -O 下会被剥离的 assert) ----------

def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _eq(got, want, what):
    if got != want:
        raise AssertionError("%s: 期望 %r, 实际 %r" % (what, want, got))


# ---------- 桩 ----------

@contextlib.contextmanager
def _patched(**attrs):
    """临时替换模块属性 (无论成败都恢复), 用于假时间/桩函数注入"""
    missing = object()
    old = {}
    try:
        for k, v in attrs.items():
            old[k] = getattr(m, k, missing)
            setattr(m, k, v)
        yield
    finally:
        for k, v in old.items():
            if v is missing:
                try:
                    delattr(m, k)
                except AttributeError:
                    pass
            else:
                setattr(m, k, v)


class _FakeTime:
    """假 time 模块: 可控时间戳; sleep 只推进时钟, 不真正等待"""

    def __init__(self, now=1000.0):
        self.now = now

    def time(self):
        return self.now

    def sleep(self, secs):
        self.now += secs

    def localtime(self):
        return (2026, 1, 1, 0, 0, 0, 0, 1)


class _Seq:
    """按调用顺序返回预设值 (用完后一直返回最后一个); 记录调用次数"""

    def __init__(self, values):
        self.values = list(values)
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        if not self.values:
            return None
        if len(self.values) > 1:
            return self.values.pop(0)
        return self.values[0]


class _FakeHTTP:
    """假 HTTPClient (complete_sso 用): 按 URL 返回预设响应, 记录请求"""

    def __init__(self, sso=(200, {}, b""), success=(200, {}, b"")):
        self.sso = sso
        self.success = success
        self.calls = []

    def request(self, url, method="GET", body=None, headers=None, timeout=12,
                max_body=40000):
        self.calls.append(url)
        if "srun_portal_sso" in url:
            return self.sso
        return self.success


class _FlakyHTTP:
    """srun_portal_sso 正常, 成功页收尾请求抛异常 (验证"收尾失败不致命")"""

    def __init__(self):
        self.calls = []

    def request(self, url, method="GET", body=None, headers=None, timeout=12,
                max_body=40000):
        self.calls.append(url)
        if "srun_portal_sso" in url:
            return 200, {}, b""
        raise OSError("success page down")


def _boom_http():
    raise AssertionError("冷却期内不应创建 HTTPClient / 发起任何网络请求")


def _clear():
    m._clear_cooldown()


def _login_path(**overrides):
    """构造"离线 + 可走完整 CAS 流程"的默认桩上下文; 用例可覆盖任意项"""
    attrs = {
        "time_ok": lambda: True,
        "get_key": lambda client=None, refresh=False: (3233, 17),
        "check_online": lambda client=None: None,
        "detect_ac_id": lambda client=None: None,
        "get_sso_redirect": lambda client=None: _REDIRECT,
        "fix_service_url": lambda redirect: redirect,
        "cas_login": lambda *a, **k: (None, "CAS-fail"),
    }
    attrs.update(overrides)
    return _patched(**attrs)


# ---------- 常量 / 纯函数: 退避与分类 ----------

def test_cooldown_constants():
    _clear()
    _eq(m.AUTH_COOLDOWN_SEC, 1800, "凭据冷却时长")
    _eq(m.LIMIT_COOLDOWN_SEC, 600, "E2620 冷却时长")
    _eq(m.MAX_BACKOFF, 1800, "退避上限")


def test_next_backoff_sequence_and_cap():
    _eq(m._next_backoff(0), m.CHECK_INTERVAL, "下限: 从 0 应回到 CHECK_INTERVAL")
    seq = [m.CHECK_INTERVAL]
    for _ in range(6):
        seq.append(m._next_backoff(seq[-1]))
    _eq(seq, [30, 60, 120, 240, 480, 960, 1800],
        "暂时性失败退避序列 30→60→…→上限")
    _eq(m._next_backoff(1500), m.MAX_BACKOFF, "超过上限应封顶")
    _eq(m._next_backoff(m.MAX_BACKOFF), m.MAX_BACKOFF, "上限处应保持不变")


def test_fail_kind_classification():
    _clear()
    cases = [
        ("WRONG_CREDENTIAL", "auth"),
        ("CAS: 密码错误", "auth"),
        ("CAS: 账号不存在！", "auth"),
        ("sso-reject:SSO 重定向地址异常(疑似中间人)", "auth"),
        ("sso-reject:ticket-reject:xxx", "auth"),
        ("limit: E2620: 账号在线设备数超限", "limit"),
        ("key-rotated: 需手动更新内置 PUBKEY_B64", "config"),
        ("KEY_ROTATED", "config"),
        ("no-lt(http 200)", "transient"),
        ("no-redirect", "transient"),
        ("no-ticket", "transient"),
        ("bad-ticket-url: x", "transient"),
        ("time-invalid: 设备时间不可用", "transient"),
        ("verify-fail", "transient"),
        ("ghost-after-login", "transient"),
        ("CAS-fail", "transient"),
        ("key-refresh-fail:timeout", "transient"),
        ("", "transient"),
        (None, "transient"),
    ]
    for err, want in cases:
        _eq(m._fail_kind(err), want, "_fail_kind(%r)" % (err,))


def test_cooldown_helpers():
    _clear()
    _eq(m._cooldown_remaining(), 0, "无冷却时剩余应为 0")
    ft = _FakeTime(500.0)
    with _patched(time=ft):
        m._set_cooldown("limit", m.LIMIT_COOLDOWN_SEC)
        _eq(m._COOLDOWN_KIND, "limit", "冷却原因")
        _eq(m._cooldown_remaining(), m.LIMIT_COOLDOWN_SEC, "冷却剩余时长")
        ft.now += m.LIMIT_COOLDOWN_SEC + 5
        _eq(m._cooldown_remaining(), 0, "过期后剩余应为 0")
        m._clear_cooldown()
        _check(m._COOLDOWN_UNTIL is None and m._COOLDOWN_KIND is None,
               "_clear_cooldown 应复位两个模块级状态")
    _clear()


# ---------- 凭据被拒 -> auth + 冷却 ----------

def test_wrong_password_auth_kind_and_cooldown():
    _clear()
    ft = _FakeTime(1000.0)
    cas = _Seq([(None, "WRONG_CREDENTIAL")])
    with _patched(time=ft):
        with _login_path(cas_login=cas):
            ok, msg, kind = m._login_impl("20260001", "wrong")
        _eq(ok, False, "错误密码应登录失败")
        _eq(kind, "auth", "WRONG_CREDENTIAL 应归类 auth")
        _eq(msg, "WRONG_CREDENTIAL", "失败信息应透传")
        _eq(cas.calls, 1, "CAS 调用次数")
        _eq(m._COOLDOWN_KIND, "auth", "应写入 auth 冷却")
        _eq(m._cooldown_remaining(), m.AUTH_COOLDOWN_SEC, "凭据冷却时长")
    _clear()


def test_cas_error_page_is_auth_kind():
    # CAS 返回错误页("CAS: 密码错误") 同样属凭据被拒
    _clear()
    ft = _FakeTime(1000.0)
    with _patched(time=ft):
        with _login_path(cas_login=lambda *a, **k: (None, "CAS: 密码错误")):
            ok, msg, kind = m._login_impl("20260001", "wrong")
        _eq(ok, False, "应失败")
        _eq(kind, "auth", "CAS 错误页应归类 auth")
        _check("密码错误" in msg, "信息透传: " + msg)
        _eq(m._COOLDOWN_KIND, "auth", "应写入 auth 冷却")
    _clear()


def test_cooldown_blocks_cas_requests():
    _clear()
    ft = _FakeTime(1000.0)
    cas_calls = []
    check_calls = []

    def fake_cas(*a, **k):
        cas_calls.append(1)
        return None, "WRONG_CREDENTIAL"

    def fake_check(client=None):
        check_calls.append(1)
        return None

    with _patched(time=ft):
        m._set_cooldown("auth", m.AUTH_COOLDOWN_SEC)
        with _patched(HTTPClient=_boom_http, check_online=fake_check,
                      cas_login=fake_cas):
            ok, msg = m.login("20260001", "wrong")
        _eq(ok, False, "冷却期内登录应失败")
        _eq(msg, "cooldown:auth", "冷却返回码")
        _eq(cas_calls, [], "冷却期内绝不允许发起 CAS 请求")
        _eq(check_calls, [], "冷却检查应在任何网络请求之前返回")
        _eq(m._cooldown_remaining(), m.AUTH_COOLDOWN_SEC, "冷却期不应被重复重置")
    _clear()


def test_limit_cooldown_blocks_cas_requests():
    _clear()
    ft = _FakeTime(2000.0)
    with _patched(time=ft):
        m._set_cooldown("limit", m.LIMIT_COOLDOWN_SEC)
        with _patched(HTTPClient=_boom_http):
            ok, msg = m.login("20260001", "right")
        _eq(ok, False, "limit 冷却期内登录应失败")
        _eq(msg, "cooldown:limit", "冷却返回码应带 limit")
        _eq(m._cooldown_remaining(), m.LIMIT_COOLDOWN_SEC, "limit 冷却时长")
    _clear()


def test_cooldown_expires_then_retry_allowed():
    _clear()
    ft = _FakeTime(1000.0)
    cas = _Seq([(None, "WRONG_CREDENTIAL")])
    with _patched(time=ft):
        m._set_cooldown("auth", m.AUTH_COOLDOWN_SEC)
        ft.now += m.AUTH_COOLDOWN_SEC + 1      # 冷却过期
        with _login_path(cas_login=cas):
            ok, msg, kind = m._login_impl("20260001", "wrong")
        _eq(ok, False, "过期后重试仍失败")
        _eq(kind, "auth", "仍被拒应再次归类 auth")
        _eq(cas.calls, 1, "冷却过期后应允许再次尝试 CAS")
        _eq(m._cooldown_remaining(), m.AUTH_COOLDOWN_SEC, "失败后应重新开始冷却")
    _clear()


def test_success_clears_cooldown():
    _clear()
    ft = _FakeTime(1000.0)
    checks = _Seq([None, _INFO])         # 顶部离线, 登录成功后在线
    with _patched(time=ft):
        m._set_cooldown("auth", 10)
        ft.now += 11                     # 冷却已过期
        with _login_path(check_online=checks,
                         cas_login=lambda *a, **k: (_TICKET, None),
                         complete_sso=lambda c, url: ("ok", ""),
                         probe_internet=lambda client=None, timeout=8: "ok"):
            ok, msg, kind = m._login_impl("20260001", "right")
        _eq(ok, True, "登录应成功: %s" % msg)
        _eq(kind, "ok", "成功 kind")
        _check(msg.startswith("login-ok:"), "成功信息: " + msg)
        _check(m._COOLDOWN_UNTIL is None and m._COOLDOWN_KIND is None,
               "成功登录必须清除冷却")
    _clear()


# ---------- E2620 -> limit + 冷却 ----------

def test_complete_sso_e2620_returns_limit():
    fake = _FakeHTTP(sso=(200, {}, b'{"error":"E2620","error_msg":"device limit"}'))
    kind, msg = m.complete_sso(fake, _TICKET)
    _eq(kind, "limit", "E2620 应返回 kind=limit")
    _check("E2620" in msg, "msg 应含 E2620: " + msg)
    _eq(len(fake.calls), 2, "sso 校验 + 成功页收尾各一次")


def test_e2620_limit_kind_and_cooldown():
    _clear()
    ft = _FakeTime(1000.0)
    fake = _FakeHTTP(sso=(200, {}, b'{"error":"E2620"}'))
    with _patched(time=ft):
        with _login_path(cas_login=lambda *a, **k: (_TICKET, None),
                         HTTPClient=lambda: fake):
            ok, msg, kind = m._login_impl("20260001", "right")
        _eq(ok, False, "E2620 应登录失败")
        _eq(kind, "limit", "E2620 应归类 limit")
        _check(msg.startswith("limit:"), "失败信息应以 limit: 开头: " + msg)
        _check("E2620" in msg, "应说明设备数超限: " + msg)
        _eq(m._COOLDOWN_KIND, "limit", "应写入 limit 冷却")
        _eq(m._cooldown_remaining(), m.LIMIT_COOLDOWN_SEC, "limit 冷却时长")
        _eq(len(fake.calls), 2, "sso 校验 + 成功页收尾各一次")
    _clear()


def test_complete_sso_ok_when_no_e2620():
    fake = _FakeHTTP()
    kind, msg = m.complete_sso(fake, _TICKET)
    _eq(kind, "ok", "无 E2620 且 HTTP 200 应返回 ok")
    _eq(msg, "", "无错误信息")
    _eq(len(fake.calls), 2, "sso 校验 + 成功页收尾各一次")


def test_complete_sso_success_page_failure_not_fatal():
    # 原有语义: 成功页收尾失败不致命, 仍返回 ok (由后续在线验证判定)
    flaky = _FlakyHTTP()
    kind, msg = m.complete_sso(flaky, _TICKET)
    _eq(kind, "ok", "成功页收尾失败不应使 complete_sso 判失败")
    _eq(msg, "", "无错误信息")
    _eq(len(flaky.calls), 2, "sso 校验 + 成功页收尾各一次")


def test_complete_sso_bad_ticket_url_is_auth():
    fake = _FakeHTTP()
    kind, msg = m.complete_sso(
        fake, "http://attacker.example/v1/srun_portal_sso?ticket=x")
    _eq(kind, "auth", "非法 ticket 回跳应安全中止")
    _check("ticket-reject" in msg, "msg: " + msg)
    _eq(fake.calls, [], "非法回跳不得发起任何请求")


# ---------- transient 失败: 无冷却 ----------

def test_verify_fail_is_transient_without_cooldown():
    _clear()
    ft = _FakeTime(1000.0)
    with _patched(time=ft):
        with _login_path(cas_login=lambda *a, **k: (_TICKET, None),
                         complete_sso=lambda c, url: ("ok", "")):
            ok, msg, kind = m._login_impl("20260001", "right")
        _eq(ok, False, "verify-fail 应失败")
        _eq(kind, "transient", "verify-fail 应归类 transient")
        _eq(msg, "verify-fail", "失败信息")
        _check(m._COOLDOWN_UNTIL is None, "transient 失败不得写冷却")
    _clear()


def test_ghost_after_login_is_transient():
    _clear()
    ft = _FakeTime(1000.0)
    checks = _Seq([None, _INFO])
    with _patched(time=ft):
        with _login_path(check_online=checks,
                         cas_login=lambda *a, **k: (_TICKET, None),
                         complete_sso=lambda c, url: ("ok", ""),
                         probe_internet=lambda client=None, timeout=8: "hijacked"):
            ok, msg, kind = m._login_impl("20260001", "right")
        _eq(ok, False, "幽灵会话应失败")
        _eq(kind, "transient", "幽灵会话应归类 transient")
        _eq(msg, "ghost-after-login", "失败信息")
        _check(m._COOLDOWN_UNTIL is None, "transient 失败不得写冷却")
    _clear()


def test_no_redirect_is_transient():
    _clear()
    with _login_path(get_sso_redirect=lambda client=None: None):
        ok, msg, kind = m._login_impl("20260001", "right")
    _eq(ok, False, "拿不到 SSO 入口应失败")
    _eq(kind, "transient", "no-redirect 应归类 transient")
    _eq(msg, "no-redirect", "失败信息")
    _check(m._COOLDOWN_UNTIL is None, "transient 失败不得写冷却")
    _clear()


# ---------- 安全中止 / KEY_ROTATED ----------

def test_sso_reject_is_auth_security_abort_without_cooldown():
    _clear()
    cas_calls = []
    bad_redirect = "http://attacker.example/tpass/login?service=x"
    with _login_path(get_sso_redirect=lambda client=None: bad_redirect,
                     cas_login=lambda *a, **k: cas_calls.append(1)):
        ok, msg, kind = m._login_impl("20260001", "secret")
    _eq(ok, False, "非法 Redirect 必须登录失败")
    _eq(kind, "auth", "sso-reject 属安全中止, 归类 auth")
    _check(msg.startswith("sso-reject:"), "错误码: " + msg)
    _check("中间人" in msg, "应提示疑似中间人而非密码错: " + msg)
    _eq(cas_calls, [], "非法 Redirect 时不得发送凭据")
    _check(m._COOLDOWN_UNTIL is None,
           "sso-reject 未发送凭据 => 不写凭据冷却(换网/重启可立即重试)")
    _clear()


def test_key_rotated_insecure_is_config():
    _clear()
    with _patched(ALLOW_INSECURE_TLS=True):
        with _login_path(cas_login=lambda *a, **k: (None, "KEY_ROTATED")):
            ok, msg, kind = m._login_impl("20260001", "secret")
    _eq(ok, False, "KEY_ROTATED 且禁用刷新应失败")
    _eq(kind, "config", "不校验模式下 KEY_ROTATED 应归类 config")
    _check("key-rotated" in msg and "PUBKEY_B64" in msg,
           "应提示手动更新 PUBKEY_B64: " + msg)
    _check(m._COOLDOWN_UNTIL is None, "config 由 run_forever 停止, 不写冷却")
    _clear()


def test_key_refresh_failure_is_transient():
    _clear()

    def fake_get_key(client=None, refresh=False):
        if refresh:
            raise OSError("net down")
        return 3233, 17

    with _login_path(get_key=fake_get_key,
                     cas_login=lambda *a, **k: (None, "KEY_ROTATED")):
        ok, msg, kind = m._login_impl("20260001", "secret")
    _eq(ok, False, "刷新公钥失败应登录失败")
    _eq(kind, "transient", "刷新公钥网络异常应归类 transient")
    _check(msg.startswith("key-refresh-fail:"), "错误码: " + msg)
    _check(m._COOLDOWN_UNTIL is None, "transient 失败不得写冷却")
    _clear()


# ---------- ensure_online 冷却期行为 ----------

def test_ensure_online_cooldown_returns_false_without_cas():
    _clear()
    ft = _FakeTime(1000.0)
    cas_calls = []
    check = _Seq([None])

    def fake_cas(*a, **k):
        cas_calls.append(1)
        return None, "WRONG_CREDENTIAL"

    with _patched(time=ft):
        m._set_cooldown("auth", m.AUTH_COOLDOWN_SEC)
        with _login_path(check_online=check, cas_login=fake_cas):
            ok, msg = m.ensure_online("20260001", "wrong")
        _eq(ok, False, "冷却期内 ensure_online 应返回失败")
        _check(msg.startswith("cooldown:"), "应返回冷却状态: " + msg)
        _eq(cas_calls, [], "冷却期内 ensure_online 不得触发 CAS")
        _eq(check.calls, 1, "冷却期仍应先做一次在线检查(不碰 CAS)")
    _clear()


# ---------- run_forever 失败处置提示 ----------

def test_report_fail_hints_and_stop():
    _clear()
    ft = _FakeTime(1000.0)
    with _patched(time=ft):
        m._set_cooldown("auth", m.AUTH_COOLDOWN_SEC)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cont = m._report_fail("auth", "WRONG_CREDENTIAL")
        _check(cont is True, "auth 冷却应继续主循环")
        text = out.getvalue()
        _check("凭据被拒" in text and "30 分钟" in text,
               "凭据冷却提示应清晰: " + text)

        m._clear_cooldown()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cont = m._report_fail("auth", "sso-reject:bad")
        _check(cont is True, "sso-reject 安全中止应继续")
        _check("中间人" in out.getvalue(), "sso-reject 提示: " + out.getvalue())

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cont = m._report_fail("limit", "limit: E2620")
        _check(cont is True, "limit 应继续主循环")
        text = out.getvalue()
        _check("E2620" in text and "--kick" in text,
               "limit 提示应给出 PC 端释放名额命令: " + text)

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cont = m._report_fail("config", "key-rotated")
        _check(cont is False, "config 应停止自动登录(避免无意义重试)")
        _check("PUBKEY_B64" in out.getvalue(), "config 提示: " + out.getvalue())

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cont = m._report_fail("transient", "no-lt")
        _check(cont is True, "transient 应继续重试")
        _check("暂时性失败" in out.getvalue(), "transient 提示: " + out.getvalue())
    _clear()


def test_login_safe_never_raises():
    def boom(u, p):
        raise OSError("sock down")

    with _patched(_login_impl=boom):
        ok, msg, kind = m._login_safe("u", "p")
    _eq(ok, False, "异常应收敛为失败")
    _eq(kind, "transient", "网络异常应归类 transient")
    _check("sock down" in msg, "错误信息: " + msg)

    def oom(u, p):
        raise MemoryError()

    with _patched(_login_impl=oom):
        ok, msg, kind = m._login_safe("u", "p")
    _eq(ok, False, "MemoryError 应收敛为失败")
    _eq(kind, "transient", "MemoryError 应归类 transient")
    _check("MemoryError" in msg, "错误信息: " + msg)


# ---------- run_forever 主循环接线 (冷却期不重登 / config 停止) ----------

class _FakeSta:
    """假 WLAN: isconnected() 最多返回 N 次 True, 之后掉线"""

    def __init__(self, alive_checks):
        self.left = alive_checks

    def isconnected(self):
        if self.left <= 0:
            return False
        self.left -= 1
        return True


def test_run_forever_stops_on_config_failure():
    _clear()
    ft = _FakeTime(1000.0)
    wifi_calls = []

    def wifi():
        wifi_calls.append(1)
        return _FakeSta(0)          # 掉线 -> 只走开机登录, 不进内层巡检

    with _patched(time=ft, USERNAME="u", PASSWORD="p", wifi_connect=wifi,
                  ensure_time=lambda: (True, "time-ok"), led=lambda on: None,
                  _login_impl=lambda u, p: (False, "key-rotated: x", "config")):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            m.run_forever()
    _eq(len(wifi_calls), 1, "config 类失败应立即停止主循环, 不再重连重试")
    _check("已停止自动登录" in out.getvalue(),
           "应提示停止原因: " + out.getvalue())
    _clear()


def test_run_forever_auth_cooldown_skips_cas():
    # 开机登录因错误密码进入冷却; 内层离线巡检期间只做在线检查, 不得再登录
    _clear()
    ft = _FakeTime(1000.0)
    login_calls = []
    wifi_calls = []

    def wifi():
        wifi_calls.append(1)
        if len(wifi_calls) > 1:
            raise SystemExit(0)     # 第二次重连时结束主循环, 测试退出
        return _FakeSta(1)          # 内层巡检跑 1 轮后掉线

    def fake_login(u, p):
        login_calls.append(1)
        m._set_cooldown("auth", m.AUTH_COOLDOWN_SEC)
        return False, "WRONG_CREDENTIAL", "auth"

    out = io.StringIO()
    try:
        with _patched(time=ft, USERNAME="u", PASSWORD="p", wifi_connect=wifi,
                      ensure_time=lambda: (True, "time-ok"), led=lambda on: None,
                      check_online=lambda client=None: None,
                      probe_internet=lambda client=None, timeout=8: "unknown",
                      _login_impl=fake_login):
            with contextlib.redirect_stdout(out):
                m.run_forever()
    except SystemExit:
        pass
    text = out.getvalue()
    _eq(len(login_calls), 1,
        "冷却期内离线巡检不得再尝试登录(即零 CAS 请求)")
    _check("凭据被拒" in text, "应打印凭据冷却提示: " + text)
    _check("冷却中" in text and "跳过 CAS" in text,
           "冷却期内应提示跳过 CAS: " + text)
    _clear()


def main():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for name, fn in tests:
        _clear()
        try:
            fn()
            print("[+] %s" % name)
        except AssertionError as ex:
            failed += 1
            print("[-] %s: %s" % (name, ex))
        except Exception as ex:
            failed += 1
            print("[!] %s: %r" % (name, ex))
    _clear()
    print("\n%d/%d 通过" % (len(tests) - failed, len(tests)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
