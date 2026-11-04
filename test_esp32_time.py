#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
"""ESP32 时间同步 / 设备自检 离线测试 (不联网, 不需要凭据)

背景: ESP32 版默认 CERT_REQUIRED, 证书校验强依赖设备时钟; 而无电池 RTC 的
ESP32 断电后时钟复位为 2000 年。本文件验证:
  * time_ok() 年份边界判定
  * sync_time() 成功/失败/缺少 ntptime 模块
  * ensure_time() 时间正常时不发起 NTP
  * login() 在时间不可用且校时失败时, 返回 time-invalid 且不发起 CAS 请求
  * self_check() 结构完整、INSECURE 模式下跳过主机名自证
  * 固件缺少 ntptime 时不会崩溃

运行: python test_esp32_time.py
"""

import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import neu_login_esp32 as m

_REDIRECT = ("https://pass.neu.edu.cn/tpass/login?service="
             "http%3A%2F%2Fipgw.neu.edu.cn%2Fsrun_portal_sso")


# ---------- 显式断言 (不依赖 -O 下会被剥离的 assert) ----------

def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _eq(got, want, what):
    if got != want:
        raise AssertionError("%s: 期望 %r, 实际 %r" % (what, want, got))


# ---------- 桩 ----------

class _FakeTime:
    """假 time 模块: localtime 返回可控年份"""

    def __init__(self, year=2000):
        self.year = year

    def localtime(self):
        return (self.year, 1, 1, 0, 0, 0, 0, 1)

    def time(self):
        return 0

    def sleep(self, seconds):
        pass


class _FakeNtp:
    """假 ntptime 模块: settime 成功时把设备时间改到 2026 年"""

    def __init__(self, fake_time, fail=False):
        self.fake_time = fake_time
        self.fail = fail
        self.host = None
        self.timeout = None
        self.calls = 0

    def settime(self):
        self.calls += 1
        if self.fail:
            raise OSError("ntp timeout")
        self.fake_time.year = 2026


@contextlib.contextmanager
def _patched(module, **attrs):
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
                delattr(module, k)
            else:
                setattr(module, k, v)


@contextlib.contextmanager
def _fake_module(name, module):
    missing = object()
    old = sys.modules.get(name, missing)
    sys.modules[name] = module
    try:
        yield
    finally:
        if old is missing:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = old


def _quiet():
    return contextlib.redirect_stdout(io.StringIO())


# ---------- time_ok ----------

def test_time_ok_boundaries():
    with _patched(m, MIN_VALID_YEAR=2024):
        for year, want in ((2000, False), (2023, False), (2024, True),
                           (2026, True), (2099, True), (2100, False)):
            with _patched(m, time=_FakeTime(year)):
                _eq(m.time_ok(), want, "time_ok(year=%d)" % year)


def test_time_ok_never_raises_on_broken_time():
    class _BadTime:
        def localtime(self):
            raise OSError("rtc broken")

    with _patched(m, time=_BadTime()):
        _eq(m.time_ok(), False, "localtime 异常时应返回 False")


# ---------- sync_time ----------

def test_sync_time_success():
    fake_time = _FakeTime(2000)
    fake_ntp = _FakeNtp(fake_time)
    with _patched(m, time=fake_time, NTP_HOST="ntp.neu.edu.cn", NTP_TIMEOUT=8):
        with _fake_module("ntptime", fake_ntp):
            ok, msg = m.sync_time()
    _check(ok, "NTP 成功应返回 True: " + msg)
    _eq(fake_ntp.calls, 1, "settime 调用次数")
    _eq(fake_ntp.host, "ntp.neu.edu.cn", "ntptime.host")
    _check("ntp-ok" in msg, "成功信息: " + msg)
    _check(m.time_ok(), "校时后时间应可用")


def test_sync_time_failure():
    fake_time = _FakeTime(2000)
    fake_ntp = _FakeNtp(fake_time, fail=True)
    with _patched(m, time=fake_time, NTP_HOST="ntp.neu.edu.cn"):
        with _fake_module("ntptime", fake_ntp):
            ok, msg = m.sync_time()
    _check(not ok, "NTP 失败应返回 False")
    _check("ntp-fail" in msg, "失败信息应可识别: " + msg)


def test_sync_time_without_ntptime_module():
    with _patched(m, time=_FakeTime(2000)):
        sys.modules["ntptime"] = None          # 让 import ntptime 抛 ImportError
        try:
            ok, msg = m.sync_time()
        finally:
            sys.modules.pop("ntptime", None)
    _check(not ok, "缺少 ntptime 模块应返回 False 而不是抛 ImportError")
    _check("no-ntptime" in msg, "应提示缺少模块: " + msg)


# ---------- ensure_time ----------

def test_ensure_time_skips_when_time_ok():
    with _patched(m, time=_FakeTime(2026)):
        sys.modules["ntptime"] = None          # 若误发起 NTP 会 ImportError
        try:
            with _quiet():
                ok, msg = m.ensure_time()
        finally:
            sys.modules.pop("ntptime", None)
    _check(ok and msg == "time-ok", "时间正常时不应发起 NTP: %r" % ((ok, msg),))


def test_ensure_time_attempts_sync_when_invalid():
    fake_time = _FakeTime(2000)
    fake_ntp = _FakeNtp(fake_time)
    with _patched(m, time=fake_time):
        with _fake_module("ntptime", fake_ntp):
            with _quiet():
                ok, msg = m.ensure_time()
    _check(ok, "应自动校时成功: " + msg)
    _eq(fake_ntp.calls, 1, "应尝试一次 NTP")


# ---------- login 前置时间检查 ----------

def test_login_rejects_invalid_time_without_cas():
    cas_calls = []

    def fake_cas(*a, **kw):
        cas_calls.append(1)
        return None, "CAS-fail"

    with _patched(m,
                  time=_FakeTime(2000),
                  check_online=lambda client=None: None,
                  detect_ac_id=lambda client=None: None,
                  get_sso_redirect=lambda client=None: _REDIRECT,
                  cas_login=fake_cas,
                  ensure_time=lambda: (False, "no-ntp")):
        with _quiet():
            ok, msg = m.login("u", "p")
    _check(ok is False, "时间不可用时登录应失败")
    _check("time-invalid" in msg, "应明确报 time-invalid: " + msg)
    _check(not cas_calls, "时间不可用时不得发起 CAS 请求(不发送凭据)")


def test_login_skips_time_check_in_insecure_mode():
    # 用户显式关了校验时, 时间不再是前提, 不应被 time-invalid 拦下
    calls = []

    def fake_cas(*a, **kw):
        calls.append(1)
        return None, "CAS-fail"

    with _patched(m,
                  ALLOW_INSECURE_TLS=True,
                  time=_FakeTime(2000),
                  check_online=lambda client=None: None,
                  detect_ac_id=lambda client=None: None,
                  get_sso_redirect=lambda client=None: _REDIRECT,
                  cas_login=fake_cas):
        with _quiet():
            ok, msg = m.login("u", "p")
    _check(msg == "CAS-fail", "INSECURE 模式应继续到 CAS 阶段: " + msg)
    _eq(len(calls), 1, "CAS 调用次数")


# ---------- 自检 ----------

def test_self_check_structure():
    with _patched(m,
                  time=_FakeTime(2026),
                  _ca_subjects=lambda: ["GlobalSign GCC R3 DV TLS CA 2020", "GlobalSign"],
                  _ca_loadable=lambda: True,
                  _check_hostname_verification=lambda: "ok"):
        with _quiet():
            out = m.self_check()
    _eq(out["tls_mode"], "verified", "tls_mode")
    _eq(out["time_ok"], True, "time_ok")
    _eq(out["hostname_check"], "ok", "hostname_check")
    _check(out["ca_loadable"] is True, "ca_loadable")
    _check(isinstance(out["time"], tuple) and len(out["time"]) == 6, "time 应是 6 元组")
    _check(out["mem_free_kb"] == -1 or out["mem_free_kb"] >= 0, "mem_free_kb")


def test_self_check_insecure_skips_hostname_probe():
    # INSECURE 模式下不应发起真实握手; 直接走真实 _check_hostname_verification
    with _patched(m, ALLOW_INSECURE_TLS=True):
        _eq(m._check_hostname_verification(), "skipped(insecure)", "主机名自证应跳过")


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
