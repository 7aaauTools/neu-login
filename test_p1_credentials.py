#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
"""PR1 凭据入口与落盘 离线测试 (不联网, 不需要凭据)

覆盖 (审计 A1/A2/A3):
  * -u 后交互 getpass 取密码; --password-stdin 从 stdin 读; -p 兼容但告警
  * 半套参数(-u 无密码)不再静默回落到已保存凭据
  * 凭据保存: 原子写(无残留临时文件)、POSIX 600/目录 700、无"先写后 chmod"
  * 凭据读取: 坏 JSON / 字段缺失返回 None 且告警, 不再崩溃
  * --devices: 优先 HTTPS; HTTPS 不可用回退明文 HTTP 时显式告警

运行: python test_p1_credentials.py
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import neu_login

_TMP = tempfile.mkdtemp(prefix="neu-p1-")


# ---------- 显式断言 (不依赖 -O 下会被剥离的 assert) ----------

def _check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _eq(got, want, what):
    if got != want:
        raise AssertionError("%s: 期望 %r, 实际 %r" % (what, want, got))


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


class _FakeStdin(io.StringIO):
    def __init__(self, text, tty):
        io.StringIO.__init__(self, text)
        self._tty = tty

    def isatty(self):
        return self._tty


def _run_main(argv, stdin_text="", tty=False):
    """在进程内跑 main(), 返回 (exit_code, stdout, stderr)"""
    old_argv = sys.argv
    sys.argv = ["neu_login.py"] + argv
    out, err = io.StringIO(), io.StringIO()
    code = None
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            old_stdin = sys.stdin
            sys.stdin = _FakeStdin(stdin_text, tty)
            try:
                try:
                    neu_login.main()
                except SystemExit as ex:
                    code = ex.code
            finally:
                sys.stdin = old_stdin
    finally:
        sys.argv = old_argv
    return code, out.getvalue(), err.getvalue()


def _capture_login():
    captured = {}

    def fake_login(username, password):
        captured["username"] = username
        captured["password"] = password
        return True, "stub-ok", "ok"

    return captured, fake_login


# ---------- A1: 密码入口 ----------

def test_password_stdin():
    captured, fake_login = _capture_login()
    with _patched(neu_login, CRED_FILE=os.path.join(_TMP, "none1.json"), login=fake_login):
        code, out, err = _run_main(["-u", "alice", "--password-stdin"],
                                   stdin_text="stdin-secret\n")
    _eq(code, 0, "退出码")
    _eq(captured.get("password"), "stdin-secret", "stdin 密码")
    _check("警告" not in err, "stdin 方式不应出现 argv 告警: " + err)


def test_argv_password_warns():
    captured, fake_login = _capture_login()
    with _patched(neu_login, CRED_FILE=os.path.join(_TMP, "none2.json"), login=fake_login):
        code, out, err = _run_main(["-u", "alice", "-p", "argv-secret"])
    _eq(code, 0, "退出码")
    _eq(captured.get("password"), "argv-secret", "argv 密码仍兼容")
    _check("警告" in err and "password-stdin" in err,
           "应告警并提示改用 --password-stdin: " + err)


def test_interactive_getpass_used():
    captured, fake_login = _capture_login()
    fake_getpass = types.SimpleNamespace(getpass=lambda prompt="": "interactive-secret")
    with _patched(neu_login, CRED_FILE=os.path.join(_TMP, "none3.json"),
                  login=fake_login, getpass=fake_getpass):
        code, out, err = _run_main(["-u", "alice"], tty=True)
    _eq(code, 0, "退出码")
    _eq(captured.get("password"), "interactive-secret", "getpass 密码")


def test_interactive_getpass_cancel():
    fake_getpass = types.SimpleNamespace(getpass=lambda prompt="": (_ for _ in ()).throw(KeyboardInterrupt()))
    with _patched(neu_login, CRED_FILE=os.path.join(_TMP, "none4.json"), getpass=fake_getpass):
        code, out, err = _run_main(["-u", "alice"], tty=True)
    _eq(code, neu_login.EXIT_TRANSIENT, "取消输入应返回 transient(2)")
    _check("取消" in err, "应提示已取消: " + err)


def test_partial_credentials_rejected():
    code, out, err = _run_main(["-u", "alice"])        # 非终端且无已存凭据
    _eq(code, 2, "半套参数应 argparse 报错(2)")
    _check("缺少密码" in err or "缺少密码" in out, "应提示缺少密码: " + err + out)


# ---------- A3: 凭据落盘 ----------

def test_save_credentials_atomic_and_private():
    d = os.path.join(_TMP, "cred-dir")
    path = os.path.join(d, "credentials.json")
    with _patched(neu_login, CRED_FILE=path):
        neu_login.save_credentials("alice", "p@ss")
    with open(path, encoding="utf-8") as f:
        _eq(json.load(f), {"username": "alice", "password": "p@ss"}, "文件内容")
    leftovers = [n for n in os.listdir(d) if n.startswith(".neu-cred-")]
    _eq(leftovers, [], "不应残留临时文件")
    if os.name == "posix":
        _eq(os.stat(path).st_mode & 0o777, 0o600, "凭据文件权限")
        _eq(os.stat(d).st_mode & 0o777, 0o700, "凭据目录权限")


def test_save_load_roundtrip():
    path = os.path.join(_TMP, "roundtrip", "credentials.json")
    with _patched(neu_login, CRED_FILE=path):
        neu_login.save_credentials("bob", "secret")
        data = neu_login.load_credentials()
    _eq(data, {"username": "bob", "password": "secret"}, "读回内容")


def test_load_credentials_corrupt_json():
    path = os.path.join(_TMP, "broken.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write("{not-json")
    err = io.StringIO()
    with _patched(neu_login, CRED_FILE=path), contextlib.redirect_stderr(err):
        data = neu_login.load_credentials()
    _eq(data, None, "坏 JSON 应返回 None")
    _check("损坏" in err.getvalue(), "应提示文件损坏: " + err.getvalue())


def test_load_credentials_missing_fields():
    path = os.path.join(_TMP, "partial.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"username": "alice"}, f)
    err = io.StringIO()
    with _patched(neu_login, CRED_FILE=path), contextlib.redirect_stderr(err):
        data = neu_login.load_credentials()
    _eq(data, None, "字段缺失应返回 None")
    _check("缺少" in err.getvalue(), "应提示字段缺失: " + err.getvalue())


def test_load_credentials_absent_returns_none():
    with _patched(neu_login, CRED_FILE=os.path.join(_TMP, "no-such-file.json")):
        _eq(neu_login.load_credentials(), None, "文件不存在应返回 None")


# ---------- A2: --devices 传输安全 ----------

def test_list_devices_prefers_https():
    calls = []

    def fake_fetch(opener, url, **kw):
        calls.append(url)
        return 200, '{"data": []}', {}

    err = io.StringIO()
    with _patched(neu_login, fetch=fake_fetch), contextlib.redirect_stderr(err):
        result = neu_login.list_devices("alice", "pw")
    _eq(result, {"data": []}, "返回值")
    _check(calls and calls[0].startswith("https://"), "应优先 HTTPS: %r" % calls)
    _eq(len(calls), 1, "HTTPS 成功时不应再走明文 HTTP")
    _check("明文" not in err.getvalue(), "HTTPS 成功时不应告警: " + err.getvalue())


def test_list_devices_falls_back_http_with_warning():
    calls = []

    def fake_fetch(opener, url, **kw):
        calls.append(url)
        if url.startswith("https://"):
            raise neu_login.PortalError("tls unavailable")
        return 200, '{"data": [1]}', {}

    err = io.StringIO()
    with _patched(neu_login, fetch=fake_fetch), contextlib.redirect_stderr(err):
        result = neu_login.list_devices("alice", "pw")
    _eq(result, {"data": [1]}, "回退 HTTP 后应返回数据")
    _check(any(u.startswith("http://") for u in calls), "应尝试明文 HTTP: %r" % calls)
    _check("明文" in err.getvalue() and "md5" in err.getvalue(),
           "回退明文 HTTP 必须告警(md5/嗅探风险): " + err.getvalue())


def test_list_devices_both_fail():
    def fake_fetch(opener, url, **kw):
        raise neu_login.PortalError("down")

    err = io.StringIO()
    with _patched(neu_login, fetch=fake_fetch), contextlib.redirect_stderr(err):
        result = neu_login.list_devices("alice", "pw")
    _check("error" in result, "都失败应返回 error: %r" % (result,))
    _check("明文" in err.getvalue(), "应提示 HTTPS/明文均失败: " + err.getvalue())


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
