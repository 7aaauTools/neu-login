#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
"""纯函数离线单元测试: RSA / SPKI DER 解析 / fix_service_url / ESP32 响应体解析

不访问网络、不需要凭据:
    python test_neu_login.py        # 直接运行
    pytest test_neu_login.py        # 也可用 pytest
"""

import contextlib
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import neu_login

import neu_login_esp32

_REDIRECT = ("https://pass.neu.edu.cn/tpass/login?service="
             "http%3A%2F%2Fipgw.neu.edu.cn%2Fsrun_portal_sso")


def test_parse_spki_builtin_key():
    n, e = neu_login.parse_spki(neu_login.PUBKEY_B64)
    assert n.bit_length() == 2048, "内置公钥应为 RSA-2048, 实际 %d bit" % n.bit_length()
    assert e == 65537


def test_rsa_pkcs1v15_structure():
    # e=1 时 pow(m,1,n)=m 且 m<n, 密文即编码块本身, 可离线验证 PKCS#1 v1.5 结构
    k = 128
    n = (1 << (8 * (k - 1))) + 12345
    data = b"hello"
    em = neu_login.rsa_pkcs1v15_encrypt(n, 1, data)
    assert len(em) == k
    assert em[:2] == b"\x00\x02", "EM 必须以 00 02 开头"
    assert em[-len(data):] == data, "尾部必须是明文本身"
    assert em[-len(data) - 1] == 0, "PS 与明文之间必须有 0x00 分隔符"
    assert all(em[2:-len(data) - 1]), "PS 填充字节必须全部非零"


def test_rsa_real_key_shape():
    n, e = neu_login.get_rsa_key()
    cipher = neu_login.rsa_pkcs1v15_encrypt(n, e, b"selftest")
    assert len(cipher) == 256
    try:
        neu_login.rsa_pkcs1v15_encrypt(n, e, b"x" * 246)
        assert False, "超长明文应抛 ValueError"
    except ValueError:
        pass


def test_fix_service_url_appends_acid():
    neu_login.DETECTED_AC_ID = None
    try:
        out = neu_login.fix_service_url(_REDIRECT)
    finally:
        neu_login.DETECTED_AC_ID = None
    assert out.startswith("https://pass.neu.edu.cn/tpass/login?service=")
    assert out.endswith("srun_portal_sso%3Fac_id%3D16"), out


def test_fix_service_url_dynamic_acid():
    neu_login.DETECTED_AC_ID = 7
    try:
        out = neu_login.fix_service_url(_REDIRECT)
    finally:
        neu_login.DETECTED_AC_ID = None
    assert out.endswith("srun_portal_sso%3Fac_id%3D7"), out


def test_fix_service_url_idempotent():
    redirect = _REDIRECT + "%3Fac_id%3D16"
    neu_login.DETECTED_AC_ID = None
    try:
        assert neu_login.fix_service_url(redirect) == redirect
    finally:
        neu_login.DETECTED_AC_ID = None


def test_fix_service_url_no_service_param():
    redirect = "https://pass.neu.edu.cn/tpass/login"
    assert neu_login.fix_service_url(redirect) == redirect


def test_esp32_fix_service_url():
    m = neu_login_esp32
    m.DETECTED_AC_ID = 7
    try:
        out = m.fix_service_url(_REDIRECT)
    finally:
        m.DETECTED_AC_ID = None
    assert out.startswith("https://pass.neu.edu.cn/tpass/login?service=")
    assert out.endswith("srun_portal_sso%3Fac_id%3D7"), out


def test_esp32_fix_service_url_idempotent():
    redirect = _REDIRECT + "%3Fac_id%3D16"
    assert neu_login_esp32.fix_service_url(redirect) == redirect


class _FakeSock:
    """模拟 ESP32 HTTPClient._read_body 需要的 socket 接口"""

    def __init__(self, raw):
        self._raw = raw
        self._pos = 0

    def readline(self):
        i = self._raw.find(b"\n", self._pos)
        if i < 0:
            out, self._pos = self._raw[self._pos:], len(self._raw)
        else:
            out, self._pos = self._raw[self._pos:i + 1], i + 1
        return out

    def read(self, n):
        out = self._raw[self._pos:self._pos + n]
        self._pos += len(out)
        return out


def test_esp32_read_body_content_length():
    c = neu_login_esp32.HTTPClient()
    body = c._read_body(_FakeSock(b"hello world"), {"content-length": "5"}, 1000)
    assert bytes(body) == b"hello"


def test_esp32_read_body_chunked():
    c = neu_login_esp32.HTTPClient()
    raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    body = c._read_body(_FakeSock(raw), {"transfer-encoding": "chunked"}, 1000)
    assert bytes(body) == b"Wikipedia"


def test_esp32_ensure_online_fast_path():
    # 已在线且探测正常 -> 立即返回, 不触发登录
    m = neu_login_esp32
    orig = (m.check_online, m.probe_internet, m.login)
    m.check_online = lambda c=None: ["u", "t", "0", "0", "0", "0", "0", "0", "10.0.0.1"]
    m.probe_internet = lambda c=None, timeout=8: "ok"
    m.login = lambda u, p: (True, "should-not-call")
    try:
        ok, msg = m.ensure_online("u", "p")
        assert ok and msg.startswith("online:"), msg
    finally:
        m.check_online, m.probe_internet, m.login = orig


def test_esp32_ensure_online_ghost_relogin():
    # 幽灵会话(账面在线但被劫持) -> 走重登
    m = neu_login_esp32
    orig = (m.check_online, m.probe_internet, m.login)
    m.check_online = lambda c=None: ["u"] * 9
    m.probe_internet = lambda c=None, timeout=8: "hijacked"
    m.login = lambda u, p: (True, "rebuilt") if (u, p) == ("u", "p") else (False, "?")
    try:
        ok, msg = m.ensure_online("u", "p")
        assert ok and msg == "rebuilt", msg
    finally:
        m.check_online, m.probe_internet, m.login = orig


def test_esp32_ensure_online_offline_relogin():
    m = neu_login_esp32
    orig = (m.check_online, m.login)
    m.check_online = lambda c=None: None
    m.login = lambda u, p: (True, "login-ok")
    try:
        assert m.ensure_online("u", "p") == (True, "login-ok")
    finally:
        m.check_online, m.login = orig


def test_esp32_ensure_online_no_credentials():
    m = neu_login_esp32
    orig = (m.USERNAME, m.PASSWORD)
    m.USERNAME = m.PASSWORD = ""
    try:
        ok, msg = m.ensure_online()
        assert not ok and "no-credentials" in msg, msg
    finally:
        m.USERNAME, m.PASSWORD = orig


# ============ 回归测试 (fetch 打桩, 不联网) ============

def _stub_fetch(resp_by_url):
    """替换 neu_login.fetch: 按 URL 关键字返回预设 (code, body, headers); "*" 匹配任意 URL"""
    def fake_fetch(opener, url, data=None, timeout=12, referer=None):
        for key, resp in resp_by_url.items():
            if key != "*" and key in url:
                return resp
        return resp_by_url.get("*", (200, "", {}))
    orig = neu_login.fetch
    neu_login.fetch = fake_fetch
    return orig


def test_logout_offline_not_online():
    # 回归: 门户返回 not_online 时 logout 不再 IndexError 崩溃
    orig = _stub_fetch({"rad_user_info": (200, "not_online_error", {})})
    try:
        assert neu_login.logout() == "当前不在线"
    finally:
        neu_login.fetch = orig


def test_logout_short_body():
    orig = _stub_fetch({"rad_user_info": (200, "a,b,c", {})})
    try:
        assert neu_login.logout() == "当前不在线"
    finally:
        neu_login.fetch = orig


def test_logout_online_flow():
    resp = {
        "rad_user_info": (200, "user01,1750000000,0,1024,0,0,0,0,10.0.0.1,x", {}),
        "srun_portal": (200, 'srun({"error":"ok"})', {}),
    }
    orig = _stub_fetch(resp)
    try:
        assert neu_login.logout() == "已注销"
    finally:
        neu_login.fetch = orig


def test_probe_internet_302_hijack():
    # 回归: 302 劫持标志在 Location 头(body为空), 必须判定 hijacked
    orig = _stub_fetch({"*": (302, "", {"Location": "http://202.118.1.87/index_16.html?ac_id=16"})})
    try:
        assert neu_login.probe_internet() == "hijacked"
    finally:
        neu_login.fetch = orig


def test_probe_internet_204_ok():
    orig = _stub_fetch({"*": (204, "", {})})
    try:
        assert neu_login.probe_internet() == "ok"
    finally:
        neu_login.fetch = orig


def test_detect_ac_id_302_location():
    # 回归: AC 编号在 Location 头时也能检测到, 不再静默回落默认16
    loc = "http://202.118.1.87/index_9.html?ac_id=9&wlanacname=NEU-AC9"
    orig = _stub_fetch({"*": (302, "", {"Location": loc})})
    old = neu_login.DETECTED_AC_ID
    neu_login.DETECTED_AC_ID = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            assert neu_login.detect_ac_id() == 9
        assert neu_login.DETECTED_AC_ID == 9
    finally:
        neu_login.fetch = orig
        neu_login.DETECTED_AC_ID = old


def test_detect_ac_id_injected_body():
    # 200 注入页形态 (原有逻辑): 标志在 body
    body = "<script>top.self.location.href='http://202.118.1.87/index_7.html?ac_id=7'</script>"
    orig = _stub_fetch({"*": (200, body, {})})
    old = neu_login.DETECTED_AC_ID
    neu_login.DETECTED_AC_ID = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            assert neu_login.detect_ac_id() == 7
    finally:
        neu_login.fetch = orig
        neu_login.DETECTED_AC_ID = old


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
