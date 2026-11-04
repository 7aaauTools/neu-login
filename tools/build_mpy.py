#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
"""把 neu_login_esp32.py 编译成 .mpy，并生成独立运行入口 dist/main.py

为什么需要：
    ESP32-C3 等内存紧张设备上，MicroPython 现场编译 ~48KB 源码会产生大量
    临时分配、显著恶化堆碎片；随后 mbedtls 在 TLS 握手解析证书链时会出现
        OSError(-10368, 'MBEDTLS_ERR_X509_ALLOC_FAILED')
    （实测：同一块 C3、同一固件下，.py 部署失败，.mpy 部署正常）。
    预编译成 .mpy 后设备端只需加载字节码，握手恢复正常。

用法：
    # 1. 安装与设备固件**完全一致**版本的 mpy-cross
    #    设备上 print(sys.version) 查看版本，例如 v1.29.0
    pip install mpy-cross==1.29.0.post2
    # 2. 生成（--mpy-cross 可省略，若 mpy-cross 已在 PATH）
    python tools/build_mpy.py
    python tools/build_mpy.py --mpy-cross D:/path/to/mpy-cross.exe

生成：
    dist/neu_login_esp32.mpy  -> 上传为 :neulib.mpy
    dist/main.py              -> 上传为 :main.py（独立运行入口，内容仅 2 行）

注意：
    * 修改 neu_login_esp32.py 的 CONFIG（学号/密码等）后需要重新生成 .mpy。
    * mpy-cross 版本必须与固件版本一致，否则设备端会报 incompatible .mpy file。
    * 库模式集成时无需 main.py，只需上传 .mpy 并 `import neulib`。
"""

import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "neu_login_esp32.py")
OUT = os.path.join(ROOT, "dist")

MAIN_PY = """# 独立运行入口: 由 tools/build_mpy.py 生成
# 凭据放在设备上的 secrets.py (不要提交仓库, 已列入 .gitignore):
#     USERNAME = "学号"
#     PASSWORD = "密码"
# 模块已预编译为 neulib.mpy, 避免设备端现场编译大文件造成堆碎片
# (ESP32-C3 上会导致 mbedtls MBEDTLS_ERR_X509_ALLOC_FAILED)
import neulib
try:
    import secrets
    neulib.USERNAME = secrets.USERNAME
    neulib.PASSWORD = secrets.PASSWORD
except ImportError:
    pass

neulib.run_forever()
"""


def find_mpy_cross(explicit):
    if explicit:
        return explicit if os.path.exists(explicit) else None
    for name in ("mpy-cross", "mpy-cross.exe", "mpy_cross.exe"):
        path = shutil.which(name)
        if path:
            return path
    return None


def main():
    ap = argparse.ArgumentParser(description="编译 neu_login_esp32.py -> .mpy 并生成 main.py")
    ap.add_argument("--mpy-cross", help="mpy-cross 可执行文件路径（默认从 PATH 查找）")
    args = ap.parse_args()

    tool = find_mpy_cross(args.mpy_cross)
    if not tool:
        print("[!] 找不到 mpy-cross。请安装与设备固件同版本的：\n"
              "      pip install mpy-cross==<设备 sys.version 中的版本，例如 1.29.0.post2>\n"
              "    或用 --mpy-cross 指定可执行文件路径。", file=sys.stderr)
        return 2
    if not os.path.exists(SRC):
        print("[!] 找不到源文件: %s" % SRC, file=sys.stderr)
        return 2

    os.makedirs(OUT, exist_ok=True)
    target = os.path.join(OUT, "neu_login_esp32.mpy")
    cmd = [tool, "-o", target, SRC]
    print("[*] " + " ".join(cmd))
    try:
        rc = subprocess.call(cmd)
    except OSError as ex:
        print("[!] 调用 mpy-cross 失败: %s" % ex, file=sys.stderr)
        return 2
    if rc != 0:
        print("[!] mpy-cross 失败 (rc=%d)" % rc, file=sys.stderr)
        return rc

    main_py = os.path.join(OUT, "main.py")
    with open(main_py, "w", encoding="utf-8", newline="\n") as f:
        f.write(MAIN_PY)
    print("[+] %s (%d bytes)" % (target, os.path.getsize(target)))
    print("[+] %s" % main_py)
    print("""
部署 (ESP32-C3 等内存紧张设备):
    mpremote cp dist/neu_login_esp32.mpy :neulib.mpy
    mpremote cp dist/main.py :main.py
    # 首次部署还需在设备上创建 secrets.py (凭据, 不要提交仓库):
    #   USERNAME = "学号"
    #   PASSWORD = "密码"
    # 然后:
    mpremote reset
库模式: 只需上传 .mpy, 业务代码 import neulib
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
