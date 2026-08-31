# neu-login

东北大学校园网自动登录工具 —— 覆盖 NEU-2.4G / NEU 无线网与有线网（Srun 深澜门户 + CAS 统一身份认证）。

纯 Python 标准库实现，**零第三方依赖**；同一套认证逻辑提供 CPython 与 MicroPython (ESP32) 两个版本，并附带 Linux 主机一键部署方案（Debian 及其他使用 systemd + NetworkManager 的现代发行版）。

## 功能特性

- **一键登录 / 注销 / 状态查询**：保存凭据后单命令完成认证，附流量统计
- **断线自动重连**：守护模式（`--watch`），或 systemd 事件驱动 + 定时巡检（见 `debian/`）
- **幽灵会话检测与自愈**：认证记录存在但流量被门户劫持（实际无法上网）时，自动注销并重建会话
- **AC 编号（ac_id）动态检测**：从劫持 URL 自动识别本网段真实编号，跨网段（不同宿舍楼/教学馆）移动免配置
- **公钥轮换自愈**：CAS 登录公钥变化时自动在线刷新并重试，无需升级脚本
- **多设备管理**：列出账号所有在线设备、踢指定设备下线（应对账号 3 台设备上限）
- **附带工具**：Windows 连接过程采集脚本、离线单元测试

## 文件结构

| 路径 | 说明 |
|------|------|
| `neu_login.py` | 主脚本：登录 / 状态 / 注销 / 守护 / 多设备管理（CPython 3.6+，Windows/Linux 通用） |
| `neu_login_esp32.py` | ESP32 MicroPython 版：可独立运行，或作为库集成至业务代码 |
| `test_neu_login.py` | 离线单元测试（不联网、不需要凭据） |
| `capture_connection.ps1` | Windows 连接过程日志采集脚本（用于连接过程分析与排障） |
| `debian/` | Linux 主机一键部署（Debian 及兼容发行版；PC / 服务器 / 树莓派 / 开发板 / 随身 WiFi 设备），见 [`debian/部署指南.md`](debian/部署指南.md) |

## 快速开始（PC）

```powershell
# 一键登录（首次，同时保存凭据）
python neu_login.py -u 你的学号 -p 你的密码 --save

# 之后登录只需
python neu_login.py

# 断线自动重连守护（Ctrl+C 退出）
python neu_login.py --watch

# 在线状态与流量 / 注销 / 链路自检
python neu_login.py --status
python neu_login.py --logout
python neu_login.py --test

# 多设备管理（账号最多 3 台在线，超限登录会被拒）
python neu_login.py --devices
python neu_login.py --kick 172.26.x.x

# 离线单元测试
python test_neu_login.py
```

## ESP32 版

**方式 A：独立运行（常驻认证设备）**

1. 编辑 `neu_login_esp32.py` 顶部 CONFIG 区，填入 `USERNAME` / `PASSWORD`
2. 上传到 ESP32 并命名为 `main.py`（mpremote / Thonny / ampy 均可）
3. 上电自动连 WiFi 并登录；板载 LED 亮 = 在线，灭 = 掉线
4. 同一文件也可直接在 PC 上调试：`python neu_login_esp32.py check`

**方式 B：作为库集成到自己的业务代码**

本文件被 `import` 时不会自动启动，可直接作为模块使用：

```python
# main.py (你自己的业务入口)
import neu_login_esp32 as neu

neu.wifi_connect()                              # 连 WiFi；也可自行管理连接

while True:
    ok, msg = neu.ensure_online("学号", "密码")   # 主循环安全点: 掉线/幽灵会话自动重登
    # ... 你的业务逻辑 ...
```

可用 API（均在模块顶层导出）：

| 函数 | 说明 |
|------|------|
| `ensure_online(username=None, password=None)` | **联网保障，推荐入口**：已在线且外网可达时立即返回（开销仅两次小请求）；掉线或幽灵会话时自动重新登录。返回 `(ok, msg)`；参数省略时使用 CONFIG 区凭据 |
| `login(username, password)` | 执行完整认证流程，含在线预检与幽灵会话注销重建。返回 `(ok, msg)` |
| `check_online()` | 查询门户在线状态。在线返回字段列表（`[0]` 学号、`[8]` 本机 IP 等），离线返回 `None` |
| `probe_internet()` | 真实外网探测。返回 `"ok"`（联网正常）/ `"hijacked"`（流量被劫持，即幽灵会话）/ `"unknown"`（无法判断） |
| `logout()` | 注销当前会话（更换设备时释放在线名额） |
| `wifi_connect(ssid, timeout)` | 连接 WiFi（默认 CONFIG 区 `WIFI_SSID`）。仅 MicroPython 下可用；自行管理网络连接时无需调用 |

> **内存注意**：登录瞬时堆占用较大（TLS + RSA-2048 大整数运算）。请在主循环中**顺序调用** `ensure_online()`，不要与业务逻辑并发执行，也不要在中断回调中调用；业务较重的应用建议选用带 PSRAM 的 ESP32 模组。

## Linux 主机部署（Debian 及兼容发行版）

见 [`debian/部署指南.md`](debian/部署指南.md)。核心方案 `sudo sh setup.sh` 一键完成，之后：

- **事件驱动**：WiFi 连接 / 连通性变化时秒级触发登录（NetworkManager dispatcher）
- **定时巡检**：每 5 分钟检查在线 / 幽灵会话 / 掉线（systemd timer，无常驻进程，对低内存、小容量存储设备友好）

部署套件依赖 systemd 与 NetworkManager，适用于 Debian / Ubuntu / Raspberry Pi OS 等主流发行版；OpenWrt 等未使用 systemd 的系统请安装 Python 3 后直接运行 `neu_login.py`（无开机自启）。Windows 无需部署套件，直接 `python neu_login.py --watch` 即可。

## 工作原理

```
GET  ipgw.neu.edu.cn/v1/srun_portal_sso       → CAS 跳转地址
GET  pass.neu.edu.cn/tpass/login              → lt 令牌 + 会话 Cookie
POST rsa=RSA2048(PKCS#1 v1.5, 学号+密码) ...   → CAS 认证
302  + ticket                                 → 回门户校验
GET  /srun_portal_success                     → 认证收尾, 通知 AC 放行流量
GET  /cgi-bin/rad_user_info                   → 在线验证 + 真实联网探测
```

两个关键设计：

- **service 参数必须带 ac_id**：CAS 认证通过后，门户需要 ac_id（接入控制器编号）才会通知 AC 放行流量；缺失时只建立 radius 记录，表现为"显示在线但无法上网"的幽灵会话。脚本登录时自动补全，并从劫持 URL 动态检测本网段真实编号（默认 16）。
- **真实联网探测**：仅查询在线状态不足以发现幽灵会话，脚本额外发起真实外网请求（同时检测 302 重定向与页面注入两种劫持形态），发现劫持自动注销重建。

## 凭据与安全

- 凭据以**明文**保存（每次登录需用原始密码做 RSA 加密，无法加密存储）：Windows = 脚本同目录 `.neu_credentials.json`；Linux root = `/etc/neu/credentials.json`；Linux 普通用户 = `~/.config/neu/credentials.json`
- Linux 下凭据文件权限为 600，仅文件属主可读（Windows 无此权限模型，共用电脑请注意）
- 本机开启代理（如 Clash）不影响使用：脚本一律直连校园网服务器、不经过系统代理，在线探测结果也不会被代理干扰
- 凭据文件已列入 `.gitignore`，请勿提交到仓库或分享给他人

## 其他说明

- **公钥同步**：RSA 公钥（`PUBKEY_B64`）在 `neu_login.py` 与 `neu_login_esp32.py` 中各内置一份（运行环境不同无法共用）；学校轮换密钥时脚本会自动在线刷新，若需更新内置默认公钥请两处同步修改
- **适用范围**：针对东北大学（南湖校区）校园网（深澜门户 + CAS 统一身份认证）实现与验证；其他校区或学校若认证系统相同可自行尝试，不作保证

## 免责声明

- 本项目仅供学习研究及**使用者本人账号的自动登录**使用，与东北大学及其网络管理部门无任何关联，亦未获得其任何授权或认可
- 仅支持使用者本人的统一身份认证凭据；不得用于代他人认证、批量认证、账号共享或任何规避计费、突破限制的用途
- 严禁将本项目用于对校园网或任何网络设施的扫描、压力测试、攻击或其他滥用行为
- 使用者应遵守所在学校网络管理规定及适用法律法规；因使用本项目产生的一切后果由使用者自行承担
- 本项目按"现状"提供，不提供任何形式的担保

## 版本

- **v1.0** 首个发布版本

## 许可证

本项目以 [GPL-3.0-or-later](LICENSE) 许可发布，即 GNU GPL 第 3 版或（由你选择的）任意更高版本。各源码文件头部附有 SPDX 标识。
