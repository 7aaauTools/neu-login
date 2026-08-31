# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 7aaau
# ============================================================
# NEU 校园网连接全过程离线采集脚本
# 用途: 断开WiFi前后运行, 完整记录 连接->DHCP->DNS->认证门户劫持->上网 的全过程
# 特性: 完全离线工作, 不依赖互联网和Agent, 所有日志落盘供事后分析
#
# 用法:
#   1. 以当前网络正常时启动:  powershell -ExecutionPolicy Bypass -File .\capture_connection.ps1
#   2. 脚本开始记录后, 手动断开 WLAN, 再重新连接 NEU-2.4G
#   3. 在浏览器完成认证(或运行 python neu_login.py 自动认证)
#   4. 确认上网恢复后, 回到此窗口按 Ctrl+C 结束
#   5. 日志保存在同目录 connection_log_时间戳.txt, 联网后交给Agent分析
# ============================================================

param(
    [string]$Interface = "WLAN",
    [int]$PollMs = 500
)

$ErrorActionPreference = "SilentlyContinue"
$LogFile = Join-Path $PSScriptRoot ("connection_log_{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "HH:mm:ss.fff"
    $line = "[$ts] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
    Write-Host $line
}

function Test-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 1500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($ComputerName, $Port)
        if ($task.Wait($TimeoutMs) -and $client.Connected) { return $true }
        return $false
    } catch { return $false }
    finally { $client.Close() }
}

# ---------- 初始快照 ----------
Write-Log "================ NEU 校园网连接过程采集开始 ================"
Write-Log "系统启动时间相关: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "--- 初始完整网络配置 ---"
ipconfig /all | ForEach-Object { if ($_ -match "\S") { Add-Content -Path $LogFile -Value "    $_" -Encoding UTF8 } }
Write-Log "--- 初始路由表(默认路由) ---"
route print -4 | Select-String "^\s+0\.0\.0\.0" | ForEach-Object { Write-Log "    $($_.Line.Trim())" }

# ---------- 状态检测函数 ----------
function Get-NetState {
    $state = [ordered]@{}

    # 1. 网卡状态
    $adapter = Get-NetAdapter -Name $Interface -ErrorAction SilentlyContinue
    $state.Adapter = if ($adapter) { $adapter.Status } else { "NotFound" }

    # 2. IPv4 地址 (DHCP 获取)
    $ipObj = Get-NetIPAddress -InterfaceAlias $Interface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1
    $state.IPv4 = if ($ipObj) { $ipObj.IPAddress } else { "None" }

    # 3. IPv6 地址
    $ip6Obj = Get-NetIPAddress -InterfaceAlias $Interface -AddressFamily IPv6 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -notlike "fe80::*" -and $_.IPAddress -notlike "169.254.*" } | Select-Object -First 1
    $state.IPv6 = if ($ip6Obj) { "Yes" } else { "None" }

    # 4. 网关可达
    $gw = (Get-NetRoute -InterfaceAlias $Interface -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
           Select-Object -First 1).NextHop
    $state.Gateway = $gw
    if ($gw) {
        $ping = Test-Connection -ComputerName $gw -Count 1 -Quiet
        $state.GwPing = $ping
    } else {
        $state.GwPing = $false
    }

    # 5. DNS 解析能力 (校园DNS 202.118.1.29)
    $state.DNS = Test-TcpPort -ComputerName "202.118.1.29" -Port 53

    # 6. 认证门户可达 (校内地址, 未认证也可达)
    $state.Portal = Test-TcpPort -ComputerName "ipgw.neu.edu.cn" -Port 80

    # 7. HTTP 外网访问 + 劫持检测 (一次请求同时判定两项)
    #    已认证: 200 直连; 未认证: 302 劫持到门户; 断网: 超时/DNS失败
    #    注意: AllowAutoRedirect=false 时 3xx 不抛异常, 302 劫持必须在成功路径识别
    $state.Hijack = "N/A"
    $state.Internet = $false
    try {
        $req = [System.Net.HttpWebRequest]::Create("http://www.baidu.com/")
        $req.Timeout = 2500
        $req.AllowAutoRedirect = $false
        $req.UserAgent = "Mozilla/5.0"
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        if ($code -in 301,302,303,307,308) {
            # 未认证: 302 劫持, 重定向目标在 Location 头
            $loc = $resp.Headers["Location"]
            if ($loc) {
                $state.Hijack = "劫持->$($loc.Substring(0, [Math]::Min(80, $loc.Length)))"
            } else {
                $state.Hijack = "重定向无Location($code)"
            }
        } else {
            $state.Internet = ($code -eq 200)
            $state.Hijack = "无($code直连)"
        }
        $resp.Close()
    } catch [System.Net.WebException] {
        $ex = $_.Exception
        if ($ex.Response) {
            try {
                if ($ex.Response.Headers["Location"]) {
                    $loc = $ex.Response.Headers["Location"]
                    $state.Hijack = "劫持->$($loc.Substring(0, [Math]::Min(80, $loc.Length)))"
                } else {
                    $state.Hijack = "请求失败($($ex.Status))"
                }
            } finally {
                $ex.Response.Close()
            }
        } else {
            $state.Hijack = "请求失败($($ex.Status))"
        }
    } catch {
        $state.Hijack = "异常:$($_.Exception.Message.Substring(0, [Math]::Min(40, $_.Exception.Message.Length)))"
    }

    return $state
}

function Format-State {
    param($State)
    return ($State.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " | "
}

# ---------- 主循环 ----------
Write-Log "--- 进入持续监测模式 (每 $PollMs ms 轮询, 只记录状态变化) ---"
Write-Log "操作提示: 现在可以 断开WLAN -> 重连NEU-2.4G -> 完成认证, 全程会被记录"

$lastState = $null
$lastFullLog = Get-Date
$heartbeats = 0

while ($true) {
    try {
        $state = Get-NetState
        $stateStr = Format-State $state

        if ($stateStr -ne $lastState) {
            # 找出具体变化的字段
            if ($lastState) {
                $changes = @()
                foreach ($key in $state.Keys) {
                    if ($state[$key] -ne $lastState[$key]) {
                        $changes += "$key : $($lastState[$key]) -> $($state[$key])"
                    }
                }
                if ($changes.Count -gt 0) {
                    Write-Log ("状态变化 [" + ($changes -join "; ") + "]")
                }
            } else {
                Write-Log "初始状态: $stateStr"
            }
            $lastState = $state
        }

        # 每60秒输出一次心跳全量状态
        if (((Get-Date) - $lastFullLog).TotalSeconds -ge 60) {
            Write-Log "心跳#$heartbeats : $stateStr"
            $lastFullLog = Get-Date
            $heartbeats++
        }

        Start-Sleep -Milliseconds $PollMs
    } catch {
        Write-Log "采集异常: $($_.Exception.Message)"
        Start-Sleep -Seconds 2
    }
}
