# =============================================================================
# deploy/client_stop.ps1 — cipherbox 客户端停止（常驻 Agent + LO 加密服务）
#
# 精确匹配进程命令行，绝不误杀无关 python/soffice：
#   * Agent: python.exe 且命令行含 "-m agent"（本仓库的常驻程序/launcher）
#   * LO 服务: soffice.exe/soffice.bin 且命令行含 cipherbox-profile（本系统专用 profile）
# 幂等：无匹配进程时打印提示并正常退出 0；只打印被停止的进程，不做二次确认查询。
#
# 用法（普通用户即可，无需管理员）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File deploy\client_stop.ps1
# =============================================================================
[CmdletBinding()]
param()
$ErrorActionPreference = "Stop"

function Ok($msg)   { Write-Host "[stop] $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "[stop] $msg" -ForegroundColor Yellow }

# -- 1. 停常驻 Agent（python.exe 且命令行含 -m agent）---------------------------------
$agents = @(Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match '-m\s+agent' })
if ($agents.Count -gt 0) {
    foreach ($p in $agents) {
        Write-Host "[stop] 停止 Agent: PID $($p.ProcessId) $($p.CommandLine)"
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Ok "已停止 $($agents.Count) 个 Agent 进程"
} else {
    Ok "没有运行中的 Agent 进程"
}

# -- 2. 停 LO 加密服务（soffice 且命令行含 cipherbox-profile）--------------------------
$lo = @(Get-CimInstance Win32_Process -Filter "Name='soffice.exe' OR Name='soffice.bin'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'cipherbox-profile' })
if ($lo.Count -gt 0) {
    Warn "注意: LO 进程被强制结束，受控会话中未保存的编辑会丢失。"
    foreach ($p in $lo) {
        Write-Host "[stop] 停止 LO: PID $($p.ProcessId) $($p.Name)"
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Ok "已停止 $($lo.Count) 个 LO 加密服务进程"
} else {
    Ok "没有运行中的 LO 加密服务进程 (cipherbox-profile)"
}

# -- 完成 ---------------------------------------------------------------------------
Ok "cipherbox 客户端已全部停止。重新启动: powershell -NoProfile -ExecutionPolicy Bypass -File deploy\client_start.ps1"
exit 0
