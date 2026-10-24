# Windows tripwire primitives, measured per privilege level. Synthetic decoy only; benign.
$ErrorActionPreference = 'Continue'
function M($k,$v){ Write-Output ("MEASURED`t{0}`t{1}" -f $k,$v) }
try { $t = "C:\Users\Public\ameentmp2"; New-Item -ItemType Directory -Force -Path $t | Out-Null; $env:TEMP=$t; $env:TMP=$t } catch {}
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal($wi)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
M "whoami" $wi.Name
M "is_elevated_admin" $admin

# T1: is NTFS last-access time a usable read tripwire?
$f = Join-Path $t "credentials.bak"
Set-Content -Path $f -Value ("FAKE-CANARY-" * 100)
$old = (Get-Date).AddDays(-2)
try { (Get-Item $f).LastAccessTime = $old } catch { M "lastaccess_set_error" $_.Exception.Message }
$before = (Get-Item $f).LastAccessTime
Start-Sleep -Seconds 2
$null = [IO.File]::ReadAllText($f)
Start-Sleep -Seconds 2
$after = (Get-Item $f).LastAccessTime
M "ntfs_lastaccess_refreshed_by_read" ($after -gt $before)
M "ntfs_lastaccess_before" $before.ToString("o")
M "ntfs_lastaccess_after" $after.ToString("o")
try { (Get-Item $f).LastAccessTime = $old; M "ntfs_lastaccess_forgeable_by_same_user" (((Get-Item $f).LastAccessTime) -eq $old) } catch { M "ntfs_lastaccess_forgeable_by_same_user" ("ERR " + $_.Exception.Message) }
M "fsutil_disablelastaccess" ((& fsutil behavior query disablelastaccess 2>&1 | Out-String).Trim() -replace "\s+"," ")

# T2: can this principal open a real-time kernel file-event trace (PID-attributed file events)?
$name = "AmeenKF" + [guid]::NewGuid().ToString("N").Substring(0,6)
M "etw_kernel_file_realtime_session" ((& logman create trace $name -p "Microsoft-Windows-Kernel-File" -rt -ets 2>&1 | Out-String).Trim() -replace "\s+"," ")
& logman stop $name -ets 2>&1 | Out-Null

# T3: per-process CPU time readable (gap-composition primitive for local inference)?
$ok = 0; $deny = 0
Get-Process | ForEach-Object { try { $null = $_.TotalProcessorTime; $ok++ } catch { $deny++ } }
M "cpu_time_readable_processes" $ok
M "cpu_time_denied_processes" $deny
