# Windows evasion test: how many short-lived child processes does a POLLING
# detector miss, and does process-name masquerade fool a name-based detector?
# Defensive research against my own detector. Benign: children just exit.
$ErrorActionPreference='Continue'
function M($k,$v){ Write-Output ("MEASURED`t{0}`t{1}" -f $k,$v) }

# --- Evasion 1: polling miss rate for short-lived processes ------------------
$N = 60
$seen = @{}
$stop = $false
# poller thread: hammer Get-Process, record distinct child PIDs matching marker
$rs = [runspacefactory]::CreateRunspace(); $rs.Open()
$rs.SessionStateProxy.SetVariable('seen',$seen)
$ps = [powershell]::Create(); $ps.Runspace=$rs
$ps.AddScript({
  $end=(Get-Date).AddSeconds(4)
  while((Get-Date) -lt $end){
    Get-CimInstance Win32_Process -Filter "Name='ameenmark.exe'" -ErrorAction SilentlyContinue | ForEach-Object { $seen[$_.ProcessId]=1 }
  }
}) | Out-Null
$h=$ps.BeginInvoke()
# make a marker binary = copy of cmd.exe, spawn N short-lived instances
$mark="$env:TEMP\ameenmark.exe"; Copy-Item "$env:SystemRoot\System32\cmd.exe" $mark -Force
Start-Sleep -Milliseconds 200
1..$N | ForEach-Object { Start-Process $mark "/c exit" -WindowStyle Hidden; Start-Sleep -Milliseconds 35 }
Start-Sleep -Seconds 1
$stop=$true; $ps.EndInvoke($h) | Out-Null; $rs.Close()
M "polling_children_spawned" $N
M "polling_children_caught" $seen.Count
M "polling_recall_pct" ([math]::Round(100.0*$seen.Count/$N,1))

# --- Evasion 2: argv/name masquerade — does the PROCESS still have a parent? --
$svc="$env:TEMP\svchost.exe"; Copy-Item "$env:SystemRoot\System32\cmd.exe" $svc -Force
$p=Start-Process $svc "/c ping -n 3 127.0.0.1 >NUL" -PassThru -WindowStyle Hidden
Start-Sleep -Milliseconds 500
$ci=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction SilentlyContinue
M "masq_process_name" ($ci.Name)
M "masq_parent_pid_visible" ($(if($ci.ParentProcessId){"yes:"+$ci.ParentProcessId}else{"no"}))
M "masq_real_image_path" ($(if($ci.ExecutablePath){"exposed:"+(Split-Path $ci.ExecutablePath -Leaf)}else{"hidden"}))
try{$p|Stop-Process -Force -EA SilentlyContinue}catch{}
