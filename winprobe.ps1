# Ameen Windows primitive probe. Measures whether the agent-detection signature
# is observable with DOCUMENTED Win32 APIs, and at what privilege. Benign telemetry:
# enumerate own/other processes, per-PID TCP table, and a Job-object process list.
$ErrorActionPreference = 'Continue'
# Ameen: ensure writable TEMP so Add-Type (C# compile) works for a fresh standard user
try { $t = "C:\Users\Public\ ameentmp".Replace(" ",""); New-Item -ItemType Directory -Force -Path $t | Out-Null; $env:TEMP=$t; $env:TMP=$t } catch {}
function M($k,$v){ Write-Output ("MEASURED`t{0}`t{1}" -f $k,$v) }

# --- privilege context -------------------------------------------------------
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$wp = New-Object Security.Principal.WindowsPrincipal($wi)
$admin = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
M "whoami" $wi.Name
M "is_elevated_admin" $admin

# --- f1: per-PID TCP table via GetExtendedTcpTable (TCP_TABLE_OWNER_PID_ALL=5) --
Add-Type @"
using System;using System.Runtime.InteropServices;
public class Ip {
 [DllImport("iphlpapi.dll",SetLastError=true)]
 public static extern uint GetExtendedTcpTable(IntPtr p,ref int size,bool order,int af,int cls,int res);
}
"@
try {
  $sz=0; [Ip]::GetExtendedTcpTable([IntPtr]::Zero,[ref]$sz,$false,2,5,0) | Out-Null
  $buf=[Runtime.InteropServices.Marshal]::AllocHGlobal($sz)
  $rc=[Ip]::GetExtendedTcpTable($buf,[ref]$sz,$false,2,5,0)
  if($rc -eq 0){
    $n=[Runtime.InteropServices.Marshal]::ReadInt32($buf)
    # each MIB_TCPROW_OWNER_PID = 24 bytes: state,local,localport,remote,remoteport,pid
    $withPid=0; $off=4
    for($i=0;$i -lt $n;$i++){ $op=[Runtime.InteropServices.Marshal]::ReadInt32($buf,$off+20); if($op -gt 0){$withPid++}; $off+=24 }
    M "f1_tcp_rows" $n
    M "f1_rows_with_owning_pid" $withPid
    M "f1_getextendedtcptable" "OK_unprivileged"
  } else { M "f1_getextendedtcptable" ("rc="+$rc) }
  [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
} catch { M "f1_getextendedtcptable" ("ERR "+$_.Exception.Message) }

# --- f2/f5: process ancestry + start time (toolhelp / CIM) -------------------
$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$tot=($procs|Measure-Object).Count
$wppid=($procs|Where-Object {$_.ParentProcessId -ne $null}|Measure-Object).Count
$wstart=($procs|Where-Object {$_.CreationDate -ne $null}|Measure-Object).Count
$wpath=($procs|Where-Object {$_.ExecutablePath}|Measure-Object).Count
M "f2_processes_visible" $tot
M "f2_with_parent_pid" $wppid
M "f5_with_start_time" $wstart
M "f2_with_exe_path" $wpath

# --- U3: Job object full process list incl. descendants ---------------------
Add-Type @"
using System;using System.Runtime.InteropServices;using System.Diagnostics;
public class Jb {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr CreateJobObject(IntPtr a,string n);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool AssignProcessToJobObject(IntPtr j,IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool QueryInformationJobObject(IntPtr j,int c,IntPtr i,int len,IntPtr ret);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(int a,bool inh,int pid);
}
"@
try {
  $job=[Jb]::CreateJobObject([IntPtr]::Zero,$null)
  if($job -eq [IntPtr]::Zero){ M "u3_job" "CreateJobObject_FAILED" } else {
    # launch a cmd that spawns a child and a grandchild, assign to job
    $p=Start-Process cmd.exe "/c ping -n 2 127.0.0.1 >NUL & cmd /c ping -n 2 127.0.0.1 >NUL" -PassThru -WindowStyle Hidden
    $h=[Jb]::OpenProcess(0x1F0FFF,$false,$p.Id)
    $assigned=[Jb]::AssignProcessToJobObject($job,$h)
    M "u3_assign_to_job" $assigned
    Start-Sleep -Milliseconds 800
    # JobObjectBasicProcessIdList = 3
    $len=8+8*64; $buf=[Runtime.InteropServices.Marshal]::AllocHGlobal($len)
    [Runtime.InteropServices.Marshal]::WriteInt32($buf,0,64)   # MaxCount
    $ok=[Jb]::QueryInformationJobObject($job,3,$buf,$len,[IntPtr]::Zero)
    if($ok){
      $inJob=[Runtime.InteropServices.Marshal]::ReadInt32($buf,4) # NumberInList
      M "u3_query_job_processlist" "OK"
      M "u3_processes_in_job_subtree" $inJob
    } else { M "u3_query_job_processlist" ("FAILED gle="+[Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    try{$p|Stop-Process -Force -ErrorAction SilentlyContinue}catch{}
  }
} catch { M "u3_job" ("ERR "+$_.Exception.Message) }

# --- ETW real-time: can we start a kernel-process trace session? ------------
try {
  $s = New-Object System.Diagnostics.Eventing.Reader.EventLogSession
  M "etw_eventlogsession_ctor" "OK"
} catch { M "etw_eventlogsession_ctor" ("ERR "+$_.Exception.Message) }
# logman create (documented to need no admin to CREATE, admin to START kernel)
$lm = (logman query providers 2>&1 | Select-String "Kernel-Process" | Measure-Object).Count
M "etw_kernel_process_provider_listed" $lm
