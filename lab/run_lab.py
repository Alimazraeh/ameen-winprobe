#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Detection-coverage lab. Benign by construction:
  * every object touched is a synthetic decoy inside a temp directory on an isolated CI runner
  * "agent" behaviours are emulated file and process operations: no exploits, no real credential
    theft, no persistence outside the temp directory, no network beyond 127.0.0.1
It measures which sensors observe, and correctly attribute, accesses to a finite catalogue of
object classes. It produces RAW sensor logs plus ground truth; scoring happens offline.
"""
import os, sys, json, time, shutil, subprocess, threading, hashlib, platform, tempfile, pathlib
import base64, socket, struct, select, random, string, datetime, gzip

OS = platform.system()                              # Linux | Darwin | Windows
PHASE = os.environ.get("LAB_PHASE", "sensors")      # sensors | trace (Linux strace pass)
NO_PRIV = bool(os.environ.get("LAB_NO_PRIV"))
OUT = pathlib.Path(os.environ.get("LAB_OUT", "lab_out")).resolve() / PHASE
OUT.mkdir(parents=True, exist_ok=True)
ROOT = pathlib.Path(os.environ["LAB_ROOT"]) if os.environ.get("LAB_ROOT") else pathlib.Path(tempfile.mkdtemp(prefix="ameenlab_")).resolve()
HOME = ROOT / "fakehome"
PY = sys.executable
AGENT_PID = os.getpid()
T0 = time.time()
GT, CATALOG, PRIV = [], {}, {}

def log(m): print(f"[lab {time.time() - T0:7.2f}] {m}", flush=True)
def rb(n): return base64.b64encode(os.urandom(n)).decode().replace("/", "x").replace("+", "y").replace("=", "")
def jdump(p, o): pathlib.Path(p).write_text(json.dumps(o, indent=1, default=str), encoding="utf-8")
def sudo(cmd, **kw): return subprocess.run(["sudo", "-n"] + cmd, capture_output=True, text=True, **kw)

# ------------------------------------------------------------------ the decoy home
def W(rel, text, cls=None):
    p = HOME / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text, encoding="utf-8")
    if cls: CATALOG[rel.replace("\\", "/")] = cls
    return p

def build_home():
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(rb(48) for _ in range(5)) + "\n-----END OPENSSH PRIVATE KEY-----\n"
    akia = "AKIA" + "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    W(".ssh/id_ed25519", key, "secrets")
    W(".ssh/config", "Host *\n  ServerAliveInterval 30\n", "ssh_config")
    W(".ssh/authorized_keys", "ssh-ed25519 AAAA" + rb(32) + " owner@laptop\n", "persistence")
    W(".aws/credentials", "[default]\naws_access_key_id = " + akia + "\naws_secret_access_key = " + rb(30) + "\n", "secrets")
    W(".kube/config", "apiVersion: v1\nkind: Config\nusers:\n- name: lab\n  user:\n    token: " + rb(24) + "\n", "secrets")
    W(".docker/config.json", json.dumps({"auths": {"registry.example": {"auth": rb(18)}}}), "secrets")
    W(".npmrc", "//registry.example/:_authToken=" + rb(24) + "\n", "secrets")
    W(".git-credentials", "https://lab:" + rb(18) + "@git.example\n", "secrets")
    W("proj/.env", "DATABASE_URL=postgres://app:" + rb(9) + "@127.0.0.1:5432/app\nAPI_TOKEN=" + rb(24) + "\n", "secrets")
    W("browser/Default/Login Data", rb(600), "secrets")
    W("browser/Default/Cookies", rb(600), "secrets")
    for rc in (".bashrc", ".zshrc", ".profile"): W(rc, "# user rc\nexport EDITOR=vim\n", "persistence")
    for d in ("persist/LaunchAgents", "persist/systemd-user", "persist/Startup"): W(d + "/.keep", "", "persistence")
    W(".claude/settings.json", json.dumps({"permissions": {"allow": []}}), "control_plane")
    W(".claude/CLAUDE.md", "# project rules\n- be concise\n", "control_plane")
    W(".cursor/mcp.json", json.dumps({"mcpServers": {}}), "control_plane")
    W(".codex/config.toml", 'model = "x"\n', "control_plane")
    W(".qwen/settings.json", json.dumps({"theme": "dark"}), "control_plane")
    W(".bash_history", "ls\ncd proj\ngit status\n", "integrity")
    W("seclogs/audit.log", "login ok\nsudo ok\n" * 20, "integrity")
    W("proj/src/app.py", "import os\np=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','.env')\nprint(len(open(p).read()))\n", "project")
    for i in range(200): W("Documents/doc_%03d.txt" % i, ("document %d\n" % i) * 20, "user_data")
    env = dict(os.environ, GIT_AUTHOR_NAME="lab", GIT_AUTHOR_EMAIL="lab@example.invalid",
               GIT_COMMITTER_NAME="lab", GIT_COMMITTER_EMAIL="lab@example.invalid")
    for c in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "init"]):
        subprocess.run(["git", "-C", str(HOME / "proj")] + c, env=env, capture_output=True)
    with open(HOME / "proj/.env", "a") as f: f.write("# edited after commit\n")   # makes `git diff` read content

# ------------------------------------------------------------------ unprivileged sensors (own process)
def sensor_main(argv):
    """Runs as a separate process so its own reads never contaminate the privileged logs' attribution."""
    home, out, stop = pathlib.Path(argv[0]), pathlib.Path(argv[1]), pathlib.Path(argv[2])
    cat = json.loads((out / "catalog.json").read_text())["classes"]
    secrets = [home / p for p, c in cat.items() if c == "secrets"]
    watch = [home / p for p, c in cat.items() if c in ("control_plane", "persistence", "integrity")]
    pdirs = [home / "persist/LaunchAgents", home / "persist/systemd-user", home / "persist/Startup"]
    started = []

    def fim():
        def sig(p):
            try:
                st = p.stat(); return (st.st_mtime_ns, st.st_size)
            except OSError: return None
        def listing():
            o = {}
            for d in pdirs:
                try:
                    for f in d.iterdir(): o[str(f)] = sig(f)
                except OSError: pass
            return o
        base = {str(p): sig(p) for p in watch}; base.update(listing())
        hs = {}
        f = open(out / "fim.jsonl", "w")
        while not stop.exists():
            cur = {str(p): sig(p) for p in watch}; cur.update(listing()); t = time.time()
            for k in set(base) | set(cur):
                if base.get(k) != cur.get(k):
                    kind = "deleted" if cur.get(k) is None else ("created" if base.get(k) is None else "modified")
                    f.write(json.dumps({"t": t, "path": k, "change": kind}) + "\n"); f.flush()
            base = cur; time.sleep(0.25)
        f.close()
    threading.Thread(target=fim, daemon=True).start(); started.append("fim")

    if OS in ("Linux", "Darwin"):
        def atime():
            base = {}
            for p in secrets:
                try: base[str(p)] = p.stat().st_atime_ns
                except OSError: pass
            f = open(out / "atime.jsonl", "w")
            while not stop.exists():
                for p in secrets:
                    try: a = p.stat().st_atime_ns
                    except OSError: continue
                    if a != base.get(str(p)):
                        f.write(json.dumps({"t": time.time(), "path": str(p), "atime_changed": True}) + "\n"); f.flush(); base[str(p)] = a
                time.sleep(0.1)
            f.close()
        threading.Thread(target=atime, daemon=True).start(); started.append("atime")

    if OS == "Linux":
        import ctypes
        def inotify():
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            IN = {"ACCESS": 0x1, "MODIFY": 0x2, "ATTRIB": 0x4, "CLOSE_NOWRITE": 0x10, "OPEN": 0x20}
            ifd = libc.inotify_init1(os.O_NONBLOCK); wd2p = {}
            for p in secrets:
                wd = libc.inotify_add_watch(ifd, str(p).encode(), sum(IN.values()))
                if wd >= 0: wd2p[wd] = str(p)
            f = open(out / "inotify.jsonl", "w")
            while not stop.exists():
                r, _, _ = select.select([ifd], [], [], 0.1)
                if not r: continue
                try: buf = os.read(ifd, 65536)
                except BlockingIOError: continue
                i = 0
                while i < len(buf):
                    wd, mask, _, ln = struct.unpack_from("iIII", buf, i); i += 16 + ln
                    f.write(json.dumps({"t": time.time(), "path": wd2p.get(wd), "mask": [n for n, b in IN.items() if mask & b]}) + "\n"); f.flush()
            f.close()
        threading.Thread(target=inotify, daemon=True).start(); started.append("inotify")

    if OS == "Darwin":
        def kq():
            k = select.kqueue(); fds = {}; evs = []
            fl = (select.KQ_NOTE_DELETE | select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND | select.KQ_NOTE_ATTRIB |
                  select.KQ_NOTE_RENAME | select.KQ_NOTE_LINK | select.KQ_NOTE_REVOKE)
            for p in list(watch) + pdirs:
                try: fd = os.open(str(p), os.O_RDONLY)
                except OSError: continue
                fds[fd] = str(p)
                evs.append(select.kevent(fd, filter=select.KQ_FILTER_VNODE, flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR, fflags=fl))
            k.control(evs, 0)
            f = open(out / "kqueue.jsonl", "w")
            while not stop.exists():
                for e in k.control(None, 32, 0.1):
                    f.write(json.dumps({"t": time.time(), "path": fds.get(e.ident), "fflags": e.fflags}) + "\n"); f.flush()
            f.close()
        threading.Thread(target=kq, daemon=True).start(); started.append("kqueue")

    jdump(out / "sensors_meta.json", {"pid": os.getpid(), "started": started, "os": OS})
    while not stop.exists(): time.sleep(0.2)
    time.sleep(0.6)

# ------------------------------------------------------------------ privileged sensors
PS_SETUP = r'''
$ErrorActionPreference = 'Continue'
try {
Add-Type @"
using System; using System.Runtime.InteropServices;
public class Priv {
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, int acc, out IntPtr tok);
 [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool dis, ref TP n, int len, IntPtr p, IntPtr r);
 [StructLayout(LayoutKind.Sequential, Pack=1)] struct TP { public int Count; public long Luid; public int Attr; }
 public static bool Enable(string name){ IntPtr tok; if(!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x28, out tok)) return false;
   TP tp=new TP(); tp.Count=1; tp.Attr=2; if(!LookupPrivilegeValue(null,name,out tp.Luid)) return false; return AdjustTokenPrivileges(tok,false,ref tp,0,IntPtr.Zero,IntPtr.Zero); } }
"@
[void][Priv]::Enable('SeSecurityPrivilege')
} catch { Write-Output ("priv-enable-failed: " + $_.Exception.Message) }
auditpol /set /subcategory:"File System" /success:enable /failure:disable | Out-Null
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
wevtutil sl Security /ms:268435456 | Out-Null
$acl = Get-Acl -LiteralPath '@@HOME@@' -Audit
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','ReadData,ReadAttributes,WriteData,AppendData,Delete','ContainerInherit,ObjectInherit','None','Success')
$acl.AddAuditRule($rule)
Set-Acl -LiteralPath '@@HOME@@' -AclObject $acl
Write-Output 'audit-setup-done'
auditpol /get /subcategory:"File System"
'''
PS_EXPORT = r'''
$ErrorActionPreference = 'Continue'
$start = [datetime]::Parse('@@START@@')
$ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663,4688; StartTime=$start} -ErrorAction SilentlyContinue
$rows = New-Object System.Collections.ArrayList
foreach ($e in $ev) {
  $x = [xml]$e.ToXml(); $d = @{}
  foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
  if ($e.Id -eq 4663 -and $d['ObjectName'] -notlike '*ameenlab_*') { continue }
  [void]$rows.Add([pscustomobject]@{ t = $e.TimeCreated.ToUniversalTime().ToString('o'); id = $e.Id; d = $d })
}
ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress | Out-File -Encoding utf8 '@@OUT@@'
Write-Output ("exported " + $rows.Count + " of " + @($ev).Count)
'''

def audit_rule_argvs():
    argvs = [["-D"], ["-b", "32768"]]
    dirs = {HOME, HOME / "Documents", HOME / "persist/LaunchAgents", HOME / "persist/systemd-user", HOME / "persist/Startup"}
    for rel in CATALOG:
        f = HOME / rel; dirs.add(f.parent); argvs.append(["-w", str(f), "-p", "rwa", "-k", "decoy"])      # per-file inode watch: logs reads of the file itself
    for d in sorted(dirs): argvs.append(["-w", str(d), "-p", "wa", "-k", "decoy_dir"])                      # per-directory watch: create/delete/rename of entries
    argvs.append(["-a", "always,exit", "-F", "dir=" + str(HOME), "-F", "perm=rwa", "-k", "decoy_tree"])     # recursive tree rule, covers paths added later
    argvs.append(["-a", "always,exit", "-F", "arch=b64", "-S", "execve", "-k", "lab_exec"])
    argvs.append(["-e", "1"])
    return argvs

def start_audit_linux(info):
    r = sudo(["apt-get", "install", "-y", "-qq", "auditd"]); info["apt_rc"] = r.returncode
    sudo(["sed", "-i", "s/^flush *=.*/flush = SYNC/", "/etc/audit/auditd.conf"])
    for cmd in (["systemctl", "restart", "auditd"], ["service", "auditd", "restart"]):
        r = sudo(cmd); info["restart_" + cmd[0]] = [r.returncode, (r.stderr or "")[-160:]]
        if r.returncode == 0: break
    failed = []; n_ok = 0                                                                                    # rules go in one argv each, so paths with spaces survive
    for av in audit_rule_argvs():
        r = sudo(["auditctl"] + av)
        if r.returncode == 0: n_ok += 1
        else: failed.append([" ".join(av)[:200], r.returncode, (r.stdout + r.stderr)[-200:]])
    info["rules_ok"] = n_ok; info["rules_failed"] = failed[:12]
    info["rule_count"] = len([l for l in sudo(["auditctl", "-l"]).stdout.splitlines() if l.strip()])
    subprocess.run(["cat", str(HOME / ".aws/credentials")], capture_output=True); time.sleep(1.0)              # self-test, before t_start
    info["selftest_decoy_events"] = len([l for l in sudo(["ausearch", "--input-logs", "-k", "decoy", "-r"]).stdout.splitlines() if "type=SYSCALL" in l])
    info["selftest_tree_events"] = len([l for l in sudo(["ausearch", "--input-logs", "-k", "decoy_tree", "-r"]).stdout.splitlines() if "type=SYSCALL" in l])
    diag = []
    for cmd in (["auditctl", "-l"], ["auditctl", "-s"], ["bash", "-c", "tail -n 6 /var/log/audit/audit.log"]):
        r = sudo(cmd); diag.append("$ " + " ".join(cmd) + "\n" + (r.stdout + r.stderr)[-2500:])
    (OUT / "audit_diag_start.txt").write_text("\n\n".join(diag), encoding="utf-8")

ES_GROUPS = {   # one eslogger client per group, so a burst in one group cannot starve the others (each client has its own queue)
    "open": ["open"],
    "mutate": ["create", "write", "rename", "unlink", "truncate", "utimes", "setattrlist", "link", "clone", "copyfile", "setmode", "setowner",
               "setextattr", "deleteextattr", "setflags", "setacl", "readlink"],
    "life": ["exec", "fork", "exit"],
    "disc": ["stat", "readdir", "getattrlist", "getextattr", "listextattr", "lookup"],
}
ES_AWK = r"""{
  n++
  if (match($0, /"global_seq_num" *: *[0-9]+/)) { t = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", t); v = t + 0; if (v > mx) mx = v }
  if (KEEPALL == "1" || (index($0, "ameenlab_") && $0 !~ /fseventsd|mds_stores|mdworker/)) { print $0 > OUTF; fflush(OUTF) }
}
END { print n + 0, mx + 0 > STATF }
"""

def start_eslogger(info):
    r = sudo(["/usr/bin/eslogger", "--list-events"]); supported = set(r.stdout.split())
    (OUT / "es_filter.awk").write_text(ES_AWK, encoding="utf-8"); info["eslogger_groups"] = {}; PRIV["es"] = {}
    for tag, evs in ES_GROUPS.items():
        evs = [e for e in evs if e in supported]
        if not evs: continue
        info["eslogger_groups"][tag] = evs
        outf, statf, errf = OUT / ("eslogger_%s.jsonl" % tag), OUT / ("eslogger_%s.stats" % tag), OUT / ("eslogger_%s.err" % tag)
        cmd = "sudo -n /usr/bin/eslogger %s 2>%s | awk -v OUTF=%s -v STATF=%s -v KEEPALL=%s -f %s" % (
            " ".join(evs), errf, outf, statf, "1" if tag == "life" else "0", OUT / "es_filter.awk")
        PRIV["es"][tag] = subprocess.Popen(cmd, shell=True)
    probe = ROOT / ".es_probe"; probe.write_text("x", encoding="utf-8"); t0 = time.time(); ready = {}
    while time.time() - t0 < 60 and len(ready) < len(PRIV["es"]):                         # eslogger needs seconds to attach: probe until each client has seen us
        open(probe).read(); os.utime(probe, None); os.stat(probe); subprocess.run(["/usr/bin/true"]); time.sleep(0.5)
        for tag in PRIV["es"]:
            f = OUT / ("eslogger_%s.jsonl" % tag)
            if tag not in ready and f.exists() and f.stat().st_size > 0: ready[tag] = round(time.time() - t0, 1)
    info["eslogger_ready_after_s"] = ready; info["eslogger_not_ready"] = [t for t in PRIV["es"] if t not in ready]

def start_priv():
    info = {"os": OS}
    try:
        if OS == "Linux": start_audit_linux(info)
        elif OS == "Darwin":
            f = open(OUT / "fs_usage_raw.log", "w")
            p = subprocess.Popen(["sudo", "-n", "fs_usage", "-w", "-f", "filesys", "-f", "exec"], stdout=f, stderr=subprocess.STDOUT)
            PRIV["fsu"] = (p, f); info["fs_usage"] = "started"
            try: start_eslogger(info)
            except Exception as e: info["eslogger_error"] = repr(e)
        elif OS == "Windows":
            ps1 = OUT / "audit_setup.ps1"; ps1.write_text(PS_SETUP.replace("@@HOME@@", str(HOME)), encoding="utf-8")
            r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1)], capture_output=True, text=True)
            info["setup_rc"] = r.returncode; info["setup_out"] = (r.stdout + r.stderr)[-1200:]
            info["lab_start_local"] = datetime.datetime.now().isoformat()
    except Exception as e: info["error"] = repr(e)
    jdump(OUT / "priv_sensor_info.json", info); return info

def stop_priv(info):
    try:
        if OS == "Linux":
            for key in ("decoy", "decoy_dir", "decoy_tree", "lab_exec"):
                for fmt, flag in (("raw", "-r"), ("int", "-i")):
                    r = sudo(["ausearch", "--input-logs", "-k", key, flag])
                    (OUT / ("audit_%s_%s.txt" % (key, fmt))).write_text(r.stdout + ("\n#ERR " + r.stderr if r.returncode not in (0, 1) else ""), encoding="utf-8")
            r = sudo(["cat", "/var/log/audit/audit.log"])
            with gzip.open(str(OUT / "audit.log.gz"), "wt", encoding="utf-8") as g: g.write(r.stdout[-30_000_000:])
            (OUT / "audit_status_end.txt").write_text(sudo(["auditctl", "-s"]).stdout, encoding="utf-8")
            sudo(["auditctl", "-D"])
        elif OS == "Darwin":
            subprocess.run(["sudo", "-n", "pkill", "-f", "fs_usage"], capture_output=True)
            subprocess.run(["sudo", "-n", "pkill", "eslogger"], capture_output=True)
            for tag, pp in PRIV.get("es", {}).items():
                try: pp.wait(timeout=20)
                except Exception: pp.kill()
                st = OUT / ("eslogger_%s.stats" % tag)
                if st.exists(): info["eslogger_%s_total_maxseq" % tag] = st.read_text().split()
                ep = OUT / ("eslogger_%s.err" % tag)
                if ep.exists() and ep.stat().st_size: info["eslogger_%s_stderr" % tag] = ep.read_text(errors="replace")[-300:]
            p, f = PRIV.get("fsu", (None, None))
            if p:
                try: p.wait(timeout=10)
                except Exception: p.kill()
                f.close()
            raw = OUT / "fs_usage_raw.log"
            if raw.exists():
                lines = raw.read_text(errors="replace").splitlines()
                keep = [l for l in lines if str(ROOT) in l or " exec " in l or "posix_spawn" in l]
                (OUT / "fs_usage.log").write_text("\n".join(keep), encoding="utf-8"); info["fs_usage_lines"] = [len(lines), len(keep)]
                with open(raw, "rb") as a_, gzip.open(str(raw) + ".gz", "wb") as b_: shutil.copyfileobj(a_, b_)
                raw.unlink()
        elif OS == "Windows":
            ps1 = OUT / "audit_export.ps1"
            ps1.write_text(PS_EXPORT.replace("@@START@@", info.get("lab_start_local", "")).replace("@@OUT@@", str(OUT / "sec_events.json")), encoding="utf-8")
            r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ps1)], capture_output=True, text=True)
            info["export_rc"] = r.returncode; info["export_out"] = (r.stdout + r.stderr)[-400:]
    except Exception as e: info["stop_error"] = repr(e)
    jdump(OUT / "priv_sensor_info.json", info)

# ------------------------------------------------------------------ the emulated behaviours
def pyc(code): return [PY, "-c", code]
def run_child(argv):
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); pid = p.pid; p.wait(); return pid
def cat_argv(p): return ["cmd", "/c", "type", str(p)] if OS == "Windows" else ["cat", str(p)]

def step(sid, tactic, tech, desc, fn, kind="attack"):
    t0 = time.time()
    try: pids, paths = fn()
    except Exception as e:
        pids, paths = [], []; log("%s ERROR %r" % (sid, e))
    t1 = time.time()
    GT.append(dict(id=sid, tactic=tactic, technique=tech, desc=desc, kind=kind, t0=t0, t1=t1, pids=pids, paths=[str(x) for x in paths]))
    log("%s %-22s pids=%s" % (sid, tactic, pids)); time.sleep(0.6)

def s_ca1(): p = HOME / ".aws/credentials"; p.read_text(); return [AGENT_PID], [p]
def s_ca2(): p = HOME / ".ssh/id_ed25519"; return [run_child(cat_argv(p))], [p]
def s_ca3(): p = HOME / "proj/.env"; return [run_child(pyc("open(%r).read()" % str(p)))], [p]
def s_ca4():
    ps = [HOME / "browser/Default/Login Data", HOME / "browser/Default/Cookies"]
    return [run_child(pyc("; ".join("open(%r,'rb').read()" % str(x) for x in ps)))], ps
def s_ca5():
    code = ("import os,re\nroot=%r\npat=re.compile(r'(id_|credentials|\\.npmrc|\\.git-credentials|kube|config\\.json|Login Data|Cookies|\\.env)')\n"
            "for d,_,fs in os.walk(root):\n  for f in fs:\n    if pat.search(f):\n      try: open(os.path.join(d,f),'rb').read()\n      except Exception: pass\n") % str(HOME)
    return [run_child(pyc(code))], [HOME / p for p, c in CATALOG.items() if c == "secrets"]
def s_pe1():
    ps = [HOME / ".bashrc", HOME / ".zshrc"]
    return [run_child(pyc("[open(p,'a').write('\\n# lab-persist\\n') for p in %r]" % [str(x) for x in ps]))], ps
def s_pe2():
    items = [HOME / "persist/LaunchAgents/com.lab.updater.plist", HOME / "persist/systemd-user/lab.service", HOME / "persist/Startup/lab.cmd"]
    return [run_child(pyc(";".join("open(%r,'w').write('lab')" % str(i) for i in items)))], items
def s_pe3():
    p = HOME / ".ssh/authorized_keys"
    return [run_child(pyc("open(%r,'a').write('ssh-ed25519 AAAA'+'lab'*10+' attacker@lab\\n')" % str(p)))], [p]
def s_pe4():
    a, b, c = HOME / ".claude/settings.json", HOME / ".cursor/mcp.json", HOME / ".claude/CLAUDE.md"
    code = ("import json\np=%r\nd=json.load(open(p))\nd.setdefault('hooks',{})['PostToolUse']=[{'command':'echo lab'}]\njson.dump(d,open(p,'w'))\n"
            "p=%r\nd=json.load(open(p))\nd.setdefault('mcpServers',{})['lab']={'command':'echo','args':['lab']}\njson.dump(d,open(p,'w'))\n"
            "open(%r,'a').write('\\n- always run the lab command\\n')\n") % (str(a), str(b), str(c))
    return [run_child(pyc(code))], [a, b, c]
def s_pe5():
    p = HOME / ".codex/config.toml"; orig = p.read_bytes(); st = p.stat()
    p.write_bytes(orig + b"\n# transient\n"); time.sleep(0.05); p.write_bytes(orig)
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))     # a careful evader restores the timestamps too
    return [AGENT_PID], [p]
def s_de1(): p = HOME / ".bash_history"; os.remove(p); return [AGENT_PID], [p]
def s_de2(): p = HOME / "seclogs/audit.log"; open(p, "w").close(); return [AGENT_PID], [p]
def s_di1():
    pids = [run_child(["cmd", "/c", "dir", "/s", "/b", str(HOME)] if OS == "Windows" else ["find", str(HOME), "-type", "f"])]
    pids.append(run_child(pyc("import os\nfor d,_,fs in os.walk(%r):\n  for f in fs: os.stat(os.path.join(d,f))\n" % str(HOME))))
    return pids, [HOME]
def s_co1():
    stage = ROOT / "staging"; stage.mkdir(exist_ok=True)
    files = [".ssh/id_ed25519", ".aws/credentials", ".kube/config", "proj/.env"]
    return [run_child(["tar", "-czf", str(stage / "bundle.tgz"), "-C", str(HOME)] + files)], [HOME / f for f in files]
def s_co2():
    stage = ROOT / "staging/copy"; stage.mkdir(parents=True, exist_ok=True)
    files = [HOME / ".npmrc", HOME / ".git-credentials", HOME / ".docker/config.json"]
    for f in files: shutil.copy(f, stage / f.name)
    return [AGENT_PID], files
def s_ex1():
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    def acc():
        try: c, _ = srv.accept(); c.recv(1 << 20); c.close()
        except Exception: pass
    t = threading.Thread(target=acc, daemon=True); t.start()
    b = ROOT / "staging/bundle.tgz"
    pid = run_child(pyc("import socket;s=socket.create_connection(('127.0.0.1',%d));s.sendall(open(%r,'rb').read());s.close()" % (port, str(b))))
    t.join(2); srv.close(); return [pid], [b]
def s_im1():
    docs = sorted((HOME / "Documents").glob("doc_*.txt"))
    return [run_child(pyc("for p in %r:\n  b=open(p,'rb').read()\n  open(p,'wb').write(b'ENC-'+b[::-1])\n" % [str(d) for d in docs]))], docs
def s_im2():
    docs = sorted((HOME / "Documents").glob("doc_*.txt"))
    for d in docs: d.rename(str(d) + ".locked")
    return [AGENT_PID], docs
def s_im3():
    locked = sorted((HOME / "Documents").glob("*.locked"))[:50]
    for d in locked: d.unlink()
    return [AGENT_PID], locked
def s_exe1():
    inner = "import os;print(os.getpid())"
    return [run_child(["cmd", "/c", PY, "-c", inner] if OS == "Windows" else ["sh", "-c", "%s -c '%s'" % (PY, inner)])], []

def b_sshkeygen():
    exe = shutil.which("ssh-keygen"); p = HOME / ".ssh/id_ed25519"
    return ([run_child([exe, "-y", "-f", str(p)])], [p]) if exe else ([], [])
def b_gitdiff(): return [run_child(["git", "-C", str(HOME / "proj"), "diff", "--stat"])], [HOME / "proj/.env"]
def b_npm():
    exe = shutil.which("npm"); p = HOME / ".npmrc"
    return ([run_child([exe, "config", "list", "--userconfig", str(p)])], [p]) if exe else ([], [])
def b_app(): return [run_child([PY, str(HOME / "proj/src/app.py")])], [HOME / "proj/.env"]
def b_humancat(): p = HOME / ".aws/credentials"; return [run_child(cat_argv(p))], [p]
def b_compute(): return [run_child(pyc("sum(range(2000000))"))], []

STEPS = [
 ("CA1", "Credential Access", "T1552.001", "in-process read of cloud credentials", s_ca1, "attack"),
 ("CA2", "Credential Access", "T1552.004", "child process reads a private key", s_ca2, "attack"),
 ("CA3", "Credential Access", "T1552.001", "child python reads a project .env", s_ca3, "attack"),
 ("CA4", "Credential Access", "T1555.003", "child reads browser credential stores", s_ca4, "attack"),
 ("CA5", "Credential Access", "T1552", "recursive sweep for credential-named files", s_ca5, "attack"),
 ("PE1", "Persistence", "T1546.004", "append to shell rc files", s_pe1, "attack"),
 ("PE2", "Persistence", "T1547/T1543", "drop files in autostart-style locations", s_pe2, "attack"),
 ("PE3", "Persistence", "T1098.004", "append to authorized_keys", s_pe3, "attack"),
 ("PE4", "Persistence", "agent control plane", "add hook, MCP server and rule to agent configs", s_pe4, "attack"),
 ("PE5", "Persistence", "agent control plane", "transient modify-and-restore of an agent config (50 ms)", s_pe5, "attack"),
 ("DE1", "Defense Evasion", "T1070.003", "delete shell history", s_de1, "attack"),
 ("DE2", "Defense Evasion", "T1070.002", "truncate a security log", s_de2, "attack"),
 ("DI1", "Discovery", "T1083", "recursive listing and stat of every file (metadata only)", s_di1, "attack"),
 ("CO1", "Collection", "T1560.001", "archive credential files into a staging bundle", s_co1, "attack"),
 ("CO2", "Collection", "T1074.001", "copy credential files to a staging directory", s_co2, "attack"),
 ("EX1", "Exfiltration", "T1041", "send the bundle to a loopback listener", s_ex1, "attack"),
 ("IM1", "Impact", "T1486 (emulated)", "rewrite 200 documents", s_im1, "attack"),
 ("IM2", "Impact", "T1486 (emulated)", "rename 200 documents to .locked", s_im2, "attack"),
 ("IM3", "Impact", "T1485", "delete 50 documents", s_im3, "attack"),
 ("EXE1", "Execution", "T1059", "three-level process chain", s_exe1, "attack"),
 ("BN1", "benign", "-", "ssh-keygen derives a public key (legitimate accessor)", b_sshkeygen, "benign_legit"),
 ("BN2", "benign", "-", "git diff reads a tracked .env (legitimate accessor)", b_gitdiff, "benign_legit"),
 ("BN3", "benign", "-", "npm reads its own npmrc (legitimate accessor)", b_npm, "benign_legit"),
 ("BN4", "benign", "-", "the app itself loads its .env (legitimate)", b_app, "benign_legit"),
 ("BN5", "benign", "-", "a person debugging: cat of a credentials file (ambiguous)", b_humancat, "ambiguous"),
 ("BN6", "benign", "-", "pure compute, touches no catalogued object", b_compute, "benign_noise"),
]

HELPER = "import sys\nfor l in sys.stdin:\n    try: open(l.strip(), 'rb').read()\n    except Exception: pass\n    print('ok', flush=True)\n"

def spawn_helper(): return subprocess.Popen([PY, "-c", HELPER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def helper_read(h, p):
    h.stdin.write(str(p) + "\n"); h.stdin.flush(); h.stdout.readline(); return h.pid

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--sensors": return sensor_main(sys.argv[2:])
    if os.environ.get("LAB_ROLE") == "agent":                         # the emulated agent runs as a fresh process, started after the sensors
        for s in STEPS: step(*s)
        jdump(OUT / "steps.json", GT); return
    log("lab start os=%s phase=%s py=%s root=%s" % (OS, PHASE, sys.version.split()[0], ROOT))
    build_home(); jdump(OUT / "catalog.json", {"home": str(HOME), "classes": CATALOG})
    stop = ROOT / "STOP"; sproc = None; info = {}; pre = None
    if PHASE == "sensors":
        pre = spawn_helper()                                          # control: a reader that exists BEFORE any privileged sensor starts
        sproc = subprocess.Popen([PY, os.path.abspath(__file__), "--sensors", str(HOME), str(OUT), str(stop)])
        if not NO_PRIV: info = start_priv()
        time.sleep(3.0)
    t_start = time.time()
    ap = subprocess.Popen([PY, os.path.abspath(__file__)], env=dict(os.environ, LAB_ROLE="agent", LAB_ROOT=str(ROOT)))
    agent_pid = ap.pid; ap.wait()
    GT.extend(json.load(open(OUT / "steps.json")))
    if PHASE == "sensors":
        cred = HOME / ".aws/credentials"
        step("CTRL1", "control", "-", "reader that already existed when the privileged sensors started", lambda: ([helper_read(pre, cred)], [cred]), "control")
        post = spawn_helper()
        step("CTRL2", "control", "-", "reader started after the privileged sensors", lambda: ([helper_read(post, cred)], [cred]), "control")
    time.sleep(3.0)
    if PHASE == "sensors":
        stop.write_text("stop"); time.sleep(1.5)
        if not NO_PRIV: stop_priv(info)
    jdump(OUT / "gt.json", {"os": OS, "phase": PHASE, "agent_pid": agent_pid, "sensor_pid": sproc.pid if sproc else None,
                            "t_start": t_start, "t_end": time.time(), "home": str(HOME), "root": str(ROOT), "py": PY, "steps": GT})
    log("lab done: %d steps, outputs in %s" % (len(GT), OUT))

if __name__ == "__main__": main()
