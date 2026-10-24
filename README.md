# Windows primitive probe — real-hardware measurement

Grades the Windows endpoint primitives from `CROSS_PLATFORM_DETECTION_v0.1.md` §4
from **[U] unverified** to **[M] measured**, by running documented Win32 APIs on a
real `windows-latest` GitHub Actions runner — in both the runner's own context and
a freshly-created **standard (non-admin) user**.

## What it measures
- **f1** — `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)`: per-connection owning PID, unprivileged?
- **f2/f5** — `Win32_Process` ancestry (ParentProcessId) + start time (CreationDate), and how much a standard user can see of other users' processes
- **U3** — Job object + `JobObjectBasicProcessIdList`: does an unprivileged launcher enumerate the full process subtree it started?
- **ETW** — can a standard user start a kernel-process trace session, or is it the documented admin/Performance-Log-Users gate?

## Run it (needs `gh` with `repo`+`workflow` scopes — you have both)
```
cd research/windows
git init -q && git add -A && git commit -qm "winprobe"
gh repo create ameen-winprobe --private --source=. --push
gh workflow run probe.yml -R <you>/ameen-winprobe
# wait ~2 min, then:
gh run watch -R <you>/ameen-winprobe
gh run view -R <you>/ameen-winprobe --log | grep MEASURED
```

## Honesty caveat
A CI runner is a Windows **Server** VM and runs elevated by default — which is exactly
why the probe also drops to a standard user via a `/RL LIMITED` scheduled task. Even so,
it is not a locked-down corporate laptop. It proves the **APIs and kernel behaviour** on
real Windows; it does not prove a hardened-desktop privilege posture. That distinction is
carried back into the matrix as [M-server] vs still-[U] for hardened desktops.

## Cleanup
```
gh repo delete <you>/ameen-winprobe --yes
```
