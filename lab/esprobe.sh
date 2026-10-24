#!/bin/bash
# Diagnostic: does Endpoint Security (via eslogger) deliver file events for user-session processes on a macOS runner? Benign: touches only files it creates.
set -u
W="${RUNNER_TEMP:-/tmp}/esp_out"; rm -rf "$W"; mkdir -p "$W"; cd "$W"
OUTD="$GITHUB_WORKSPACE/es_diag"; mkdir -p "$OUTD"
T="$(mktemp -d)"; echo "mktemp dir: $T"; sw_vers | tr '\n' ' '; echo; echo "SIP: $(csrutil status 2>&1)"; id -u
echo secret > "$T/ameenlab_target.txt"; mkdir -p /tmp/ameenlab_tmp; echo x > /tmp/ameenlab_tmp/f.txt
sudo -n /usr/bin/eslogger open create write unlink rename stat readdir exec fork exit close lookup getattrlist > es_all.jsonl 2> es_all.err &
sleep 8
echo "--- generating events (marker: ameenlab_)"
cat "$T/ameenlab_target.txt" > /dev/null                                   # user, platform binary
python3 -c "open('$T/ameenlab_target.txt').read()"                        # user, non-platform
/usr/bin/python3 -c "open('$T/ameenlab_target.txt').read()"               # user, platform python
sudo -n cat "$T/ameenlab_target.txt" > /dev/null                           # root, platform binary
sudo -n python3 -c "open('$T/ameenlab_target.txt').read()"                 # root, non-platform
touch "$T/ameenlab_new.txt"; mv "$T/ameenlab_new.txt" "$T/ameenlab_new2.txt"; rm "$T/ameenlab_new2.txt"
ls -la "$T" > /dev/null; stat "$T/ameenlab_target.txt" > /dev/null
sleep 6
sudo -n pkill -INT eslogger; sleep 3; sudo -n pkill eslogger 2>/dev/null; sleep 1
python3 - <<'PY' | tee "$OUTD/summary.txt"
import json, collections, os
rows = 0; bytype = collections.Counter(); byuid = collections.Counter(); lab = []; u501 = []; exes_by_uid = collections.defaultdict(collections.Counter)
for l in open("es_all.jsonl", errors="replace"):
    try: d = json.loads(l)
    except Exception: continue
    rows += 1; ev = next(iter(d["event"])); at = d["process"]["audit_token"]
    bytype[ev] += 1; byuid[(at["ruid"], at["euid"])] += 1
    exes_by_uid[at["ruid"]][(ev, d["process"]["executable"]["path"].split("/")[-1])] += 1
    if "ameenlab_" in l: lab.append(d)
    if at["ruid"] == 501 and len(u501) < 40: u501.append(d)
print("total events:", rows); print("by type:", dict(bytype)); print("by (ruid,euid):", dict(byuid))
print("events mentioning ameenlab_:", len(lab))
for d in lab[:20]:
    ev = next(iter(d["event"])); print("   LAB", ev, d["process"]["executable"]["path"], d["process"]["audit_token"]["ruid"])
print("ruid=501 (event, exe) top:", exes_by_uid[501].most_common(25))
print("ruid=0 (event, exe) top:", exes_by_uid[0].most_common(12))
json.dump(u501, open(os.environ["GITHUB_WORKSPACE"] + "/es_diag/uid501_sample.json", "w"))
PY
cp -f es_all.err "$OUTD/" 2>/dev/null
echo done
