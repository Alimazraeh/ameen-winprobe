#!/bin/bash
# Diagnostic: does Endpoint Security (via eslogger) deliver file events for processes started by this job? Benign: touches only files it creates.
set -u
W="${RUNNER_TEMP:-/tmp}/esp_out"; rm -rf "$W"; mkdir -p "$W"; cd "$W"
T="$(mktemp -d)"; echo "mktemp dir: $T"; sw_vers; uname -a; id; echo "SIP: $(csrutil status 2>&1)"
echo secret > "$T/ameenlab_target.txt"; mkdir -p /tmp/ameenlab_tmp; echo x > /tmp/ameenlab_tmp/f.txt; echo y > "$HOME/ameenlab_home.txt"
run_variant() {  # $1=name, rest = eslogger events
  name="$1"; shift
  sudo -n /usr/bin/eslogger "$@" > "es_$name.jsonl" 2> "es_$name.err" &
  sleep 8
  cat "$T/ameenlab_target.txt" > /dev/null; cat /tmp/ameenlab_tmp/f.txt > /dev/null; cat "$HOME/ameenlab_home.txt" > /dev/null
  python3 -c "open('$T/ameenlab_target.txt').read()"
  /usr/bin/python3 -c "open('$T/ameenlab_target.txt').read()"
  touch "$T/ameenlab_new.txt"; mv "$T/ameenlab_new.txt" "$T/ameenlab_new2.txt"; echo z >> "$T/ameenlab_new2.txt"; rm "$T/ameenlab_new2.txt"
  ls -la "$T" > /dev/null; stat "$T/ameenlab_target.txt" > /dev/null
  sleep 6
  sudo -n pkill -INT eslogger; sleep 3; sudo -n pkill eslogger 2>/dev/null; sleep 1
  echo "== variant $name: lines=$(wc -l < es_$name.jsonl) bytes=$(wc -c < es_$name.jsonl) lab-lines=$(grep -c ameenlab_ es_$name.jsonl) err=$(head -c 200 es_$name.err | tr '\n' ' ')"
  grep ameenlab_ "es_$name.jsonl" | python3 -c "
import sys, json, collections
c = collections.Counter()
for l in sys.stdin:
    try: d = json.loads(l)
    except Exception: continue
    ev = next(iter(d['event'])); p = d['process']['executable']['path'].split('/')[-1]
    c[(ev, p)] += 1
for k, v in sorted(c.items(), key=lambda x: -x[1])[:25]: print('   ', v, k)
"
}
run_variant open_only open
run_variant many open create write unlink rename stat readdir exec fork exit
echo "== all events seen per type in the many-variant (any path):"
python3 - <<'PY'
import json, collections
c = collections.Counter(); procs = collections.Counter()
for l in open("es_many.jsonl", errors="replace"):
    try: d = json.loads(l)
    except Exception: continue
    ev = next(iter(d["event"])); c[ev] += 1
    procs[(ev, d["process"]["executable"]["path"].split("/")[-1])] += 1
print(dict(c))
for k in [k for k in procs if k[0] in ("open",)][:0]: pass
print("top open processes:", [(k[1], v) for k, v in procs.most_common(60) if k[0] == "open"][:15])
PY
mkdir -p "$GITHUB_WORKSPACE/es_diag" 2>/dev/null; cp -f es_*.err "$GITHUB_WORKSPACE/es_diag/" 2>/dev/null
grep ameenlab_ es_open_only.jsonl | head -50 > "$GITHUB_WORKSPACE/es_diag/open_lab_lines.jsonl" 2>/dev/null
grep ameenlab_ es_many.jsonl | head -200 > "$GITHUB_WORKSPACE/es_diag/many_lab_lines.jsonl" 2>/dev/null
echo done
