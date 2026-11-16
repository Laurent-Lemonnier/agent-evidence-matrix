#!/bin/sh
# usage: dnsaid_sig_run.sh <python with dns-aid-core installed> <dns-aid-core checkout> <outdir>
# Writes fresh cases (signed by their code), runs our independent reader and the model of their live
# discoverer over them, and prints one line per case with both verdicts against the expected one.
PY=$1; CO=$2; OUT=$3; H=$(cd "$(dirname "$0")" && pwd)
rm -rf "$OUT"; mkdir -p "$OUT"
"$PY" -I "$H/dnsaid_sig_cases.py" "$CO" "$OUT/cases" > "$OUT/gen.txt" 2>&1 || { echo "setup: case generation failed"; cat "$OUT/gen.txt"; exit 2; }
for set in pinned new; do
  "$PY" -I "$H/dnsaid_sig_reader.py" "$OUT/cases/$set"/*.json > "$OUT/ours-$set.tsv" || { echo "setup: our reader exited $?"; exit 2; }
  "$PY" -I "$H/dnsaid_sig_theirs.py" "$CO" "$OUT/cases/$set"/*.json 2>/dev/null | grep -v '^20[0-9][0-9]-' > "$OUT/theirs-$set.tsv"
done
"$PY" -I - "$OUT" <<'PYEOF'
import json, os, sys
out = sys.argv[1]
def rd(p):
    return {f[0]: f[1] for f in (l.rstrip("\n").split("\t") for l in open(p)) if len(f) >= 2}
# Their verifier's result on these cases goes to its maintainers before it is published here.
HELD = {"ce2-crit-unknown-extension", "ce6-empty-realm-injected"}
tot = {}
for s in ("pinned", "new"):
    ours, theirs = rd(f"{out}/ours-{s}.tsv"), rd(f"{out}/theirs-{s}.tsv")
    for fn in sorted(os.listdir(f"{out}/cases/{s}")):
        c = json.load(open(f"{out}/cases/{s}/{fn}"))
        k, e = c["case"], c["expected"]
        o, t = ours.get(k, "MISSING"), theirs.get(k, "MISSING")
        if k in HELD:
            t = "not-published"
        for n, v in (("ours", o), ("their_live", t)):
            if v == "not-published":
                continue
            a = tot.setdefault((s, n), [0, 0]); a[1] += 1; a[0] += v == e
        print(f"{s}\t{k}\texpected={e}\tours={o}\ttheir_live={t}")
for (s, n), (a, b) in sorted(tot.items()):
    print(f"SUMMARY {s} {n} {a}/{b}")
PYEOF
