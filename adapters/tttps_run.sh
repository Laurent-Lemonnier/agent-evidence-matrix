#!/bin/sh
# usage: run.sh <recheck-dir> <venv-python> <draft13.txt> <outdir>
# Replays: extract Appendix B, run THEIR pot_record_v2 at each pinned module, read the bytes with our adapter.
set -u
R=$1; PY=$2; D13=$3; OUT=$4
mkdir -p "$OUT"
cd / || exit 1
"$PY" -I "$R/adapter/tttps_pot_adapter.py" extract "$D13" "$OUT/d13-vectors.json" || exit 1
V=$(cat "$OUT/d13-vectors.json")
for t in e60bae0:"$R/_raw/mcp-e60bae0/pot_record_v2.ts" e123ba9:"$R/_raw/mcp-e123ba9/pot_record_v2.ts" npm0.4.7:"$R/_raw/npm/x/package/dist/pot_record_v2.js"; do
  label=${t%%:*}; mod=${t#*:}
  D13_VECTORS="$V" node "$R/adapter/tttps_emit.mjs" "$mod" "$label" > "$OUT/emit-$label.json" 2> "$OUT/emit-$label.err" || echo "emit $label failed rc=$?"
done
"$PY" -I "$R/adapter/tttps_pot_adapter.py" check "$D13" "$OUT"
