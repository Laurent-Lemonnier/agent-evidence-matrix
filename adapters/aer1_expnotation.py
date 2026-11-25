"""Run both reference runners of the AER-1 kit on x-entry-count-float with
entry_count spelled several ways, and print what each runner answers.

    python -I adapters/aer1_expnotation.py <kit checkout>

The kit's `base/` directory is copied to a scratch directory and only the one
token of the `x-entry-count-float` vector is rewritten in the raw JSON text. The
vector expects invalid, so a runner that rejects the spelling prints PASS and one
that accepts it prints FAIL.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SPELLINGS = ["5.0", "5", "5e0", "5E+0", "50e-1", "5.00"]
ORIGINAL = '"entry_count": 5.0,'


def run(cmd: list[str], cwd: Path) -> str:
    done = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    for line in done.stdout.splitlines():
        if "x-entry-count-float" in line:
            return f"{line.strip()} (exit {done.returncode})"
    return f"no x-entry-count-float line (exit {done.returncode})"


def main(kit: Path) -> int:
    base = kit / "base"
    text = (base / "commitment-vectors.json").read_text(encoding="utf-8")
    if text.count(ORIGINAL) != 1:
        print(f"expected exactly one {ORIGINAL!r} in commitment-vectors.json", file=sys.stderr)
        return 2
    for spelling in SPELLINGS:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "base"
            shutil.copytree(base, work)
            (work / "commitment-vectors.json").write_text(
                text.replace(ORIGINAL, f'"entry_count": {spelling},'), encoding="utf-8"
            )
            print(f"entry_count {spelling}")
            print("  python:", run([sys.executable, "conformance.py"], work))
            print("  node:  ", run(["node", "conformance.cjs"], work))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
