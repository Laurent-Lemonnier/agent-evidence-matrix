<!-- Copyright 2026 Konrad Gruszka -->
<!-- Licensed under the Apache License, Version 2.0; see LICENSE. -->
# Notice on material from agent-evidence-vectors

Some files in this directory carry values taken from the manifests of the test vector repository
https://github.com/probityai/agent-evidence-vectors at commit 250de75575a945d00211415d7af41894d15427fa,
from `corpora/vectors-agent-audit-record/MANIFEST.json` and `corpora/vectors-restart-records/MANIFEST.json`.
That repository is distributed under the Apache License, Version 2.0. Its LICENSE file at that commit is
included here unchanged as `LICENSE.agent-evidence-vectors` (SHA-256
8b506a9d145be0a6fbef3f0519996faf84c770f8ab8d32d120c8682f2ad6181f, also pinned in `pins.json`). At that
commit the repository root holds no NOTICE file, and the two corpora hold no LICENSE or NOTICE file of
their own.

Files that carry values from those manifests:

- `results/agent_audit_record/*.json` other than `_summary.json`: the vector identifier, file path, kind,
  draft revision and section, the whole `expected` object (verdicts and codes), and for vectors of kind
  indeterminate the verdict of each listed reading. The rationale texts of the readings are not copied.
- `results/agent_audit_record/_by_revision.json`: vector identifiers, draft revisions, sections and
  expected verdicts.
- `results/restoration_evidence/*.json` other than `_summary.json`: the vector identifier, shape, kind,
  rule and the whole `expected` object (verdict and reason).
- `README.md` and `READINGS.md`: vector identifiers and expected verdicts or codes where a difference is
  discussed.
- `pins.json`: the file paths of the corpora at that commit.

The vector files themselves are not copied into this directory. `tools/run_all.py` fetches them at the
pinned commit and checks each against its SHA-256 in `pins.json`. Everything else here, including the
verifiers under `tools/` and the verdicts they produce, is the work of b7n0de and under the Apache License,
Version 2.0, as `LICENSE` in the root of this archive states.

`leap-seconds.list` is the IERS leap second file as published at
https://data.iana.org/time-zones/data/leap-seconds.list, unchanged (SHA-256
db5a895f16853b03bfc865e8d68f9fc8710ef1740e3400c701cd46a5bbbc3433). It states that it is in the public
domain.
