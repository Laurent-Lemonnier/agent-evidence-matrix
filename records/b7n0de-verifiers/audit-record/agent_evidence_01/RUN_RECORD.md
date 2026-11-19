<!-- Copyright 2026 Konrad Gruszka -->
<!-- Licensed under the Apache License, Version 2.0; see LICENSE. -->
# Run record

This is the run that wrote `results/`, with every command, its exit code and the environment it ran in. Times are read from the clock of the machine the run used, in UTC.

## Environment

| Item | Value |
|---|---|
| tree | this archive, as it is shipped |
| interpreter | Python 3.11.18 (CPython), Linux x86_64 with glibc 2.39 |
| packages | cryptography 50.0.2 for the runner, pytest 9.2.0 for the checks, in a fresh virtual environment; the runner imports only cryptography |
| git | 2.43.0 |
| network | none; every run below ran in its own network namespace without an interface to the outside (`unshare -n`) |
| time of the run that wrote `results/` | 2026-11-15T20:39:13Z |

## Inputs and when they were fetched

| Input | Pinned as | Fetched |
|---|---|---|
| revision 03 of the agent audit record draft, txt, 3976 lines | SHA-256 `c5d0b74686b62b5d1fd954b2dae0cf02b402c87a06efa6fc82abf8fa847ed786`, address in `pins.json` | 2026-11-07T21:57:23Z, HTTP 200, datatracker time of the revision 2026-10-29T22:20:04Z; not fetched again for this run |
| revision 00 of the restoration evidence draft, txt, 1344 lines | SHA-256 `0ae1b94c226cf85b006dfb34abf2180e9dcbda34ad30b9933067df37eafec745`, address in `pins.json` | 2026-11-07T21:57:23Z, HTTP 200, datatracker time of the revision 2026-11-02T07:15:01Z; not fetched again for this run |
| probityai/agent-evidence-vectors | commit `250de75575a945d00211415d7af41894d15427fa`, 304 file digests and the SHA-256 of LICENSE | cloned from GitHub on 2026-11-15 before the run, HEAD of that clone `60ad7564ab8775c9ac0636484e7938f3bbd69d4a`; the runner then cloned this local copy bare and read the pinned commit by its hash |
| leap-seconds.list of the IERS, as published by IANA | SHA-256 `db5a895f16853b03bfc865e8d68f9fc8710ef1740e3400c701cd46a5bbbc3433`, own hash line `a9bad145 84c31c70 758402aa b37bfd54 5923836a`, expires 28 June 2027 | 2026-11-08T03:33:17Z, from https://data.iana.org/time-zones/data/leap-seconds.list; not fetched again for this run |

The drafts and the leap-second list are checked against their pins as described in `README.md`: the runner checks the list itself, the drafts are compared by hand.

## Commands

From the root of this archive, with `<work>` a directory outside it and `aev.git` a local clone of the vector repository:

```
python3 -m venv venv && venv/bin/pip install cryptography==50.0.2 pytest==9.2.0
git clone --bare https://github.com/probityai/agent-evidence-vectors aev.git
unshare -n venv/bin/python -I audit-record/agent_evidence_01/tools/run_all.py --work <work> --repository aev.git --update
unshare -n venv/bin/python -I audit-record/agent_evidence_01/tools/run_all.py --work <work2> --repository aev.git
unshare -n venv/bin/python -m pytest -q -p no:cacheprovider audit-record/agent_evidence_01/tests
```

| Command | Exit | Output |
|---|---|---|
| `run_all.py --update` | 0 | leap-seconds.list equal to both pins and its hash line; 304 pinned files, 304 digests equal, LICENSE equal to its pin and to `LICENSE.agent-evidence-vectors`; agent-audit-record 187 of 225 equal; restoration evidence 57 of 57 equal, reason 57 of 57; planted cases 5620, as expected 5620; 286 result files written |
| `run_all.py` | 0 | the same counts, 286 result files byte-equal to `results/`, none different, none missing, none new |
| `pytest` of `tests/` | 0 | 1032 passed, 0 failed, 0 skipped |

Each run generates its own throwaway test key, so the planted-fault cases are signed with a different key every time, and only their verdicts are compared.

## Output of the runs

agent-audit-record, 225 vectors, verdict equal 187, not equal 38. The 38 are CS18, CS19, CS20, CS21, CS22, CS26, CS27, CS28, CS29, CS30, CS31, CS34, CS38, CS39, CS40, CS41, CS43, CS48, CS49, CS50, CS53, CS54, PR4, PR5, PR6, PR7, PR8, PR9, PR10, PR11, DS4, DS5, DS6, DS7, DS8, DS9, DS10 and X6. CS32 agrees in its verdict and differs in its set verdict.

| Secondary result | Equal | Not equal |
|---|---|---|
| derivedTier | 76 | 0 |
| withinLimit | 7 | 0 |
| dating.entry | 22 | 0 |
| dating.datedAt | 22 | 0 |
| dating.delegationRoot | 22 | 0 |
| dating.receipt | 3 | 0 |
| set.missing | 1 | 0 |
| set.verdict | 17 | 11 |

restoration evidence, 57 vectors, verdict equal 57, verdict and reason equal 57, file digests as stated in its MANIFEST.json 57 of 57.

Planted faults, 5620 cases, 5620 as expected, 0 deviating.

| Data type | signature-byte | field | key | required | reference | control | profile | time | jcs | retained |
|---|---|---|---|---|---|---|---|---|---|---|
| aar | 76 | 228 | 228 | 1976 | 457 | 152 | 760 | 1064 | 152 | 3 |
| rer | 15 | 15 | 15 | 178 | 9 | 15 | 130 | 117 | 30 | 0 |

Against `results/` of the earlier pinned commit `b2e412c4bc8e0f80443ceaac52ff8f5d836293c8`, which this run replaced, 280 of the 286 files are byte-equal. Three changed, `agent_audit_record/_summary.json`, `agent_audit_record/_by_revision.json` and `planted_faults_summary.json`, and three are new, the files of PS3, PS4 and PS5, the three vectors the corpus gained between the two commits. No verdict and no reason at any other vector changed.

## Digests

| File | SHA-256 |
|---|---|
| `pins.json` | `4aa5aff78f5b105d0dda85601123d700d6b6ead84b58563739ef5bb36b0904e7` |
| `leap-seconds.list` | `db5a895f16853b03bfc865e8d68f9fc8710ef1740e3400c701cd46a5bbbc3433` |
| `LICENSE.agent-evidence-vectors` | `8b506a9d145be0a6fbef3f0519996faf84c770f8ab8d32d120c8682f2ad6181f` |
| `tools/aar_verifier.py` | `1482b4d4bf2c8aab9fc16156ff74d0bf78840fbf6b088c66e6fe7f230773fe12` |
| `tools/rer_verifier.py` | `831ced476b8862eb2a5b4740b1554adefab01f3f45c85c5276fc06eab85d3c91` |
| `tools/leap_seconds.py` | `6114f06761e5407c3d90d06e77468b9f1dfce2b342cbbe1f9cd4aab631d08f80` |
| `tools/run_aar.py` | `c9a8d4fa4aab259cc08968e2e96a75573367245aff1aa9e902eb24cc71b5a032` |
| `tools/run_rer.py` | `670e8de7dd1a5298d7370abc4529e70334e2673202daf2bc1708172af359dd31` |
| `tools/run_faults.py` | `a2633b76af30892ee91e6e1e342f7bbd6ac182264e572391e871ea9edb4d66ea` |
| `tools/run_all.py` | `60a6709dcab662433cd9f0066f030238b1ef41d2b509f579af118b88c36df2cc` |
| `tests/check_runner_exit_codes_and_paths.py` | `fee253cec7634796acc84ee4f2ac547638cc3d1970db9be04e7ebb09bb41a84a` |
| `tests/check_json_profile_and_times.py` | `ff9cd1723c2ee7c60368cd0e8bca08a2cd19060b13f2416eec87691a11c546d5` |
| `results/planted_faults_summary.json` | `fdb2cb3bbb9fdb9c22ffa2b7292971b73b43613ba528503969b8d2b3e3697cef` |
| the 286 files under `results/`, as `sha256sum` lines sorted by path, hashed again | `39e0fff2095a3296ab0947c431d9bfd78b97e469079187dbca27bb9b4537dd54` |

The last value is reproduced from this directory with `find results -type f | LC_ALL=C sort | xargs sha256sum | sha256sum`.
