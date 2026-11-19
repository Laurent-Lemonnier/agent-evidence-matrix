# Results

Two verifiers by b7n0de, run without network against two corpora of probityai/agent-evidence-vectors at commit
`250de75575a945d00211415d7af41894d15427fa`. Per-member data, including the SHA-256 of every member file, is in `results.json`.
How to check these numbers, and how to recompute them with the source code in `b7n0de-verifier-source-20261115.tar.gz`
(SHA-256 `a81ab5af84a8da9cce6f64b65a911a83cc3a09973bb34bfce08da79f65cbd8fa`), is in `README.md`.

## Agent audit record

| Field | Value |
|---|---|
| Corpus | `corpora/vectors-agent-audit-record` |
| Package and version | agent-evidence-vectors, git `v0.36.3-201-g250de755`; MANIFEST.json differs from the one in agent-evidence-vectors 0.36.3 on PyPI |
| Corpus commit | `250de75575a945d00211415d7af41894d15427fa` |
| SHA-256 of MANIFEST.json | `362175b54c95ae06181dfa953cca23003c7bd4ce699a73effb9fe6884e37c828` |
| Members | 225 |
| Verdict equal to MANIFEST.json | 187 |
| Verdict different | 38 |
| Verifier | b7n0de audit-record verifier, `audit-record/agent_evidence_01/tools/aar_verifier.py` in `b7n0de-verifier-source-20261115.tar.gz`; it follows revision 03 of the draft |

Members whose verdict differs, with the revision their `draftRevision` names.

| draftId | Revision | Expected | Ours | Our first code |
|---|---|---|---|---|
| CS18 | 01 | valid | malformed | consumption-malformed |
| CS19 | 01 | valid | malformed | consumption-malformed |
| CS20 | 01 | valid | malformed | consumption-malformed |
| CS21 | 01 | valid | malformed | consumption-malformed |
| CS22 | 01 | valid | malformed | consumption-malformed |
| CS26 | 01 | valid | malformed | consumption-malformed |
| CS27 | 01 | valid | malformed | consumption-malformed |
| CS28 | 01 | valid | malformed | consumption-malformed |
| CS29 | 01 | valid | malformed | consumption-malformed |
| CS30 | 01 | valid | malformed | consumption-malformed |
| CS31 | 01 | valid | malformed | consumption-malformed |
| CS34 | 01 | valid | malformed | member-missing |
| CS38 | 01 | valid | malformed | member-missing |
| CS39 | 01 | valid | malformed | member-missing |
| CS40 | 01 | valid | malformed | member-missing |
| CS41 | 04 | valid | malformed | member-missing |
| CS43 | 04 | valid | malformed | member-missing |
| CS48 | 04 | valid | malformed | member-missing |
| CS49 | 04 | valid | malformed | member-missing |
| CS50 | 04 | valid | malformed | member-missing |
| CS53 | 04 | valid | malformed | member-missing |
| CS54 | 04 | valid | malformed | member-missing |
| PR4 | 04 | malformed | valid | none |
| PR5 | 04 | malformed | valid | none |
| PR6 | 04 | malformed | valid | none |
| PR7 | 04 | malformed | valid | none |
| PR8 | 04 | malformed | valid | none |
| PR9 | 04 | malformed | valid | none |
| PR10 | 04 | malformed | valid | none |
| PR11 | 04 | malformed | valid | none |
| DS4 | 04 | malformed | valid | none |
| DS5 | 04 | malformed | valid | none |
| DS6 | 04 | malformed | valid | none |
| DS7 | 04 | malformed | valid | none |
| DS8 | 04 | malformed | valid | none |
| DS9 | 04 | malformed | valid | none |
| DS10 | 04 | malformed | valid | none |
| X6 | none | malformed | valid | none |

## Restoration evidence

| Field | Value |
|---|---|
| Corpus | `corpora/vectors-restart-records` |
| Package and version | agent-evidence-vectors, git `v0.36.3-201-g250de755`; MANIFEST.json byte-equal to agent-evidence-vectors 0.36.3 on PyPI and to vectors-restart-records/ at tag v0.31.2 |
| Corpus commit | `250de75575a945d00211415d7af41894d15427fa` |
| SHA-256 of MANIFEST.json | `7a3cd31da92c7349f508b8225f032dd43d16cb983ea647ac0027586bed31a6d0` |
| Members | 57 |
| Verdict equal to MANIFEST.json | 57 |
| Verdict different | 0 |
| Reason equal to MANIFEST.json | 57 |
| Verifier | b7n0de restoration-evidence verifier, `audit-record/agent_evidence_01/tools/rer_verifier.py` in `b7n0de-verifier-source-20261115.tar.gz`; it follows revision 00 of the draft |

No member differs.

## Agent audit record through the external-verifier contract

The same verifier, through a thin adapter, run by `packaging/run_vectors.py` at the head of pull request 575
(`34704695b763814f2f56d7926939131553465208`), contract `https://probityai.github.io/agent-evidence-vectors/contract/agent-audit-record/v1`. The corpus member files there are byte-equal to the commit above.
The runner's report is `contract/report.json`.

| Runner total | Value |
|---|---|
| vectors | 225 |
| conform | 180 |
| fail | 45 |
| reasonParityMismatch | 32 |
| suiteRefusals | 0 |

The 45 failing members fall into three classes.

| Class | Members | Meaning |
|---|---|---|
| verdict differs | 38 (CS18, CS19, CS20, CS21, CS22, CS26, CS27, CS28, CS29, CS30, CS31, CS34, CS38, CS39, CS40, CS41, CS43, CS48, CS49, CS50, CS53, CS54, PR4, PR5, PR6, PR7, PR8, PR9, PR10, PR11, DS4, DS5, DS6, DS7, DS8, DS9, DS10, X6) | the verdict differs, the same members as in the table above |
| secondary result differs | 1 (CS32) | the verdict is equal, a declared secondary result (set verdict) differs |
| field not provided (set codes) | 6 (CS7, CS8, CS17, SQ5, X17, X18) | our verifier names no set codes in the corpus vocabulary; the adapter passes its own check names, so the comparison cannot pass |
