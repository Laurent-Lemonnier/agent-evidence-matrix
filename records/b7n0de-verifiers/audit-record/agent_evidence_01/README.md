<!-- Copyright 2026 Konrad Gruszka -->
<!-- Licensed under the Apache License, Version 2.0; see LICENSE. -->
# Clean-room run of the agent-evidence-vectors corpora

This directory holds two verifiers written from the text of two Internet-Drafts alone, the run of both against the published test vectors for those drafts, and the planted faults used to see that each verifier refuses what it should refuse. It is an interoperability exercise and defines no format of its own.

## What was checked

| Data type | Draft | Corpus at the pinned commit | Verdict equal |
|---|---|---|---|
| agent-audit-record | revision 03 of the agent audit record draft | corpora/vectors-agent-audit-record, 225 vectors | 187 of 225 |
| restoration evidence | revision 00 of the restoration evidence draft | corpora/vectors-restart-records, 57 vectors | 57 of 57 |

The vectors are those of https://github.com/probityai/agent-evidence-vectors at commit `250de75575a945d00211415d7af41894d15427fa` (`git describe --tags` gives `v0.36.3-201-g250de755`). The drafts are the plain-text renderings of revision -03 and revision -00 from the IETF archive. `pins.json` names both drafts with their IETF archive addresses and SHA-256, and the vector commit with the SHA-256 of each of the 304 `.json` files under the two corpora.

Neither the drafts nor the vectors are stored here. The runner clones the vector repository bare, without a working tree, reads only the pinned files as blobs of the pinned commit and refuses any file whose bytes differ from its pin. The results carry values from the manifests of the vectors, such as the expected verdicts and codes. `NOTICE.md` names those files and where the values come from, and `LICENSE.agent-evidence-vectors` is the LICENSE of the vector repository at the pinned commit, unchanged.

## Result

- agent-audit-record after -03. The verdict equals the manifest verdict for 187 of 225 vectors and differs for 38. Where the manifest states them and the verdict is valid, the secondary results agree as well. derivedTier 76 of 76, withinLimit 7 of 7, and for the 22 retained records the entry state, datedAt and the delegation root 22 of 22 each, the receipt statement 3 of 3. The set verdict agrees for 17 of 28 sets. Of the 11 others, ten belong to the groups below; CS32 is discussed separately. All rows of Appendix B of -03 that are present in the corpus agree.
- restoration evidence after -00. The verdict equals the manifest verdict for 57 of 57 vectors, and so does the first reason code. Of the 57, 49 are single records and 8 are bundles, 15 accept and 42 reject.
- Planted faults. 5620 cases at the 76 agent-audit-record vectors and the 15 restoration-evidence vectors that both the manifest and the verifier hold valid, and all 5620 came out as expected. The counts per fault kind are in `results/planted_faults_summary.json`.

The 38 differing agent-audit-record verdicts fall into five groups. Each row gives the sentence of -03 the verifier follows.

| Group | Vectors | Expected | This verifier | Sentence of -03 |
|---|---|---|---|---|
| `supersedes` in consumption | CS18 to CS22, CS26 to CS31 | valid | malformed | Section 5.9, "consumption MUST carry each of these members and no other (vector CS9)". The list there has no `supersedes`. |
| `asset` in place of `unit` | CS34, CS38 to CS41, CS43, CS48 to CS50, CS53, CS54 | valid | malformed | Section 5.9, "unit, the unit amounts are counted in; for money, an ISO 4217 alphabetic code", in the same MUST list. These vectors carry `asset` and no `unit`. |
| predicate member `principal` | PR4 to PR11 | malformed | valid | Section 4, "Seventeen required predicate members and two optional members are defined in Section 5." No sentence of -03 refuses a further top-level predicate member. |
| predicate member `dataSubject` | DS4 to DS10 | malformed | valid | The same sentence of Section 4. |
| a fourth member in a `held` entry | X6 | malformed | valid | Section 5.9, "held, an array with one entry for each unsettled earlier permit, each carrying that permit's operationKey, requestDigest and amount". Unlike consumption itself, this sentence has no "and no other". |

The vectors of the first group name draftRevision -01, four of the second group name -01 and seven name -04, and all vectors of the third and fourth group name -04. X6 names Section 5.9 and no revision. PR1 to PR3 and DS1 to DS3 are valid on both sides. Each vector's file in `results/agent_audit_record/` holds the expected result, the verifier's result, its first failure code with the section, and the comparison. For the two vectors of kind indeterminate, N2 and PS1b, it holds the verdict of each reading the manifest lists and whether the verifier's verdict is among them, not the rationale text of the readings.

One set verdict differs while the record verdicts agree. CS32 expects the set to be malformed, a retry as a new operation under another limitDigest. Section 5.9 says "The key is scoped by limitDigest." and "a retaining party that holds the records under one limitDigest runs them". The two records of CS32 carry different limitDigest values, so under -03 no set check runs between them.

## Which revision the vectors name

The manifest of the agent-audit-record corpus names revision 00 of the agent audit record draft as its base, and single vectors carry draftRevision. The verifier follows -03 throughout. `results/agent_audit_record/_by_revision.json` holds the assignment per vector.

| Revision the vector names | Vectors | Verdict equal | Different |
|---|---|---|---|
| -00 (no draftRevision) | 125 | 124 | 1 (X6) |
| -01 | 58 | 43 | 15 (supersedes 11, asset 4) |
| -03 | 4 | 4 | 0 |
| -04 | 38 | 16 | 22 (principal 8, dataSubject 7, asset 7) |

This run used revision -03. Revision -04 was not read. Four vectors cite sections that -03 does not have, X4 and X5 cite 4.8 and X17 and X18 cite 4.9, and all four agree because -03 carries the same behaviour in Sections 4 and 5.1. Section 10 of -03 describes release v0.28.0 with 141 vectors. The pinned commit carries 225. Vector R17 of Appendix B of -03 is not in the corpus.

For restoration evidence the vectors name no draft revision. The manifest names the profile restoration-evidence/v1, and the verifier follows -00. Its corpusDigest and registryDigest appear verbatim in -00 (Sections 10 and 4.3). Neither digest was recomputed in this run.

## Readings

Where the text of a draft allows more than one reading, the reading implemented is written down in `READINGS.md`, with the section and whether a vector decides it. It lists L-TOP to L-LEAP for agent-audit-record and L-R23 to L-RUTC for restoration evidence, and where a code comment or failure text in `tools/` names a reading, it uses these identifiers. Three readings were adjusted after a first run had led back to the draft text, and one rule that -03 does not carry was removed. `READINGS.md` names each of them.

## JSON, times and canonical numbers

Section 4.1 of restoration-evidence-00 says statements are I-JSON (RFC 7493), canonicalized as in Section 4.1 of agent-audit-record-03 using JCS (RFC 8785), and that times are RFC 3339 UTC times to whole seconds. Sections 4.1.1 and 4.1.2 of agent-audit-record-03 require RFC 8785, the I-JSON safe-integer bound, no duplicate member and no nesting past 128 levels. RFC 8785 brings in I-JSON as a whole: Section 3.1 says the data "MUST be adapted for I-JSON [RFC7493] formatting", and Section 5 has a verifier "Parse the JSON data and verify that it adheres to I-JSON" before it verifies the signature. Both verifiers therefore refuse what RFC 7493 Section 2.1 bars from names and string values, surrogate code points and noncharacters, and what RFC 8785 Section 3.1 bars from numbers, a value that is not an IEEE 754 double (overflow to infinity, a non-zero literal that underflows to zero). Both refuse an integer of magnitude 2^53 or more, a duplicate member and nesting past 128 levels. Section 4.3 of agent-audit-record-03 makes every time an RFC 3339 date-time, with any offset.

Both verifiers accept a time only if its calendar date and clock time exist, written in ASCII digits with nothing before or after, for any year from 0000 to 9999 as RFC 3339 Sections 1 and 5.6 allow, and with a "t" and "z" in lower case as well, which Section 5.6 also allows. Restoration evidence takes a UTC time to end in "Z", "z", "+00:00" or "-00:00": RFC 3339 Section 4.3 gives "Z" and "+00:00" as UTC, and "-00:00" as a time whose UTC value is known while its local offset is not (readings L-RLEAP and L-RUTC). Another offset and any fraction are refused there, because the draft asks for whole seconds in UTC. RFC 3339 Section 5.7 allows a second 60 only "at the end of months in which a leap second occurs", shifted by the zone offset, and points to a table of leap seconds. The verifiers take that table from `leap-seconds.list`, the IERS file as published by IANA, pinned with its SHA-256 and checked against its own hash line when it is loaded. A second 60 is accepted where the list records a leap second, and refused anywhere else, including at an instant after the expiry of the list (28 June 2027), which the list cannot confirm. A second 60 is its own instant after 23:59:59 and before the following midnight. Both verifiers compare and subtract times as exact elapsed seconds, a rational number built from the digits of the fraction and never a binary float, so every spelling of one instant that a verifier accepts gives one value and distinct instants keep their order at any precision. For agent-audit-record that is every RFC 3339 spelling, with any offset, case and number of fraction digits. For restoration evidence it is every accepted spelling, which its profile limits to the four UTC designators in whole seconds. RFC 3339 Section 5.6 puts no bound on the digits of a fraction. Python limits the digits `int()` converts from text, 4300 by default since 3.11, and allows any limit from 640 upwards or none. The verifiers convert a fraction in parts of at most 500 digits, below the smallest limit Python allows, and leave the limit as it is, so a fraction of any length names its instant under every limit: 2016-12-31T23:59:59.999999999Z is earlier than 2016-12-31T23:59:60Z, 2016-12-31T23:59:60.999999999Z is earlier than 2017-01-01T00:00:00Z, and two seconds pass from 23:59:59 to the midnight after a leap second. After the last entry of the list (1 January 2017) no further leap second is counted. The runner compares the dating time with the manifest as an instant as well. A property check takes a sample of equivalent spellings, not all of them. For 4000 random instants with fractions of up to nine digits and 200 with fractions of 4301 to 8602 digits, longer than `int()` converts by default, with second 60 at the dates of the list, it writes the four UTC spellings and six more drawn at random from offsets, letter case and trailing zeros, and checks that each verifier gives one value per instant for the spellings it accepts, that restoration evidence refuses the others, and that the order of distinct instants is kept for neighbours and for 4000 random pairs. The same holds for a JSON number: RFC 8259 bounds no digits, and an integer of more than 16 digits is refused as an unsafe integer, the rule of agent-audit-record Section 4.1.1, and not as text that does not parse. The delegation-root key set of a retained record and every JSON file the runner reads go through the same reader as the statement (reading L-ROOTMAT), so no number anywhere depends on the limit. `tests/check_json_profile_and_times.py` runs each of its cases under the limits 640, 4300 and none and expects the same result under each.

Both serialize numbers in the ECMAScript form RFC 8785 prescribes, and agree with every finite value of Table 1 in Appendix B of RFC 8785 and with its samples for sorting and for the UTF-8 bytes. `tests/check_json_profile_and_times.py` holds the focused checks with the cases taken from the RFCs, and the planted faults below include one fault kind per rule. No verdict and no reason at any vector changed through these checks.

## Planted faults

Each fault is applied to a vector that the manifest and the verifier both hold valid. For faults behind the signature, the runner re-signs the changed statement with a throwaway Ed25519 key that exists only in memory during the run, and pins only that key. One control re-signs the unchanged statement; another re-encodes the payload with other whitespace. Together they stayed valid in all 152 agent-audit-record cases. The signature covers the RFC 8785 bytes of the parsed statement (Section 4.6 of -03).

| Data type | Fault kind | Cases | As expected |
|---|---|---|---|
| agent-audit-record | signature byte flipped | 76 | 76 |
| agent-audit-record | signed field changed, signature kept | 228 | 228 |
| agent-audit-record | another pinned key (foreign, agent key, none) | 228 | 228 |
| agent-audit-record | required member removed, re-signed | 1976 | 1976 |
| agent-audit-record | reference broken, re-signed, plus envelope digest and anchor proof | 457 | 457 |
| agent-audit-record | controls (re-signed, payload reformatted) | 152 | 152 |
| agent-audit-record | not I-JSON, re-signed (number overflow and underflow, unsafe integer, unsafe integer of 4301 digits, lone surrogate in a value and in a name, noncharacter in a value and in a name, nesting past 128, duplicate member) | 760 | 760 |
| agent-audit-record | time not an RFC 3339 date-time (out of range, no such calendar day, trailing newline, second 60 not at 23:59 UTC, second 60 on a month end without a leap second, second 60 after the expiry of the leap-second list) | 456 | 456 |
| agent-audit-record | issuedAt half a second, one nanosecond or a fraction of 4301 nines before a sealedAt of 2016-12-31T23:59:60Z, or one nanosecond or a fraction of 4301 nines before a sealedAt of 2017-01-01T00:00:00Z | 380 | 380 |
| agent-audit-record | every "Z" time of the predicate written as "+00:00" or as "-00:00", re-signed, verdict unchanged | 152 | 152 |
| agent-audit-record | every "Z" time of the predicate with 4301 zeros added to its fraction, re-signed, verdict unchanged | 76 | 76 |
| agent-audit-record | number signed in its RFC 8785 form and in another form | 152 | 152 |
| agent-audit-record | delegation-root key set of the retained record R13 with an unused number of 4301 digits, with and without a sign, `rootDigest` and `envelopeDigest` recomputed and re-signed, the root not established; plus the unchanged key set re-signed, the root established | 3 | 3 |
| restoration evidence | signature byte flipped, on an envelope built by the runner | 15 | 15 |
| restoration evidence | signed field changed | 15 | 15 |
| restoration evidence | another pinned key | 15 | 15 |
| restoration evidence | required member removed | 178 | 178 |
| restoration evidence | reference broken (predecessor digest, predecessor content) | 9 | 9 |
| restoration evidence | control, DSSE envelope re-signed | 15 | 15 |
| restoration evidence | not I-JSON (the ten of agent-audit-record) | 130 | 130 |
| restoration evidence | time not an RFC 3339 UTC time to whole seconds (the six of agent-audit-record, and a fraction of 4301 digits) | 91 | 91 |
| restoration evidence | every "Z" time of the predicate written as "+00:00" or as "-00:00", verdict and reason unchanged | 26 | 26 |
| restoration evidence | number signed in its RFC 8785 form and in another form, on an envelope built by the runner | 30 | 30 |

The 22 consumption vectors that the verifier refuses under the readings above are left out. The corpus of restoration evidence carries bare in-toto statements without DSSE envelopes, so the signature path of that draft is exercised only on envelopes the runner builds. The flipped anchor proof is the last byte of the last anchor proof, and the expected effect is that the dating or the entry state changes. Vectors without a valid anchor (R8) are left out of that one fault kind. The 5620 single cases are written to the working directory of a run and are not stored here.

## Clean room

- The verifiers were written from the text of the two drafts alone. While they were written, no code by the author of the drafts or from probityai was opened, read or run. Later, for the contract run described in the results package, the contract runner `packaging/run_vectors.py` of the vector repository was run, not read. No file with a code extension, no Makefile, no notebook, nothing under `.githooks/` and no other repository of probityai.
- Searches in the vector repository went through `git ls-files`, filtered to exclude code files, and then through the filtered list only. File listings showed names of code files, never their content.
- From the vector repository only data was read. These were MANIFEST.json of both corpora (file lists, expected results, pinned keys, anchor trust), the vector files, the beginning of ID-MAP.json and REVISION-01-PIN.json, and LICENSE, which is included here unchanged. README.md and INDEX.md of the corpora were not read.
- The manifest describes in text fields the leaf of the test log and the format of the anchor trust. That was read as a description of pinned material and is stated as reading L-LEAF.
- The runner writes out only the pinned `.json` files of the two corpora as files. The rest of the repository stays in the object store of the bare clone and is never checked out.

## Running it

`BUILD.md` in the root of this archive gives every command with its expected exit code. In short, from the root:

```
python3 -m venv venv && venv/bin/pip install cryptography==50.0.2 pytest==9.2.0
git clone --bare https://github.com/probityai/agent-evidence-vectors aev.git
venv/bin/python -I audit-record/agent_evidence_01/tools/run_all.py --work ../agent-evidence-run --repository aev.git
venv/bin/python -m pytest -q audit-record/agent_evidence_01/tests
```

The runner needs git and the Python package `cryptography` for Ed25519, and network access only when `--repository` names a remote; with a local clone it runs without network. It first checks `leap-seconds.list` against its SHA-256 in `pins.json` and in `tools/leap_seconds.py` and against its own hash line, then clones the vector repository into the working directory, checks the 304 pins, runs both verifiers and the planted faults, and compares the fresh results with `results/` byte for byte. The working directory must lie outside the repository, which for this archive is the folder two levels above this one, the root of the archive. The runner resolves its own location before it derives this folder and the repository from it, so invoking it through `/proc/self/cwd`, a symbolic link or a relative path with `..` keeps the same boundary. The working directory is compared, like every place the runner writes to, after symbolic links are resolved, so an alias such as `/proc/self/cwd` or a link into the repository is refused, and so is a symbolic link below a place the runner writes to.

| Exit | Meaning |
|---|---|
| 0 | every pin the runner checks holds (the 304 vector files, LICENSE and `leap-seconds.list`; the drafts are checked by hand, see below) and every result file is byte-equal to `results/` |
| 1 | a result file differs, is missing, is new or cannot be read in `results/` |
| 2 | a pin does not hold (a vector file, the set of vector files, LICENSE against its pin or against `LICENSE.agent-evidence-vectors`, `leap-seconds.list` against its SHA-256 or its own hash line, `pins.json` itself), git fails, or an argument, the working directory or a place to write to is refused. `pins.json`, `leap-seconds.list` and `LICENSE.agent-evidence-vectors` fail their pin also when they are missing, cannot be read, are not a regular file or are a symbolic link, with a diagnostic that names the file |
| 3 | the run stopped on an unexpected error of its own, with the traceback printed |

`tests/check_runner_exit_codes_and_paths.py` plants each of these failures and runs the runner as a separate process, with a small vector repository built in a temporary directory and no network. To check the drafts, fetch the two URLs in `pins.json` and compare their SHA-256 with the pins.

## Files

- `tools/aar_verifier.py`, `tools/rer_verifier.py`, the two verifiers, Python standard library plus `cryptography`.
- `tools/run_aar.py`, `tools/run_rer.py`, `tools/run_faults.py`, the runners per corpus and for the planted faults. `tools/run_all.py` fetches, checks the pins and runs all three.
- `../../contract-adapter/contract_adapter.py`, the thin adapter that answers one member under the external-verifier contract of the vector repository with `tools/aar_verifier.py`.
- `results/agent_audit_record/`, one file per vector, `_summary.json` and `_by_revision.json`.
- `results/restoration_evidence/`, one file per vector and `_summary.json`.
- `results/planted_faults_summary.json`, the counts per data type and fault kind.
- `tools/leap_seconds.py` and `leap-seconds.list`, the pinned IERS leap-second list as published by IANA, and the module both verifiers read it with.
- `NOTICE.md` and `LICENSE.agent-evidence-vectors`, the origin of the values taken from the vector manifests and the license of the vector repository.
- `tests/check_json_profile_and_times.py`, focused checks of the JSON profile, the times and the canonical numbers of both verifiers, and `tests/check_runner_exit_codes_and_paths.py`, the exit codes and path checks of the runner, both collected only when the directory is named on the command line (`pytest.ini`).
- `READINGS.md`, the readings. `RUN_RECORD.md`, commands, exit codes, environment and fetch times.

## Not done

- Anchors of kind rfc3161 are not implemented, and no vector carries one. Transparency-log anchors are checked as a hash commitment against pinned tree heads, not as a signed token.
- validationData for the envelope is not compared with the pinned key. The verifier trusts the pinned key from the manifest only.
- The corpusDigest of both corpora and the registryDigest were not recomputed.
- Revision -04 of the agent-audit-record draft was not read.
- The verifiers that the vector repository ships were not read, and no output of theirs went into the results here.
- No statement about the correctness of the drafts, the vectors or any other implementation.

Assisted by little helpers.
