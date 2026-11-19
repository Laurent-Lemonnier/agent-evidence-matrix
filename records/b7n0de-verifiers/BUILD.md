<!-- Copyright 2026 Konrad Gruszka -->
<!-- Licensed under the Apache License, Version 2.0; see LICENSE. -->
# Build and run

Nothing is compiled. The verifiers need Python 3.11 or later, git, and one package, `cryptography`, for Ed25519.
The checks under `tests/` need `pytest` as well. All commands below run from the root of this archive, and each
names the exit code it gives when the archive and the corpus are as pinned.

## Environment

```sh
python3 -m venv venv
venv/bin/pip install cryptography==50.0.2 pytest==9.2.0
```

Exit 0. These are the versions the results were written with.

## Corpus

```sh
git clone --bare https://github.com/probityai/agent-evidence-vectors aev.git
```

Exit 0. The runner reads only the commit pinned in `audit-record/agent_evidence_01/pins.json`,
`250de75575a945d00211415d7af41894d15427fa`, by its hash, so a clone made later works as long as it holds that commit.

## Verifiers and planted faults

```sh
venv/bin/python -I audit-record/agent_evidence_01/tools/run_all.py --work ../agent-evidence-run --repository aev.git
```

Exit 0: every pin holds and the 286 fresh result files are byte-equal to `audit-record/agent_evidence_01/results/`.
With `--repository aev.git` the runner reads the local clone and needs no network. Without `--repository` it clones
`https://github.com/probityai/agent-evidence-vectors` itself, which needs network access to GitHub, and also exits 0.
The working directory must lie outside this archive. Exit 1 means a result file differs, 2 that a pin does not
hold or a path is refused, 3 an unexpected error; `audit-record/agent_evidence_01/README.md` gives the details.

## Checks

```sh
venv/bin/python -m pytest -q audit-record/agent_evidence_01/tests
```

Exit 0, 1032 passed. They need no network.

## External-verifier contract

The contract runner `packaging/run_vectors.py` belongs to the vector repository and is used as it is, at the head of
its pull request 575.

```sh
git -C aev.git fetch origin 34704695b763814f2f56d7926939131553465208
git -C aev.git worktree add ../../pr575 34704695b763814f2f56d7926939131553465208
venv/bin/python ../pr575/packaging/run_vectors.py --vectors ../pr575/corpora/vectors-agent-audit-record \
  --verifier "venv/bin/python -I contract-adapter/contract_adapter.py audit-record/agent_evidence_01/tools" \
  --report ../contract-report.json
```

Exit 1, because 45 of the 225 members do not conform. The totals are vectors 225, conform 180, fail 45,
reasonParityMismatch 32 and suiteRefusals 0, as in `contract/report.json` of the results package. The `fetch`
needs network access and can be left out when the clone already holds that commit.
