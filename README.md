# Agent evidence conformance matrix

One table of which agent-evidence projects can be read by shared open verifiers and conformance corpora, with a verdict and a replay command for every cell.

For people who maintain a project that records what an AI agent did and want to see how its records and canonicalization compare with the others.

Install the reader as a pinned dependency:

```
pip install agent-evidence-vectors==0.36.3 agent-evidence-verify==0.5.1
```

Rebuild the table and its coverage count:

```
python build_matrix.py
```

It prints `N of 23: 19; no record read yet: 4 of 23` today and rewrites `MATRIX.md` and `badges/`; `python build_matrix.py --check` refuses a stale table. `MATRIX.md` ends with the replay command and upstream pin for each project. Each cell is marked "their records" (the project's own record bytes were read) or "our adapter" (code in `adapters/` carried their record to our reader, or their code to our corpus), and carries one of five verdicts: agrees, contradicted, cannot-tell, unsupported, not run. A contradicted cell names its basis, where the divergence sits and the revision it was judged against; a refusal inside a profile the project declares is unsupported, with the profile named. The builder refuses a cell that breaks these rules and any evidence path that does not resolve in this repository.

Status: first run from the IETF 127 Hackathon, 10 November 2026. Propose a project by opening an issue or a pull request with a `matrix.json` entry, the adapter and its run output; its row lands after a maintainer records the review in `reviews.json`. CI rebuilds the table daily and replays the RFC 8785 corpus through `adapters/rfc8785_cli.py`.

| Page | What it holds |
|---|---|
| [MATRIX.md](MATRIX.md) | the table |
| [matrix.json](matrix.json) | the cells, source of the table |
| [adapters/](adapters) | the adapters and their recorded runs |
| [libraries/RESULTS.md](libraries/RESULTS.md) | RFC 8785 and DSSE cross-library run at current releases: 20,121 of 20,140 JCS cases agree byte for byte, DSSE PAE agrees 400 of 400 |
