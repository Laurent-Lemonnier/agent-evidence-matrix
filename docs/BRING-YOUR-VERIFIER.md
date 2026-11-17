# Bring your verifier

How a project puts its own verifier or canonicalizer on the matrix, what we run for a project that emits no records, and how a row lands. Every row ends as cells in `matrix.json` with a run file in `adapters/` that anyone can replay.

## The three routes

| Route | When | What runs | Source of the cell |
|---|---|---|---|
| Their records, our reader | the project publishes record bytes | the pinned reader (`agent-evidence-verify`, `agent-evidence-vectors`) on those bytes | "their records" |
| Their verifier, our corpus | the project ships a verifier or a canonicalizer | their code behind one of the contracts below, on our corpus | "our adapter" |
| Producer mode | the project emits no records of its own, but its code can produce them | their own producer, run here; the records it writes are then read as in the first route | "their records", with the producer run committed |

A cell whose evidence is `no records emitted` must name its producer route: `"producer": "cell N"` (the cell of the same project that reads records its own code produced) or `"producer": "none: <reason>"` when no producer exists (a requirements draft with no code, a format nobody implements yet). `build_matrix.py` refuses the cell otherwise, so "nothing to read" is never the end of a row while running their code would give us something.

## The verifier contracts

A canonicalizer (RFC 8785 or a project's own scheme) takes the a2a-jcs-v01 contract from agent-evidence-vectors (`docs/reference/corpus-readers.md`):

```
<verifier> rfc8785 <input.json>   exit 0 and {"canonical_utf8_hex": ...} on stdout
                                  exit 1 when the input has no canonical form
                                  exit 2 for anything else (an error is never a refusal)
```

and runs as `A2A_JCS_TARGET=rfc8785 agent-evidence-vectors --corpus vectors-a2a-jcs-v01 --verifier "<your command>"`. `adapters/rfc8785_cli.py` is the reference shape.

A canonicalization function with no command line of its own is scored in place by `adapters/jcs_function_score.mjs` (JavaScript or TypeScript, the source read from your commit, nothing rewritten) or `adapters/py_jcs_score.py` (the matrix's own Python reader). Both score the rfc8785 cases and then probe four inputs that have no canonical form at the parse or decode layer: two duplicate members, a surrogate written as UTF-8 bytes and a raw 0xFF byte. A function that takes a parsed value cannot see a duplicate member, because the parse already kept one of the two values, so each project's `canonicalizer` field records the function, its kind, what it takes, and in `parse_layer` whether all four inputs were refused, any one accepted, "parsed before it" (a function that takes a parsed value never sees them) or not probed; the Canonicalizers table of `MATRIX.md` shows it. A parsed-value function is given the value each case denotes, including the three non-JSON rejects (a bare NaN, Infinity or -Infinity) as the numbers they name, so a refusal is always the function's own and never the harness parse. `tests/test_canonicalizers.py` holds every recorded field to all four probe lines and the input line of the run it cites, and holds the matrix's own reader to refusing all four on the received bytes, before canonicalization.

A record verifier for another format follows the reader adapters in `adapters/` (for example `adapters/reader_cells.py`): one line per case with the verdict, a summary line, exit 0 when the run completed. Every adapter refuses to score an input it could not read or parse as a refusal: a missing reader or an unread file is a setup error.

## What a pull request carries

1. The adapter in `adapters/`, reading your code or records from a checkout named on the command line (never vendored here unless the source expires; then under `records/` with its digest).
2. The run output in `adapters/<name>-run.txt`, and a second run, byte-identical, or the reason it cannot be.
3. One tamper or mutation that must change the verdict, with its run: a check that cannot fail is not a check.
4. The `matrix.json` entry: cells (verdict, source, detail, evidence), `upstream` (one repository URL and its 40-hex commit; further inputs in `upstream.also`), the `replay` command, `independence` (author, same-owner, co-author or non-author) and, where the row canonicalizes, its `canonicalizer` record.
5. `python build_matrix.py` run once, so `MATRIX.md`, `badges/` and the README counts match.

A contradicted cell names its basis (defect, adapter, upstream-moved, revision-skew), where the divergence sits and the revision it was judged against. A refusal inside a profile the project declares is unsupported with the profile named, never contradicted.

## The review gate

The `intake` check refuses a pull request from someone who is not a maintainer when it adds or changes a row. That is by design: a row lands only after a maintainer replays it and records the review in `reviews.json`. An author-run row says so in `independence`. A project far below the size line the matrix cites at is not named; its cells keep their verdict and failure class under `withheld` (the reason and the SHA-256 of each input), with no upstream URL.
