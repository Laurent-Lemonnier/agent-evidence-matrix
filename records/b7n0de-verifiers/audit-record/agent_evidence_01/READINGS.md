<!-- Copyright 2026 Konrad Gruszka -->
<!-- Licensed under the Apache License, Version 2.0; see LICENSE. -->
# Readings

Where the text of a draft allows more than one reading, the reading implemented is listed here. The column "decided" says whether a vector of the corpus fixes the choice. "No" means the vectors do not test the point, or test it only in a way that gives the same verdict under either reading. Where a code comment or failure text in `tools/` names a reading, it uses these identifiers.

## agent-audit-record, revision 03 of the agent audit record draft

| Id | Reading implemented | Section | Decided |
|---|---|---|---|
| L-TOP | A further predicate member at the top level is not refused | 4 | Vectors that name -04 require refusal, -03 does not carry it |
| L-HELD | Entries of held may carry further members | 5.9 | X6 requires refusal, -03 does not carry it |
| L-UNIT | unit is required, asset is unknown | 5.9 | CS34 and others require asset |
| L-SCOPE | Set checks run only under one limitDigest | 5.9 | CS32 requires a check across two limitDigest values |
| L-STALE | The stale-revision check has no settlement condition | 5.9 | Yes, CS7 and CS17 |
| L-EMPTY | empty-tree means beforeRoot equals e3b0c442…b855, the hash of the empty byte string | 5.3 | No, see the note below |
| L-SIG | The envelope counts only under the pinned observer key, and one valid signature is enough | 4.4, 4.6 | No |
| L-CSIG | priorCommitment.sig is not checked, because -03 names no preimage | 5.7 | No |
| L-STYPE | _type must be https://in-toto.io/Statement/v1 | 4, IN-TOTO | Yes, X4 |
| L-DEPTH | Depth counts from 1 for the outermost object, and more than 128 is refused | 4.1.2 | In part, T4 |
| L-IJSON | The statement must be I-JSON as a whole, because RFC 8785 Section 3.1 requires its input to be adapted for I-JSON and Section 5 has the verifier check that it adheres to I-JSON before the signature. Surrogate code points and noncharacters in names and string values (RFC 7493 Section 2.1), non-finite numbers and non-zero numbers that underflow to zero (RFC 8785 Section 3.1) are refused with not-i-json | 4.1.1 | In part, X1 |
| L-SAFEINT | Integral floating-point values from 2^53 upwards are not allowed either. An integer literal is held to the bound at any length: one of more than 16 digits is refused as unsafe by its length, before any conversion, so it never counts as unparseable and never meets the limit Python sets on `int()`, which is at least 640 digits. This is the bound of 4.1.1 and not one of the verifier's own | 4.1.1 | No |
| L-HEX | Named digests are 64 characters of lowercase hex | 3, 5.1 | No |
| L-IV | interval is optional, with the if-and-only-if rule for the second subject, and writes without an interval are malformed | 4.2, 5.3 | In part, I1r and S1 |
| L-UNDER | Under a member of pathScope means equal to it, or a prefix of it up to a slash | 5.3, 5.7 | In part, V3, V4, V5 |
| L-GLOB | The glob characters are * ? [ ] { } | 5.3 | In part, V2 |
| L-TB | timeBasis is closed to beacon-anchored and asserted | 5.6 | No |
| L-REM | remediation requires cause, enforcement, signalReceivedAt and enforcedAt | 5.6 | No |
| L-F2 | Only subjectKind none beside a named subject is malformed, not the reverse | 5.2 | No |
| L-NOV | An unknown hashAlgorithm gives no verdict | 5.1 | No, no vector |
| L-SET | A set with an unreadable or malformed record is malformed as a set | 5.9, 5.10 | Yes, X17 and X18 |
| L-DATE | Anchors are checked over the recomputed envelopeDigest, and dating is reported even for a malformed entry | 4.7, 4.7.1 | Yes, R4, R9, X12, X13 |
| L-LEAF | The leaf of the test log is SHA-256 over 0x00 followed by the 32 raw bytes of envelopeDigest | 4.7.2, manifest | Yes, every R vector with a log anchor |
| L-EARLY | Two OTS times are compared by block height, other times by time | 4.7.2 | Yes, R10 and R12 |
| L-ENTRY | The retention entry carries no further members | 4.7 | No |
| L-ROOTMAT | The delegation-root element is a key set of media type application/jwk-set+json, from which the verifier derives the algorithm. The draft gives the material no profile of its own. It is read with the reader of the Statement, under the profile of 4.1 that governs the entry carrying it: UTF-8, no repeated member name, no surrogate or noncharacter, no nesting past 128 levels, every number an IEEE 754 double and every integer below 2^53. It must be an object whose member keys is a non-empty array of objects, each with a string kty, and an OKP or EC key carries a string crv; the algorithm is read off the first key. Material outside these rules is unreadable and the root not established, which 4.6 never reports as a pass. The same reader reads every JSON file the runner hands to the verifier, also the retained file that holds the entry | 4.6, 4.7 | No, R13 to R15 give the same result under either reading |
| L-LEAP | A second 60 is accepted only where the pinned leap-seconds.list records a leap second, at 23:59:60 UTC or the same instant under an offset, and not after the expiry of the list. Times are compared and subtracted as exact elapsed seconds that count the leap seconds of the list, a rational number with the decimal fraction of the time and never a binary float. A second 60 lies after 23:59:59 with any fraction and before the midnight, so 2016-12-31T23:59:59.999999999Z is earlier than 2016-12-31T23:59:60Z and 2016-12-31T23:59:60.999999999Z earlier than 2017-01-01T00:00:00Z. Every spelling of one instant that RFC 3339 allows (any offset, "Z" or "z", "t" or "T", trailing zeros of the fraction) gives the same value. Section 5.6 bounds no digits of the fraction. They are converted in parts of at most 500 digits, below 640, the smallest limit Python allows on `int()`, so a fraction of any length keeps its exact value under every limit, which the verifier leaves as it is; the verifier sets no bound of its own. After a subtracted leap second 23:59:59 would not exist; the list holds none | 4.3, RFC 3339 5.6, 5.7 | No |

### Note on L-EMPTY

Section 5.3 of -03 names the constant e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. MANIFEST.json gives 6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321 in the field emptyTree.sha256, which is a different value. In the corpus only E3 uses empty-tree, with the sha1 constant, and it is refused under either value. The vectors therefore do not decide the question.

### Note on L-CSIG

To place this reading, A1 was checked once by hand for whether priorCommitment.sig verifies under the observer key over the ASCII hex characters of commitmentDigest. It does, and over the 32 raw bytes it does not. This observation is not part of the verifier, because -03 does not fix the preimage.

### How the readings came about

Three points were adjusted after the first run, when differences led back to the draft text. L-STALE follows the sentence of Section 5.9 "puts no condition on when the held permit was issued". L-DATE and L-SET are points that -03 leaves open, and there the corpus influenced the choice. A rule of the verifier's own that -03 does not carry was removed (openedAt not after sealedAt). The verdict count stayed the same, 184 of the 222 vectors the corpus then held; only secondary results changed.

## restoration evidence, revision 00 of the restoration evidence draft

| Id | Reading implemented | Section | Decided |
|---|---|---|---|
| L-R23 | Rule 3 applies to registry values, and values the draft lists itself are checked by rule 2 | 4.3, 4.4, 10 | Yes, reasons 57 of 57 |
| L-PH | The draft names no pause_hold values, so the value is not checked | 5.1 | No |
| L-REG | registryDigest must be hex, and need not equal 1c5ff8…7fdc | 4.2, 4.3 | No |
| L-SUBJ | The subject count belongs to rule 1, one for R2, R4 and RB | 4.1, 5 | In part |
| L-SORT | Sorted means ascending by code point, and duplicates are refused only in population | 5 | No |
| L-IA | issuedAfter only with issued_after_only, otherwise rule 2 | 5.2 | No |
| L-PRED | The predecessor digest is taken over the file bytes as carried | 4.2, 7.7 | Yes, the bundle cases |
| L-B5 | Same incident means the sets from incident and related intersect with those of the R3 | 6 | In part |
| L-B7 | A credential counts as swept when it appears in population.credentials of an R2 | 6 | Yes, one case |
| L-ONE | A bundle holds exactly one R3 | 3, 6 | No |
| L-ORD | B1 reports the first failure in file-name order | 6 | No |
| L-SIGC | The code for a signature failure is signature-invalid, as the draft names none | 4.1 | No |
| L-RJSON | I-JSON is applied as a whole, including the noncharacter rule of RFC 7493 Section 2.1 (as in L-IJSON), and "canonicalized as in Section 4.1 of [AUDIT-RECORD]" brings in its safe-integer bound and the nesting bound of its Section 4.1.2; a failure is statement-malformed | 4.1 | No |
| L-RLEAP | A second 60 is accepted only where the pinned leap-seconds.list records a leap second and not after its expiry, as in L-LEAP. A UTC time to whole seconds ends in "Z", "z" or "+00:00", which RFC 3339 Section 2 and Section 4.3 both give as UTC, or in "-00:00" (L-RUTC). Another offset and any fraction, ".0" included, are refused, since Section 4.1 asks for UTC times to whole seconds. Times are "compared as instants" as exact elapsed seconds, as in L-LEAP, so every accepted spelling of one instant compares equal and 23:59:60 lies between 23:59:59 and the midnight | 4.1, RFC 3339 2, 4.3, 5.6, 5.7 | No |
| L-RUTC | "-00:00" is accepted as a UTC time. RFC 3339 Section 4.3 uses it when "the time in UTC is known, but the offset to local time is unknown", and says it "differs semantically" from "Z" and "+00:00", "which imply that UTC is the preferred reference point". The difference concerns the local offset, not the instant: the time written is the time in UTC. Section 4.1 of the draft asks for UTC times and compares them as instants, so "-00:00" names the same instant as "Z" and is treated alike | 4.1, RFC 3339 4.3 | No |
