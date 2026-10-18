# Work-acceptance record (draft profile 1.3, schema 1.2)

A work-acceptance record is a checking party's signed findings about a delivered file, against criteria that were fixed before the check.
It is distinct from a counterparty's acceptance decision (accepted / rejected / disputed). A counterparty acceptance can reference a
work-acceptance record by digest, so "the checker found X" and "the counterparty accepted it" remain two signatures from two parties.

## Properties
1. **Bound to the exact file**: SHA-256 of the delivered file (and of the original, when there is one).
2. **Criteria committed first**: the criteria document has its own SHA-256 and an RFC 3161 timestamp (or a binding to terms the counterparty signed). A verifier
   reports whether the commitment predates the check. The token over `criteria.sha256` is authoritative for when; `criteria.committed_at` is the checker's own claim.
3. **Checker independence is checkable**: `parties.checker` and `parties.producer` are named separately. The checker key must not equal the producer key; a self-check is
   labelled `independence: "self-checked"` and verifiers warn on it.
4. **Verdict vocabulary**: each criterion result is `pass | fail | not-evaluated | error`. The overall verdict is `pass` only if every required criterion is `pass`.
   Any required `fail` makes it `fail`, and `fail` takes precedence over `incomplete`; otherwise any required `not-evaluated` or `error` makes it `incomplete`, never `pass`.
   Verifiers recompute the verdict from the results; a stated verdict that differs is `VERDICT_MISMATCH`.
5. **Verifiable from bytes**: canonical form JCS (RFC 8785). Ed25519 signature over the canonical `receipt` object. An RFC 3161 token over the SHA-256 of the canonical
   receipt. Suites are declared in the record (`canonicalization`, `suite`). No hosted service or account is needed.

## Verification procedure (summary)
1. Parse; refuse an unknown schema, canonicalization or suite.
2. JCS-canonicalize `receipt`; verify the Ed25519 signature with the key named by the signed `receipt.key_id`. The envelope's `signature.key_id` must equal it, else `SIGNATURE_INVALID` (the envelope is unsigned, so it cannot choose the key); whether that key is `parties.checker.key_id` is a separate check (`CHECKER_NOT_SIGNER`). **Key rule:** the public key must be a canonical encoding (y < p) of a point of prime order; any other key (neutral point, small or mixed order, non-canonical) is `KEY_REJECTED` and no signature check is run. That is a finding about the key list, not evidence of tampering. The rule applies to the key named by the signed `receipt.key_id` only; other entries in the key file do not change the outcome fields, and a verifier may report them separately (vector 28). On a signature failure report `SIGNATURE_INVALID`; the remaining checks may still be reported as diagnostics, but the contents are not presented as results.
3. If the delivered file is supplied, compare its SHA-256 with `files.remediated.sha256`.
4. If the criteria document is supplied, compare its SHA-256 with `criteria.sha256` (`CRITERIA_HASH_MISMATCH`); when it matches, check the results correspond to the criteria (`CRITERIA_RESULTS_MISMATCH`).
5. Criteria commitment. If a timestamp token is supplied, its imprint must be SHA-256 (OID 2.16.840.1.101.3.4.2.1; a same-length imprint under another algorithm is not a match) and equal `criteria.sha256` (`CRITERIA_TIMESTAMP_MISMATCH` otherwise), and its `genTime` is authoritative; a `criteria.committed_at` that disagrees is `CRITERIA_TIME_MISMATCH`. Without a usable token (none, or one over other bytes), fall back to `committed_at` and warn `CRITERIA_COMMITMENT_UNVERIFIED`. The criteria were committed before the check iff the commitment time is strictly earlier than the reference time: the **earlier** of `issued_utc` and the genTime of the record's own token when a token covering the record is supplied, else `issued_utc` (a covering token bounds the check from above; it never moves the signed issue time later). A token's stated `accuracy` widens its time against "committed before"; a token stating none is taken at its genTime; `ordering` is ignored. If not, `criteria_committed_before_check` is `no` and `CRITERIA_COMMITTED_AFTER_CHECK` is raised. **That is a problem, not a warning.**
6. Check the record's timestamp token imprint (SHA-256, as in step 5) against SHA-256 of the canonical receipt; the unsigned `timestamp.digest_sha256` field is informative and never decides the outcome; report `receipt_timestamp` as `none` (no timestamp or no token supplied), `imprint_match` or `imprint_mismatch`. A mismatching token is never used as evidence of time.
7. Recompute the verdict from the per-criterion results (property 4) and compare it with the stated verdict (`VERDICT_MISMATCH`).
8. Emit problem codes (`SIGNATURE_INVALID`, `KEY_REJECTED`, `CHECKER_NOT_SIGNER`, `KEY_COLLISION`, `INDEPENDENCE_INCONSISTENT`, `RESULT_VOCABULARY`, `VERDICT_MISMATCH`, `CRITERIA_HASH_MISMATCH`, `CRITERIA_RESULTS_MISMATCH`, `CRITERIA_TIMESTAMP_MISMATCH`, `CRITERIA_TIME_MISMATCH`, `CRITERIA_COMMITTED_AFTER_CHECK`) and warning codes (`SELF_CHECKED`, `PRODUCER_UNDECLARED`, `CRITERIA_COMMITMENT_UNVERIFIED`). The record is accepted as stated when the signature is valid and there are no problem codes. Code lists are sets: compare without regard to order. `PRODUCER_UNDECLARED` follows the parties block (no producer named), whatever the record states; a stated `independence` that differs from the derived one is also `INDEPENDENCE_INCONSISTENT`. A record refused at step 1 has the outcome `{"refused": true, "reason": "unknown schema, canonicalization or suite"}`.
9. Time-stamp authority. The outcome fields cover imprint and time only. A verifier that presents a time as evidence to a third party should also validate the token's CMS signature and certificate chain against authorities the relying party trusts, and report that separately.

## Vectors (`vectors/`, CC0)
| file | case |
|---|---|
| 01-valid.json | valid, independent, criteria committed first |
| 02-criteria-committed-after-issue.json | criteria commitment later than the check |
| 03-self-checked.json | checker == producer organisation |
| 04-required-not-evaluated.json | a required criterion `not-evaluated` → `incomplete` |
| 05-checker-key-equals-producer-key.json | key collision |
| 06-receipt-edited-after-signing.json | a finding edited after signing (contributed by babyblueviper1, CC0) |
| 07-criteria-file-swapped.json | another criteria document supplied (contributed by babyblueviper1, CC0) |
| 08-receipt-token-over-another-receipt.json | the record's token covers another record (contributed by babyblueviper1, CC0) |
| 09-stated-pass-recomputes-incomplete.json | signed `pass` with a required criterion `not-evaluated` (contributed by babyblueviper1, CC0) |
| 10-committed-at-contradicts-token.json | `committed_at` before the check, token genTime after it (contributed by babyblueviper1, CC0) |
| 11-required-criterion-fails.json | a required `fail` (contributed by babyblueviper1, CC0) |
| 12-signer-is-not-the-checker.json | signed `receipt.key_id` and envelope name test-2, `parties.checker.key_id` names test-1 (rebuilt 12b; contributed by Tetsurohhori, CC0) |
| 13-independent-but-same-party.json | stated independent, same party (contributed by Tetsurohhori, CC0) |
| 14-results-not-in-criteria.json | results do not correspond to the criteria (contributed by Tetsurohhori, CC0) |
| 15-criteria-token-over-other-bytes.json | criteria token over other bytes; fallback with warning (contributed by Tetsurohhori, CC0) |
| 16-no-criteria-token.json | no criteria token (contributed by Tetsurohhori, CC0) |
| 17-committed-at-equals-reference.json | commitment time equals reference time: strictly earlier required (contributed by Tetsurohhori, CC0) |
| 18-mismatching-record-token-later-time.json | record token over other bytes, later time: not used (contributed by Tetsurohhori, CC0) |
| 19-result-outside-vocabulary.json | result `passed` (contributed by Tetsurohhori, CC0) |
| 20-producer-undeclared.json | no producer, stated independent (contributed by Tetsurohhori, CC0; expectation amended, the contributor's is stated in the file) |
| 21-unknown-schema.json | unknown schema: refused (contributed by Tetsurohhori, CC0) |
| 22-matching-record-token-later-than-issued.json | covering record token later than `issued_utc`: reference is the earlier (contributed by babyblueviper1, CC0) |
| 23-criteria-token-imprint-oid-sha384.json | criteria token imprint algorithm SHA-384, same bytes (contributed by babyblueviper1, CC0) |
| 24-criteria-token-imprint-oid-sha3-256.json | as 23 with SHA3-256 (case from robertolocatelli81-dev) |
| 25-criteria-token-imprint-oid-sha512-256.json | as 23 with SHA-512/256 (case from robertolocatelli81-dev) |
| 26-key-small-order.json | neutral-point key; R = neutral, S = 0 verifies for any message under the bare equation: `KEY_REJECTED` |
| 27-key-non-canonical-encoding.json | non-canonical key encoding (y = p + 1): `KEY_REJECTED` |
| 28-key-file-with-unrelated-bad-entry.json | an unrelated small-order entry listed before the valid signing key: same outcome as 01 (case from robertolocatelli81-dev) |

Each file contains its inputs and an `expected` object with the outcome an independent verifier should reproduce. The keys in the vectors are test keys:
never trust them. The timestamp tokens in the vectors are imprint-and-time fixtures, not valid RFC 3161 tokens: their SignedData has no SignerInfo, so OpenSSL and other CMS parsers that require a signer refuse them. They test imprint and time handling only.

## Changelog
**Profile 1.3 (2026-10-18; schema identifier unchanged).** Resolves the questions from clean-room verifiers by Tetsurohhori and robertolocatelli81-dev and a second run by babyblueviper1 (x402-foundation/tsc#4): step 2 names the signed `receipt.key_id` and adds the canonical, prime-order key rule (`KEY_REJECTED`); step 5's reference time is the earlier of `issued_utc` and a covering token's genTime; imprints must be SHA-256 by OID; `accuracy` widens comparisons, `ordering` ignored; a token over other bytes falls back with `CRITERIA_COMMITMENT_UNVERIFIED`; `PRODUCER_UNDECLARED` follows the parties block; step 1 refusal shape; authority signature reported separately; vectors 12-27 added (12b replaces 12; Tetsurohhori's SHA-1 vector superseded by 23). Clarified 2026-10-18: the key rule applies to the named signing key only; vector 28 added; outcomes for 01-27 unchanged.
**Profile 1.2.1 (2026-10-17; schema identifier unchanged).** Resolves ambiguities found by an independent clean-room review (babyblueviper1): `CRITERIA_COMMITTED_AFTER_CHECK` is a problem; the token over `criteria.sha256` is authoritative for commitment time (`CRITERIA_TIME_MISMATCH`, fallback with `CRITERIA_COMMITMENT_UNVERIFIED`); verdict rule completed (required `fail` wins, `VERDICT_MISMATCH`); reference time uses the record's token only when it covers the record; vectors 06-11 added.
**Profile 1.2.** First draft, vectors 01-05.

## Status
Draft, offered for the evidence-record discussion in x402-foundation/tsc#4 and referenced by ACP SEP #303 (Section 7.4a). Independent clean-room
implementations are welcome; please report any disagreement with a vector's `expected` outcome as an issue.

Licence: text CC BY 4.0; vectors CC0 1.0.
