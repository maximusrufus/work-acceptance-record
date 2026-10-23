# Work-acceptance record (draft profile 1.4.1, schema 1.2)

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
5. Criteria commitment. If a timestamp token is supplied, the imprint of its signed TSTInfo (never other bytes of the response, such as `PKIStatusInfo.statusString`; genTime and accuracy come from the same TSTInfo) must be SHA-256 (OID 2.16.840.1.101.3.4.2.1; a same-length imprint under another algorithm is not a match) and equal `criteria.sha256` (`CRITERIA_TIMESTAMP_MISMATCH` otherwise), and its `genTime` is authoritative; a `criteria.committed_at` that disagrees is `CRITERIA_TIME_MISMATCH`. Without a usable token (none, or one over other bytes), fall back to `committed_at` and warn `CRITERIA_COMMITMENT_UNVERIFIED`. The criteria were committed before the check iff the commitment time is strictly earlier than the reference time: the **earlier** of `issued_utc` and the genTime of the record's own token when a token covering the record is supplied, else `issued_utc` (a covering token bounds the check from above; it never moves the signed issue time later). A token's stated `accuracy` widens its time against "committed before"; a token stating none is taken at its genTime; `ordering` is ignored. If not, `criteria_committed_before_check` is `no` and `CRITERIA_COMMITTED_AFTER_CHECK` is raised. **That is a problem, not a warning.**
6. Check the record's timestamp token imprint (SHA-256, as in step 5) against SHA-256 of the canonical receipt; the unsigned `timestamp.digest_sha256` field is informative and never decides the outcome; report `receipt_timestamp` as `none` (no timestamp or no token supplied), `imprint_match` or `imprint_mismatch`. A mismatching token is never used as evidence of time.
7. Recompute the verdict from the per-criterion results (property 4) and compare it with the stated verdict (`VERDICT_MISMATCH`).
8. Emit problem codes (`SIGNATURE_INVALID`, `KEY_REJECTED`, `CHECKER_NOT_SIGNER`, `KEY_COLLISION`, `INDEPENDENCE_INCONSISTENT`, `RESULT_VOCABULARY`, `VERDICT_MISMATCH`, `CRITERIA_HASH_MISMATCH`, `CRITERIA_RESULTS_MISMATCH`, `CRITERIA_TIMESTAMP_MISMATCH`, `CRITERIA_TIME_MISMATCH`, `CRITERIA_COMMITTED_AFTER_CHECK`) and warning codes (`SELF_CHECKED`, `PRODUCER_UNDECLARED`, `CRITERIA_COMMITMENT_UNVERIFIED`). The record is accepted as stated when the signature is valid and there are no problem codes. Code lists are sets: compare without regard to order. `PRODUCER_UNDECLARED` follows the parties block (no producer named), whatever the record states; a stated `independence` that differs from the derived one is also `INDEPENDENCE_INCONSISTENT`. A record refused at step 1 has the outcome `{"refused": true, "reason": "unknown schema, canonicalization or suite"}`.
9. Time-stamp authority. The outcome fields cover imprint and time only. A verifier that presents a time as evidence to a third party should also validate the token's CMS signature and certificate chain against authorities the relying party trusts, and report that separately. **Profile 1.4:** the outcome may carry `tsa_signature`, an object with keys `criteria` and/or `receipt` (one per token present). Without relying-party anchors (none supplied, or an empty list) it is `not_evaluated`, and an absent field reads the same. With anchors it is `verified` (CMS signature, the `contentType` signed attribute equal to an `eContentType` of `id-ct-TSTInfo` (RFC 5652 §5.3), ESS signing-certificate binding, `id-kp-timeStamping`, and a chain of CA issuers reaching a supplied anchor (matched by subject name and public key, RFC 5280 §6.1.1, not by certificate bytes; an anchor with the issuer's name but another key is not that issuer, so if only such anchors fail the value is `untrusted`), with the signer and every issuer other than the anchor valid at genTime; a root inside the token is not an anchor), `failed`, `untrusted`, `unsupported` (e.g. a curve other than P-256/P-384; RSA PKCS#1 v1.5 and ECDSA P-256/P-384 are required, RSASSA-PSS is optional) or `no_signer`. It never changes any other outcome member. When a token has more than one defect, the value is `failed` if any check that can run fails; otherwise `no_signer`, then `unsupported`, then `untrusted`. An issuer in the token that fails a check is `failed` whether or not the chain reaches a supplied anchor.

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
| 29-criteria-token-accuracy-flips-commitment.json | the criteria token is 30 s before the check but states an accuracy of 60 s: `CRITERIA_COMMITTED_AFTER_CHECK` (case from robertolocatelli81-dev) |
| 30-criteria-token-accuracy-millis-still-before.json | control for 29: the same times with an accuracy of 500 ms (the millis field): no problems |
| 31-tsa-freetsa-verified.json | live FreeTSA tokens over the criteria and the record, FreeTSA root as anchor: `tsa_signature` both `verified` |
| 32-tsa-digicert-verified.json | live DigiCert tokens, DigiCert Trusted Root G4 as anchor: both `verified` |
| 33-tsa-unrelated-root-untrusted.json | 31's tokens with an unrelated anchor: both `untrusted` |
| 34-tsa-tampered-signature-failed.json | 31 with one bit flipped in the criteria token's signature: criteria `failed`, receipt `verified` |
| 35-tsa-token-without-signer-certificate.json | a live FreeTSA criteria token requested with certReq=false: criteria `no_signer` |
| 36-tsa-no-anchors-not-evaluated.json | 31's tokens with no anchors: both `not_evaluated` (an omitted field reads the same) |
| 37-tsa-synthetic-control-verified.json | a criteria token from a test-only PKI (root, intermediate, TSA), test root as anchor: `verified` (control for 38 and 39) |
| 38-tsa-intermediate-expired-failed.json | as 37, but the intermediate CA expired before genTime while the TSA certificate is still valid: `failed` |
| 39-tsa-content-type-mismatch-failed.json | as 37, but the signed `contentType` attribute is `id-ct-authData`; the signature itself is valid: `failed` |
| 40-tsa-rsassa-pss-verified.json | as 37, signed with RSASSA-PSS (SHA-256, MGF1-SHA-256, salt 32): `verified`; `unsupported` also conforms (PSS is optional, listed in the vector's `tsa_signature_accepted`) |
| 41-tsa-ecdsa-p256-verified.json | as 37, with an ECDSA P-256 TSA key: `verified` |
| 42-tsa-ecdsa-p521-unsupported.json | as 37, with an ECDSA P-521 TSA key: `unsupported` |
| 43-tsa-empty-anchor-list-not-evaluated.json | 31's tokens with `tsa_roots_base64: []`: both `not_evaluated`, as 36 |
| 44-tsa-unsupported-curve-and-bad-digest-failed.json | as 42 (P-521), with a messageDigest that does not match: `failed` |
| 45-tsa-no-certificates-and-bad-digest-failed.json | a test-PKI token without certificates, with a messageDigest that does not match: `failed` |
| 46-tsa-unsupported-curve-and-ess-mismatch-failed.json | as 42 (P-521), with an ESS signing-certificate hash that does not match: `failed` |
| 47-receipt-payment-x402-exact.json | a passing receipt whose signed body carries the optional `payment` member (x402 exact on Base, synthetic values): no problems, the same outcome as without it |
| 48-tsa-signer-without-timestamping-eku-failed.json | a test-PKI token (root B) whose signer certificate lacks `id-kp-timeStamping`; everything else holds: `failed` |
| 49-tsa-issuer-not-a-ca-failed.json | a test-PKI token (root B) whose TSA certificate is issued by a certificate without the CA flag; everything else holds: `failed` |
| 50-criteria-token-imprint-only-in-status-string.json | the criteria token's signed TSTInfo covers other bytes; the criteria imprint and time sit only in the unsigned `statusString`: `CRITERIA_TIMESTAMP_MISMATCH`, warning `CRITERIA_COMMITMENT_UNVERIFIED` (contributed by Tetsurohhori, CC0) |
| 51-record-token-imprint-only-in-status-string.json | the record-token side of 50: `receipt_timestamp` `imprint_mismatch`, no problems |
| 52-receipt-non-integer-numbers.json | a passing receipt whose signed body holds non-integer numbers, canonicalized as RFC 8785 (ECMAScript) numbers |
| 53-tsa-anchor-same-name-other-key-untrusted.json | 37's token; the only anchor is root B, with root A's name and another key: `untrusted` |
| 54-tsa-expired-intermediate-no-anchor-failed.json | 38's token (intermediate expired) with an unrelated anchor: `failed` |
| 55-receipt-payment-outside-the-form.json | as 47, with `payment.amount` a JSON number and an extra member: no problems, the same outcome as without it |
| 56-third-party-checker-live-receipt.json | a live receipt issued by another checker under its own key (a self-test, not a real job), kept as received: no problems (contributed by babyblueviper1, CC0) |
| 57-receipt-integer-valued-doubles.json | a passing receipt whose signed body holds 1.0, 100.0, -0.0 and 300.0, which RFC 8785 writes as 1, 100, 0 and 300 |
| 58-criteria-token-imprint-only-in-unsigned-attribute.json | as 50, with the criteria imprint and time in an unsigned CMS attribute of the token's SignerInfo instead of the statusString (a well-formed response): `CRITERIA_TIMESTAMP_MISMATCH`, fallback with `CRITERIA_COMMITMENT_UNVERIFIED` (contributed by aos-standard/catalog, CC0) |
| 59-record-token-imprint-only-in-unsigned-attribute.json | the record-token side of 58, as 51: `receipt_timestamp` `imprint_mismatch`, no problems (contributed by aos-standard/catalog, CC0) |

Each file contains its inputs and an `expected` object with the outcome an independent verifier should reproduce. The keys in the vectors are test keys:
never trust them. The timestamp tokens in the vectors are imprint-and-time fixtures, not valid RFC 3161 tokens: their SignedData has no SignerInfo, so OpenSSL and other CMS parsers that require a signer refuse them. They test imprint and time handling only. Vectors 31-36 instead carry real RFC 3161 tokens (FreeTSA and DigiCert, fetched 2026-10-20), and 37-46 (except 43) tokens from a test-only PKI (openssl 3.5, re-signed at a fixed genTime; the test root is not a real authority), and relying-party anchors in `inputs.tsa_roots_base64`.

## Reference verifier (`verifier/`)

`verifier/war_verify.py` runs the procedure above using only the Python standard library (Ed25519, JCS with RFC 8785 numbers, reading the token's signed TSTInfo, and the profile 1.4 authority-signature checks are implemented in the file), with no network access:

    python -I verifier/war_verify.py vectors/*.json

`verifier/check_payment.py` (standard library, network) checks a receipt's optional `payment` member against the chain:
EIP-3009 `authorizationState(payer, nonce)` on `asset`, and, given `settlement_tx`, the `AuthorizationUsed` and
`Transfer(payer, pay_to, amount)` logs and a block no later than `issued_utc`. It reports `verified`,
`authorization_used`, `not_found`, `mismatch` or `unsupported` (also for a member outside the form: all members strings,
`network` `eip155:` plus a decimal chain id, `amount` a decimal string, 0x-hex addresses and nonce, no other members),
and changes no outcome:

    python -I verifier/check_payment.py receipt.json

It prints `AGREE` or `DIFF` per vector and exits non-zero on any disagreement; `--outcome FILE` prints the computed outcome object. It checks token imprints, times and accuracy; the authority signature (step 9) is evaluated when anchors are supplied, from a vector's `inputs.tsa_roots_base64` or `--tsa-roots FILE`. It is offered as a reference for comparison; clean-room verifiers that disagree with it, or with a vector's `expected` object, are the useful result.

## Implementations

Verifiers written from this text, each run by its implementer on the published vectors. Every row links that
implementer's own run file at a fixed commit; the result and the disclosure are theirs, as posted.

| Implementer | Code | Vectors | Result | Run file | As disclosed by the implementer |
|---|---|---|---|---|---|
| Tetsurohhori | Python, `cryptography` | 01-57 at `bc5a138` | 57/57 | [ADDENDUM-bc5a138.md](https://github.com/aos-standard/catalog/blob/dda8b4f/docs/runs/work-acceptance-record-cold/ADDENDUM-bc5a138.md) | written from the text; reference verifiers not opened; `expected` objects visible while the inputs were read |
| babyblueviper1 | Python, `cryptography` | 01-55 at `6b2f730` | 55/55 | [upstream_vectors_1_4_1_55_run.txt](https://github.com/babyblueviper1/preaction-governance-conformance/blob/bc5c21d/examples/work-acceptance-record-cold/upstream_vectors_1_4_1_55_run.txt) | written from the text; reference not opened; `expected` objects visible while the inputs were read |
| robertolocatelli81-dev | Python | 01-47 at `06d3b94` | 47/47 (441/441 fields) | [results/score_default.txt](https://github.com/robertolocatelli81-dev/work-acceptance-check-omega/blob/56233ab/results/score_default.txt) | written from the text; reference verifiers not opened |
| reference (this repository) | Python standard library; JavaScript (WebCrypto) on the spec page | 01-57 at `bc5a138` | 57/57 | `python -I verifier/war_verify.py vectors/*.json` | written with the vectors |

The other direction: receipts issued by another checker under its own key (babyblueviper1's invinoveritas checker)
pass the reference verifier unchanged, with `--tsa-roots` set to the FreeTSA and DigiCert roots of vectors 31 and 32
([run](https://github.com/babyblueviper1/preaction-governance-conformance/blob/bc5c21d/examples/work-acceptance-issuer/reference_verifier_6b2f730_run.txt)); one of them is vector 56.

To be listed, open an issue here that links your code and a run file at a published commit.

## Changelog
**Profile 1.4.1 (2026-10-21; schema identifier unchanged).** Settles readings raised by clean-room verifiers of 1.4 (Tetsurohhori; robertolocatelli81-dev) in x402-foundation/tsc#4; vectors 01-36 and their outcomes are unchanged. The `contentType` signed attribute must equal `eContentType` (39). The signer and every issuer other than the anchor must be valid at genTime, and a chain that reaches the anchor but fails a check is `failed` (38, control 37). RSA PKCS#1 v1.5 and ECDSA P-256/P-384 are required, RSASSA-PSS is optional (40, via the new vector field `tsa_signature_accepted`), P-256 (41), other curves `unsupported` (42). An empty anchor list is no anchors (43). Several defects: `failed` if any check that can run fails, else `no_signer`, `unsupported`, `untrusted` (44-46). Not exercised by a live authority: RSASSA-PSS and ECDSA P-256. Revocation is not checked. No further outcome changes to 1.4.1 before 2026-11-21; reports of disagreement are collected and answered together. Added 2026-10-21, outcome-neutral: the optional body member `payment` = `{protocol: "x402", scheme: "exact", network: "eip155:<chain id>", asset, payer, pay_to, amount, nonce}` (optionally `settlement_tx`), inside the signed and timestamped body; `(network, asset, payer, nonce)` names one settlement (vector 47, `verifier/check_payment.py`; asked for by babyblueviper1 from a live record paid on Base). Clarified 2026-10-21, outcome-neutral (from babyblueviper1's run): the anchor is matched by subject name and public key, not by certificate bytes (vector 32 separates the readings); vectors 48 and 49 exercise the `id-kp-timeStamping` and CA-flag rules. Clarified 2026-10-22, outcome-neutral for every earlier vector (from Tetsurohhori and robertolocatelli81-dev): imprint, genTime and accuracy are read from the token's signed TSTInfo only, never from other bytes of a response (50, 51); numbers follow RFC 8785's ECMAScript form, including non-integers (52). The reference verifier follows both from this version. Clarified 2026-10-22, outcome-neutral for every earlier vector (from robertolocatelli81-dev): an anchor with the issuer's name but another key does not match (53); an issuer that fails a check is `failed` even when no chain reaches an anchor (54); the `payment` form is stated and a member outside it changes no outcome (55). An anchor is not checked for validity at genTime; keys outside RSA PKCS#1 v1.5, RSASSA-PSS and ECDSA P-256/P-384 (for example Ed25519) are `unsupported`. Added 2026-10-23, outcome-neutral: vector 56 (contributed by babyblueviper1), a receipt issued by another checker under its own key; vector 57, integer-valued doubles and negative zero (from stillmarcus24). Edited 2026-10-23: the descriptions of vectors 37-42, 44-46, 48, 49, 53 and 54 now point to the provenance on the spec site; inputs and expected outcomes are unchanged.
**Profile 1.4 (2026-10-20; schema identifier unchanged).** Adds the authority-signature outcome `tsa_signature` (step 9), additive and `not_evaluated` without anchors, so vectors 01-30 and existing verifiers are unchanged; vectors 31-36 from live FreeTSA (ECDSA P-384) and DigiCert (RSA) tokens.
**Profile 1.3 (2026-10-18; schema identifier unchanged).** Resolves the questions from clean-room verifiers by Tetsurohhori and robertolocatelli81-dev and a second run by babyblueviper1 (x402-foundation/tsc#4): step 2 names the signed `receipt.key_id` and adds the canonical, prime-order key rule (`KEY_REJECTED`); step 5's reference time is the earlier of `issued_utc` and a covering token's genTime; imprints must be SHA-256 by OID; `accuracy` widens comparisons, `ordering` ignored; a token over other bytes falls back with `CRITERIA_COMMITMENT_UNVERIFIED`; `PRODUCER_UNDECLARED` follows the parties block; step 1 refusal shape; authority signature reported separately; vectors 12-27 added (12b replaces 12; Tetsurohhori's SHA-1 vector superseded by 23). Clarified 2026-10-18: the key rule applies to the named signing key only; vector 28 added; outcomes for 01-27 unchanged. Added 2026-10-19: vectors 29-30, the first whose tokens state an `accuracy`; the reference verifier in `verifier/`.
**Profile 1.2.1 (2026-10-17; schema identifier unchanged).** Resolves ambiguities found by an independent clean-room review (babyblueviper1): `CRITERIA_COMMITTED_AFTER_CHECK` is a problem; the token over `criteria.sha256` is authoritative for commitment time (`CRITERIA_TIME_MISMATCH`, fallback with `CRITERIA_COMMITMENT_UNVERIFIED`); verdict rule completed (required `fail` wins, `VERDICT_MISMATCH`); reference time uses the record's token only when it covers the record; vectors 06-11 added.
**Profile 1.2.** First draft, vectors 01-05.

## Status
Draft, offered for the evidence-record discussion in x402-foundation/tsc#4 and referenced by ACP SEP #303 (Section 7.4a). Independent clean-room
implementations are welcome; please report any disagreement with a vector's `expected` outcome as an issue.

Licence: text CC BY 4.0; vectors and verifier code CC0 1.0.
