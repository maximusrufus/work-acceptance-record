# Composing the x402 acceptance record with the work-acceptance record

Draft, not ratified. Profile identifier `war/1.2` is a draft identifier and may change.

## 1. Scope

This document defines one subject profile for the x402 acceptance record, version 0, by Shodai (CNS Labs), tag
`draft-2026-10-27`, called here "the acceptance specification". Under this profile the subject of an acceptance
record is a work-acceptance record, schema `trilatic.acceptance-receipt/1.2`, profile 1.4.1, called here "the work
specification". It also states how a work-acceptance record can refer to an acceptance record.

The acceptance specification lists composition with third-party records such as work-acceptance records as follow-up
work (its section 10). This profile is written to fit its subject-profile slot (its AR-23 to AR-29) without changing
any requirement of either specification.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 and RFC 8174. Requirement numbers `AR-n` refer to
the acceptance specification; section numbers prefixed "W" refer to the work specification.

## 2. Roles

| Acceptance specification | Under this profile |
|---|---|
| Subject record | The work-acceptance record (the envelope of W3.1: `receipt`, `signature`, `timestamp`). |
| Delivery issuer (`deliveryIssuer`) | The checker that signed the work-acceptance record, named as `trust.issuers` names it. |
| Confirming party | The buyer deciding whether to accept the delivered file (W1). |
| Outcome | The delivered file, bound by `files.remediated.sha256`. |
| Terms | The committed criteria document, bound by `criteria.sha256` (W7). |

The work record states what a checker found; the acceptance record states what the buyer decided. Each keeps its own
signer and its own claims (acceptance specification, section 6, Composition).

## 3. Subject profile `war/1.2`

### 3.1 Transmission

The `subject` input (acceptance specification, section 5) is the UTF-8 JSON text of the work-acceptance record
envelope. Its byte form is not significant: all digests below are computed over JCS of the parsed `receipt` member,
as W4 requires.

### 3.2 Authentication

A verifier supporting `war/1.2` MUST treat the subject as available if and only if all of the following hold, and as
unavailable otherwise (AR-23):

1. The text is I-JSON and the envelope has the members of W3.1.
2. `receipt.schema` is `trilatic.acceptance-receipt/1.2`, `receipt.canonicalization` is `JCS-RFC8785` and
   `receipt.suite` is `{"digest":"sha-256","signature":"Ed25519"}` (W3.2).
3. `signature.alg` is `Ed25519`, and `signature.key_id`, `receipt.key_id` and `receipt.parties.checker.key_id` are
   the same string (W5, W8 item 1).
4. `trust.issuers` holds, for `deliveryIssuer`, exactly one Ed25519 key whose key id equals `receipt.key_id`. That
   entry is the external trust input in place of the work specification's published key list (W5). `deliveryIssuer` is
   not compared with `receipt.issuer`, which is a display name (W3.2); the binding of the key to `deliveryIssuer`
   is the relying party's trust input.
5. The key passes AR-19, which is also the key rule of W5.
6. `signature.value` is canonical padded base64 of 64 bytes (W5), and the signature verifies under RFC 8032 over
   `JCS(receipt)` with the AR-20 rule on `R` and `S`.
7. `files.remediated.sha256` and `criteria.sha256` are 64 lowercase hex digits (W4), and `issued_utc` has the form
   W7.3 step 6 requires.

The remaining checks of W10 (timestamp, criteria commitment, independence, verdict) are not part of acceptance
verification under this profile. A relying party that needs them runs a work-record verifier separately and reports
its outcome beside the acceptance result.

### 3.3 Identity

The work specification defines the record digest `sha256(JCS(receipt))`, used "for citing a record elsewhere" (W4).
Under this profile:

```text
digest     = lowercase_hex( SHA-256( UTF-8( JCS( envelope.receipt ) ) ) )      ; 64 characters
identity   = "war/1.2:sha256:" || digest
contextId  = "0x" || digest
```

`subject.profile` MUST be `war/1.2`, `subject.reference` MUST equal `identity` byte-exact, and `contextId` MUST equal
`"0x" || digest`. Otherwise the record is `acceptance_record_digest_mismatch` (AR-24). The envelope's `signature` and
`timestamp` members are not part of the identity; re-wrapping or adding a timestamp token does not change it.

### 3.4 Bound values

| Value the acceptance specification needs | Derived from the work record |
|---|---|
| Outcome digest (AR-25) | `"0x" || files.remediated.sha256`. |
| Outcome time (AR-26) | `issued_utc` as Unix seconds. A non-zero fraction rounds up to the next whole second, so that a fraction never lets `issuedAt` precede the check. This profile uses `issued_utc` only: it ignores any timestamp token covering the record, and does not take the earlier of `issued_utc` and the token's genTime that W7.3 step 5 uses as its reference time. |
| Terms digest (AR-29) | `"0x" || criteria.sha256`. The evidence is the authenticated work record itself, which the subject's issuer signed; no separate `terms` artifact is used. |
| Payer (AR-31) | When `receipt.payment` is present with `network` of the form `eip155:<decimal>` and `payer` of the form `0x` followed by 40 hex digits in either case: `network || ":" || lowercase(payer)`, whose address part is `0x` followed by 40 lowercase hex characters. Otherwise the subject has no payer. |

## 4. Reverse direction

The work specification has no member that refers to an acceptance record. Its section 11 places the acceptance
decision outside the record and says that decision SHOULD cite the record digest, which section 3.3 above does. A work
record is also signed before any acceptance of it exists, so a reference can only appear in a later revision
(`revision` > 1, with `supersedes_sha256`, W3.2).

Proposed minimal member, for a later profile of the work specification:

```json
"acceptance_ref": { "profile": "x402accept/0", "statement_id": "x402accept/0:sha256:<64 hex>" }
```

`statement_id` is the acceptance record's AR-21 identity. A verifier given the acceptance record checks that its
`statementId` equals `statement_id` and that the acceptance record's `subject.reference` names the revision this one
supersedes. Under W3 unknown members are already covered by the signature and ignored for display, so a schema 1.2
verifier would carry the member without acting on it. This document does not define outcome codes for it.

## 5. Verification

A verifier runs AR-35 unchanged. This profile supplies steps 4, 6 and 7 with the subject rules of section 3:

1. Steps 1 to 3 of AR-35 (no record, preflight, key step) as written.
2. Step 4: when `subject.profile` is `war/1.2` and the subject authenticates (3.2), evaluate AR-24 with 3.3, AR-25
   and AR-26 with 3.4, and AR-29 with the terms digest of 3.4. For AR-33, "signed the subject record" means the key
   of 3.2 item 4.
3. Step 6: any other profile this verifier does not support gives `unknown` with `profile_unavailable`.
4. Step 7: an absent or unauthenticated work record gives `unknown` with `evidence_unavailable`.
5. Steps 8 and 9 as written. For `declared-evidence/0`, `subjectProfile` is `war/1.2` and `subjectReference` is the
   identity of 3.3.

### 5.1 Result vocabulary

No result token, condition or reason is added. All outcomes below are existing AR-36 tokens.

| Case | Result |
|---|---|
| Both records valid and bound, authority resolved | `verified` |
| `subject.reference` or `contextId` differs from the work record's identity | `malformed`, `acceptance_record_digest_mismatch` |
| Both records valid but the acceptance names a different work record | `malformed`, `acceptance_record_digest_mismatch` |
| `outcomeDigest` differs from `files.remediated.sha256` | `malformed`, `acceptance_outcome_digest_mismatch` |
| `termsDigest` differs from `criteria.sha256` | `malformed`, `acceptance_terms_digest_mismatch` |
| `issuedAt` earlier than the outcome time of 3.4 | `malformed`, `acceptance_precedes_outcome` |
| Acceptance signed with the checker's key, or naming the checker | `malformed`, `acceptance_signer_is_issuer` |
| Acceptance record altered after signing | `malformed`, `signature_invalid` |
| Profile id other than `war/1.2` and not supported | `unknown`, `profile_unavailable` |
| Work record named under a profile that does not define it (for example `x402ev/1`) | `unknown`: `profile_unavailable` if that profile is unsupported, `evidence_unavailable` if supported, because the subject does not authenticate under it |
| Work record absent, altered after signing, or signed by an unlisted key | `unknown`, `evidence_unavailable` |
| Declared authority names another work record | `unknown`, `acceptance_authority_unresolved` |

The work record's own codes (W10, for example `SIGNATURE_INVALID` or `VERDICT_MISMATCH`) are reported only by a
separate work-record verification and never appear in the acceptance result.

## 6. Test vectors

Sixteen vectors (`C01` to `C16`) accompany this document, generated deterministically from published seeds, with a
checker. They use the JWS form of the acceptance record only; the EIP-712 form is not exercised. The keys are test
keys; never trust a record signed by one.

## 7. Not covered

- The EIP-712 signing form of the acceptance record.
- Any check of the work record beyond 3.2: RFC 3161 timestamps, criteria commitment timing, independence, verdict
  recomputation, and the payment member's settlement (W6 to W10).
- Any relation between `disposition` and the work record's `verdict`. A buyer may accept a record whose verdict is
  `fail` or `incomplete`, or reject one whose verdict is `pass`; this profile records the decision, not its merit.
- Records of schema `/1` or `/1.1`, and work records with `revision` > 1 as a chain: each revision is a separate
  subject with its own identity.
- Binding the criteria document's content to the offer or contract terms of an x402 payment.
- Use of `criteria_commitment` (client-agreed terms digest) as the terms digest.
- How the relying party obtains the checker key it lists in `trust.issuers`.
- Response windows, `not_responded`, revocation and transport, as in the acceptance specification's section 10.

## References

- x402 acceptance record, version 0, Shodai (CNS Labs), tag `draft-2026-10-27`.
- Work-acceptance record specification, schema `trilatic.acceptance-receipt/1.2`, profile 1.4.1.
- RFC 2119; RFC 7493; RFC 7515; RFC 8032; RFC 8174; RFC 8785.
