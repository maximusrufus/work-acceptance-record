# Ambiguities found while drafting the war/1.2 composition profile

Each item quotes the line that caused it and states the reading used.

## Acceptance specification (CNSLabs, draft-2026-10-27)

1. **Who `deliveryIssuer` is when the subject is not a delivery.** Roles: "The delivery issuer signed the record of the
   delivery, called the subject record (for x402, the seller's server)." A work record is signed by a checker, not by
   the seller who delivered. Reading used: `deliveryIssuer` is the subject record's signer (the checker). Consequence:
   AR-33 then guards checker = acceptor, but nothing in the spec stops the *producer* (seller) from being the
   confirming party under this profile.

2. **Resolved by AR-29 and section 5.** AR-29: "as the subject profile defines it"; section 5: "`terms` | Zero or more issuer-signed terms artifacts". The profile may define the evidence. Original note: **AR-29 wording assumes separate terms evidence.** "`termsDigest` MUST equal the terms digest committed in
   authenticated evidence from the subject record's issuer, as the subject profile defines it." It does not say
   whether the subject record itself may be that evidence, or whether the `terms` input must be non-empty. Reading
   used: the profile may define the subject as the evidence (war/1.2 does, via `criteria.sha256`).

3. **AR-23 "a key that `trust.issuers` lists".** "`trust.issuers` | Entries `{issuer, keys}`: Ed25519 keys (optional
   key ids)". When a key id is present, it is not said whether it must match the subject's own key identifier.
   Reading used: under war/1.2 it must equal `receipt.key_id`, and exactly one entry must match.

4. **Resolved by AR-23.** AR-23: "In the profiles below, a field without its stated form makes the subject unavailable." Original note: **AR-35 step 4 vs. the profile's own subject checks.** "when the subject profile is known and the subject is
   available, AR-24 to AR-26". A profile can make a subject unavailable for a field-form failure ("a field without its
   stated form makes the subject unavailable"), so a malformed digest inside a validly signed work record yields
   `unknown`, not a mismatch. Followed as written; noted because a relying party might expect a mismatch.

5. **Unverified.** The tag and commit of SPEC.md were not confirmed from SPEC.md or CASES.md themselves. Original note: **Vectors README names an older tag.** The vectors README names tag `draft-2026-10-21`
   (commit `ad53b54…`), while SPEC.md read here is tag `draft-2026-10-27` (commit 428fa21). "Exact input and output
   bytes for every case in `CASES.md` of the published specification (CNSLabs/x402-acceptance-record, tag
   `draft-2026-10-21` …)". Unclear whether the vectors were regenerated for the later tag.

6. **AR-18 `signer` for payer/0 in JWS form.** "JWS: the key's identifier (AR-18)" for `signer`, while AR-31 requires
   `signer`, `confirmingParty` and the subject's payer to be "the same string" (an `eip155:` account). So a JWS
   payer/0 record needs a `trust.keys` entry whose `signer` is an `eip155:` account string. Vector C02 does this;
   whether the spec intends it is unclear.

7. **Resolved by AR-23 and AR-35 steps 6 and 7.** AR-35: "6. Unknown subject profile: `unknown`, reason `profile_unavailable`. 7. Subject or terms evidence unavailable: `unknown`, reason `evidence_unavailable`." Original note: **Wrong-profile outcome depends on verifier support.** AR-23: "An unknown `subject.profile` gives `unknown` with
   reason `profile_unavailable`." The same record (a work record named under `x402ev/1`) yields
   `profile_unavailable` from a verifier without x402ev/1 and `evidence_unavailable` from one with it. Not a defect,
   but vectors must state which verifier they assume (C05 does).

## Work specification (schema 1.2, profile 1.4.1)

8. **No member for a downstream decision.** Section 11: "Acceptance decision | Not in the record. The decision to
   accept or reject is the buyer's, made separately, and SHOULD cite the record digest sha256(JCS(receipt))". There
   is a forward citation rule but no prefix or profile name for the cited digest; war/1.2 introduces
   `war/1.2:sha256:`.

9. **`issued_utc` precision vs. integer seconds.** Section 7.3 step 6 allows "YYYY-MM-DDTHH:MM:SS[.fff]Z"; the
   acceptance record's `issuedAt` is integer seconds and AR-26 allows "no tolerance". Rounding is unspecified by
   either text. Reading used: round the fraction up (vectors C11, C12).

10. **Unknown members and a future `acceptance_ref`.** Section 3: "Unknown members MUST be ignored for display but
    remain covered by the signature", while section 10 refuses "Every object, array and string the procedure reads"
    of the wrong type. An added member is not read by the procedure, so a schema 1.2 verifier should carry it; the
    text does not say whether an issuer MAY add members without a schema change.

11. **`issuer` (display name) vs. `trust.issuers[*].issuer`.** Section 3.2: "issuer | Display name of the issuing
    organisation." It is not an identifier and is not compared with `deliveryIssuer`; a relying party must bind the
    key to `deliveryIssuer` itself.

## Implementation notes

- CNSLabs signing implemented from SPEC.md text only: JWS form (AR-15 to AR-17, AR-19, AR-20), body checks (AR-4 to
  AR-6, partial: integer spelling is checked through JCS re-serialisation of the payload, AR-16), statementId
  (AR-21), verification order (AR-35), authority profiles payer/0 and declared-evidence/0. EIP-712 not implemented.
