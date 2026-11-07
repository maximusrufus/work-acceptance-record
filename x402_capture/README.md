# Releasing an x402 escrow payment on a work-acceptance record (draft)

x402's `auth-capture` scheme in `escrow` with `CaptureMode: deferred` authorizes a payment and leaves capture to the server's
lifecycle manager until `captureDeadline`. This note states one rule for that decision: capture when a
work-acceptance record for the paid work checks out, and void otherwise. It adds no x402 mechanism.

## Rule
Before `captureDeadline`, the receiver authorizer captures only if the reference procedure gives all of:
`signature_valid` true, `criteria_hash` match, `criteria_committed_before_check` yes, `independence` independent,
`verdict_recomputed` pass, and no problem codes. In every other case, including no record by the deadline, it voids.

## Binding to the offer
With the offer-and-receipt extension, the signed offer fixes `payTo`, `amount` and `resourceUrl`. The record names
the same payment in its `payment` member (x402 exact, profile 1.4.1). A record whose payment member does not match
the authorized payment is no evidence for that capture. Binding the criteria document's content to the offer terms is
listed as open in `composition/COMPOSITION.md` section 7; this rule does not close it.

## Demo
`x402_capture/capture_gate.py` applies the rule to all 118 vectors: 54 capture, 64 void. The decision from the
reference verifier's output equals the decision from each vector's expected outcome in all 118 cases.

## Open
- Who runs the check, the facilitator or the receiver authorizer (`CaptureAuthorizer` with `OperatorType: custom`).
- How a partial pass maps to a capture amount (x402 already captures part and voids the rest).
- Refund after capture when a later revision of the record fails.
