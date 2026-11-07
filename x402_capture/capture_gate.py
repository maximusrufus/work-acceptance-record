"""Decide capture or void for an x402 auth-capture payment (CaptureMode deferred) from a work-acceptance record.

Draft demo, local only. Capture only when the reference verifier finds the record sound and the recomputed
verdict is pass. Otherwise void before captureDeadline. Usage: python capture_gate.py WAR_VERSION_DIR VECTOR.json...
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(sys.argv[1], "verifier"))
import war_verify as W

# what a capture needs; anything else voids
NEED = {
    "signature_valid": True,
    "criteria_hash": "match",
    "criteria_committed_before_check": "yes",
    "independence": "independent",
    "verdict_recomputed": "pass",
}


def decide(outcome):
    unmet = [k for k, w in NEED.items() if outcome.get(k) != w]
    if outcome.get("problem_codes"):
        unmet.append("problem_codes")
    return ("capture", []) if not unmet else ("void", unmet)


if __name__ == "__main__":
    for p in sys.argv[2:]:
        d, why = decide(W.vector_outcome(json.load(open(p, encoding="utf-8"))))
        print(d, os.path.basename(p), ",".join(why))
