"""Runner: python run_vectors.py <vectors.json> <out.json>  (layout per packet/VECTORS_LAYOUT.md)."""

import json
import sys

import x402acc as X


def dec(s):
    if s is None:
        return None
    b = X.b64u_dec(s)
    if b is None:
        raise ValueError("bad base64url input")
    return b


def to_inputs(i):
    return {
        "record": dec(i.get("record")),
        "subject": dec(i.get("subject")),
        "terms": [dec(t) for t in i.get("terms", [])],
        "outcome": dec(i.get("outcome")) if i.get("outcome") is not None else None,
        "trust": i.get("trust") or {},
        "chain": i.get("chain") or [],
        "contractAccounts": i.get("contractAccounts", True),
    }


def same(exp, got):
    if exp.get("result") != got.get("result") or set(exp.get("conditions", [])) != set(
        got.get("conditions", [])
    ):
        return False
    return all(
        (m in exp) == (m in got) and exp.get(m) == got.get(m)
        for m in ("disposition", "reason", "policy_refusal")
    )


def run_one(v):
    try:
        return X.verify(to_inputs(v["inputs"]))
    except X.InputRefused as e:
        return {"result": "REFUSED", "conditions": [], "error": str(e)}
    except Exception as e:  # a crash is a failure, recorded
        return {"result": "CRASH", "conditions": [], "error": repr(e)}


if __name__ == "__main__":
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    res = {}
    for v in d["vectors"]:
        got = run_one(v)
        res[v["id"]] = {
            "got": got,
            "expect": v["expect"],
            "pass": same(v["expect"], got),
        }
    json.dump(res, open(sys.argv[2], "w"), indent=1, sort_keys=True)
    print(sum(r["pass"] for r in res.values()), "/", len(res))
