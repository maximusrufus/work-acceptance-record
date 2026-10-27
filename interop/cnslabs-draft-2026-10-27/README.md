# Clean-room run: CNSLabs x402-acceptance-record, tag draft-2026-10-27

- Release tag: `draft-2026-10-27` of CNSLabs/x402-acceptance-record, commit `428fa21`.
- Checker revision: `97ac890` (frozen 2026-10-27T09:11:30-07:00, before the run). `FREEZE.md` lists the hashes of the frozen files.
- Results: 127/127 vectors (`results/REPORT.md`, `results/run_frozen.json`); no disagreements. 41 mutated or re-signed inputs (2 sanity re-signs, 39 mutations), all giving the result the specification text predicts (`results/phase3.json`, `results/phase3_mutate.py`).
- Interpretation differences: `checker/AMBIGUITIES.md` (19 readings, written before the freeze).
- Read log: `checker/READ_LOG.md`. The checker was written from `packet/SPEC.md`, `packet/CASES.md`, `packet/VECTORS_LAYOUT.md` (the specification files and the vectors-layout README of the tag) and the two pinned x402 texts they cite: the offer and receipt extension at coinbase/x402 `faa1c694` and x402ev/1 at `23b5c21`.

## Scope

JWS and EIP-712 forms as implemented in `checker/x402acc.py`. Two cases added in the specification repository's r1 (equivalent integer spellings in EIP-712 offers; a non-CAIP-2 network id in JWS pairs) were not part of this run and have not been tested here.

## Rerun

Python 3.14.5 with pynacl 1.6.2, pycryptodome 3.24.1, eth-keys 0.8.0 and rfc8785 0.1.4 (`pip install pynacl pycryptodome eth-keys rfc8785`, exact versions as listed).

    python checker/run_vectors.py <vectors.json> <out.json>

`<vectors.json>` is the tag's `vectors.json` (CC0; layout in the tag's vectors-layout README); the run prints `127 / 127`. `results/phase3_mutate.py` reads the tag's `vectors.json` and `seeds.json` from a `sealed/` directory next to `checker/` (not included here) and rewrites `results/phase3.json`.

## Hashes and the path scrub

SHA-256 of the frozen files, as in `FREEZE.md` (unchanged): the four `checker/*.py` files and `checker/AMBIGUITIES.md` are byte-identical to the frozen copies and match those hashes.

Path scrub after the freeze: absolute local paths were replaced by repository-relative names in `checker/READ_LOG.md` (three `packet/...` lines) and in `results/phase3_mutate.py` (the root directory is now derived from the script location). Their code and content are otherwise unchanged. The hash of `READ_LOG.md` in `FREEZE.md` (`7119e936...`) is the hash of the unscrubbed file; the scrubbed file is `3d7124d0d1751946...`. `phase3_mutate.py` is not in the `FREEZE.md` list (its scrubbed hash is `d2ef427e6b481b79...`). Rerun with the scrubbed script reproduces `results/phase3.json` byte for byte, and the checker reproduces `results/run_frozen.json` byte for byte.
