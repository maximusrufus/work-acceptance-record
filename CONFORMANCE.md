# Conformance reports

Implementations that have reported results against the test vectors, from their own public reports. Each row states
what the report states. Rows marked "run here" were also run by this repository, as the row says; the others have not
been run here.

| Implementation | Version | Profile | Vectors reported | Result reported | Reported on | Report |
|---|---|---|---|---|---|---|
| Reference verifier (`verifier/war_verify.py`) | `c5f49b5` (verifier and vectors) | 1.4.12 | 01-130 | 130/130 agree | 2026-11-12 | `python -I verifier/war_verify.py vectors/*.json` in this repository |
| war-verify (robertolocatelli81-dev), run here | 0.12.0, `6df465c` (`war_verify.py` sha256 `2dac8231…`) | 1.4.12 | 01-130 at `f1c8be7`, with `--vector`; 129 and 130 were published after this version | 130/130 agree; two vectors edited to a wrong expectation both disagree (exit 3) | 2026-11-12 | this repository |
| war-verify (robertolocatelli81-dev) | 0.12.0, `6df465c` | 1.4.12 | 01-128, and the live record | 129/129 documents, 1175/1175 fields | 2026-11-10 | x402-foundation/tsc#4, comment 6779379335 |
| war-verify (robertolocatelli81-dev) | 0.12.0, `ba53b5d` | 1.4.11 | 01-126, and the live record | 127/127 documents, 1157/1157 fields | 2026-11-10 | x402-foundation/tsc#4, comment 6763469305 |
| war-verify (robertolocatelli81-dev) | 0.11.0, `7d9f528` | 1.4.8 | 01-118, and the live record | 119/119 documents, 1085/1085 fields | 2026-11-07 | x402-foundation/tsc#4, comment 6709734788 |
| VATE (Poke-nushi): runs the reference verifier inside VATE's receiver (not a separate implementation) | `3e53aac` pinned | 1.4.8 | 110-118 | match | 2026-11-07 | issue #5 of this repository, comment 6705480005 |
| Tetsurohhori, profile 1.4.2 reader | v142.1 (`cb7e8f1`), run at v1.4.7 (`6f7a075`) | 1.4.2 | 01-115 | 108/115 | 2026-11-07 | x402-foundation/tsc#4, comment 6700674426 |

Open readings that a report holds behind options are listed in that report.

## Reporting a run

Open an issue with the "Conformance report" template, or post the same fields where you discuss the profile. A row is
added for a report that names:

1. the implementation and its exact version: a commit, or a release with its sha256;
2. the profile it implements, and the tag or commit of the vectors it ran;
3. the result: documents (and fields, if counted) that agree, and each vector that differs, with your outcome;
4. any vector your implementation does not cover, marked not evaluable with the reason (for example, a profile
   older than the vector), rather than counted as a failure or left out;
5. the date of the run.

Run the reference verifier the same way to compare: `python -I verifier/war_verify.py vectors/*.json`. A result that
differs from a vector is listed as it was reported; whether the vector or the implementation is wrong is settled in the
report's thread, not by removing the row.
