# Conformance reports

Implementations that have reported results against the test vectors, from their own public reports. Each row states
what the report states; this repository has not run these implementations.

| Implementation | Version | Profile | Vectors reported | Result reported | Report |
|---|---|---|---|---|---|
| Reference verifier (`verifier/war_verify.py`) | this tree | 1.4.12 | 01-128 | 128/128 agree | this repository |
| war-verify (robertolocatelli81-dev) | 0.12.0, `ba53b5d` | 1.4.11 | 01-126, and the live record | 127/127 documents, 1157/1157 fields | x402-foundation/tsc#4, comment 6763469305 |
| war-verify (robertolocatelli81-dev) | 0.11.0, `7d9f528` | 1.4.8 | 01-118, and the live record | 119/119 documents, 1085/1085 fields | x402-foundation/tsc#4, comment 6709734788 |
| VATE (Poke-nushi): runs the reference verifier inside VATE's receiver (not a separate implementation) | `3e53aac` pinned | 1.4.8 | 110-118 | match | issue #5 of this repository, comment 6705480005 |
| Tetsurohhori, profile 1.4.2 reader | v142.1 (`cb7e8f1`), run at v1.4.7 (`6f7a075`) | 1.4.2 | 01-115 | 108/115 | x402-foundation/tsc#4, comment 6700674426 |

A row is added when an implementer posts a report naming the version, profile and vectors. Open readings that a
report holds behind options are listed in that report.
