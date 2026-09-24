# Accountable multisignatures under asynchronous churn

This standalone repository accompanies the internal article **Causal Roster Certificates for Session-Separated Accountable Multisignatures under Asynchronous Churn**.

## What is established

The self-contained article proves:

- an exact interval characterization of all causal cuts authorizing one fixed identity/key-version profile;
- exact historical, view-fresh, and window-robust acceptance modes;
- a session-separated compiler that binds exact long-term versions to fresh one-session keys;
- a generic completed-framing reduction;
- a conditional executable Ed25519 signed-checkpoint/delegation/vector profile;
- a conditional key-prefixed BGLS one-session aggregate realization;
- maximum-closure tractability for per-identity chains and NP-completeness with quarantined forks;
- information limits for hidden revocation and undeclared observation.

The Ed25519 profile is implemented and performs real public-key verification. The BGLS profile is a written random-oracle reduction only: this repository does not implement pairings, choose a production curve/hash-to-group suite, or report performance. Neither profile supplies the anchor paper's constant stored registry-key compression, and neither makes the complete causal certificate constant size.

## Permanent campaign warning

The historical finite diagnostic campaign exceeded its declared cumulative ceiling. The superseded controller charged **835,446** obligations against a **600,000** ceiling. Under the governing project rule, that breach is terminal. Later runs and ledgers cannot reset, exclude, or repair it.

Accordingly, all frozen files under `data/` and `results/` are provenance and source-inspection material only. They are not evidence for a theorem, cryptographic property, complexity result, resource claim, or scientific reproduction claim. `results/campaign-status.json` is the authoritative interpretation. Do not run `reproduce.py` expecting to create valid evidence; another run would only be another post-breach observation.

## Repository map

- `proofs/analysis.tex`, `proofs/analysis.pdf`: self-contained 36-page article with embedded 80-item bibliography.
- `src/roster.py`: finite-poset roster semantics.
- `src/oracle.py`: separately structured exhaustive oracle for small source-integrity cases.
- `src/cases.py`: deterministic historical-corpus generator.
- `src/session.py`: strict semantic normalization and canonical byte encodings for history, delegation, and base messages.
- `src/reference_profile.py`: executable Ed25519 checkpoint, delegation, and linear one-session signature profile.
- `verify_reference.py`: bounded file verifier; requires canonical ASCII JSON bytes.
- `generate_reference_example.py`: deterministic generator for the public, non-secret fixture.
- `examples/`: canonical reference certificate and independent history trust anchor.
- `tests/test_core.py`, `tests/test_reference_profile.py`: 38 source-integrity tests.
- `audit_artifact.py`: static package/fixture/ledger/bibliography audit; never invokes the historical scientific runner.
- `claim_evidence_ledger.csv`: material claims mapped to proofs, source checks, and maturity.
- `literature.csv`: 80 scholarly sources with role and disclosed reading depth.
- `bibliography_audit.csv`: persistent-identifier, citation-count, and verification-depth audit for all 80 entries.
- `external_resources.csv`: scholarly/tool records, acquisition mode, license boundary, and integration role.
- `data/`, `results/`, `reproduce.py`: preserved historical diagnostics and terminal campaign disclosure; non-evidentiary.

## Dependency

The executable reference profile requires Python 3 and `cryptography>=41`, as declared in `requirements.txt`. No secret, network service, GPU, private data, or external model is required.

## Source-integrity tests

From the repository root:

```sh
python3 -m unittest discover -s tests -v
```

The current package contains **38** test methods. They cover semantic malformed inputs, exact identity/event/key binding, all temporal modes, certificate schema strictness, wrong trust anchors, signature and context mutation, cross-identity aliases, cross-role key reuse, duplicate ephemeral keys, malformed unselected active keys, noncanonical encodings, bounded input handling, duplicate JSON members, and command-line verification. Passing them shows that the package executes the stated checks; it does not prove Ed25519, the general theorems, or deployment security.

## Regenerate and verify the public certificate

```sh
python3 generate_reference_example.py
python3 verify_reference.py \
  examples/reference-certificate.json \
  examples/reference-history-public-key.txt
```

Expected verifier output:

```text
VALID
```

The generator derives deterministic test keys so the fixture is byte-reproducible. Those keys are public and unsafe for real authorization. The verifier rejects a file unless its raw bytes equal the profile's canonical ASCII-JSON encoding.

## Static delivery audit

```sh
python3 audit_artifact.py
```

This checks required files, the Ed25519 fixture, ledgers, 80 embedded bibliography items, citation retention, and the permanent campaign warning. It does not run `reproduce.py`, re-enumerate the corpus, or constitute independent scientific replication.

## Build the self-contained article

```sh
cd proofs
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
```

The source contains no `\input`, BibTeX invocation, project-tree path, repository URL, or network dependency. Successful compilation checks typesetting and references only, not mathematical correctness.

## Optional inspection of historical code

`reproduce.py` remains solely to preserve how the historical corpus and accounting records were produced. It prints a permanent noncompliance warning. Its outputs must not be described as repaired, compliant, reproduced, or claim-supporting.

## Cryptographic boundary

The executable profile uses three independently modelled Ed25519 roles:

1. a central history-checkpoint key;
2. active long-term version/delegation keys; and
3. fresh one-session keys.

It rejects byte reuse across roles, rejects one active long-term key assigned to two identities, and permits same-owner long-term reuse across event versions only because every payload binds the exact event ID. It has no secure key store, randomness service, erasure guarantee, rollback protection, replay database, governance implementation, transparency consistency proof, or availability protocol.

The proof-level BGLS profile uses validated type-III public-key pairs, public-key-prefixed messages, and a complete table/message/signer-set encoding. Its aggregate is one source-group element; the table and other certificate evidence remain linear. Current BLS implementation guidance is used for validation practice only, while the cited multi-user BLS/BGLS paper supplies the security theorem.

## Trust, licensing, and external use

Event authenticity, admission, ownership, and observation completeness are explicit inputs, not inferred from signatures alone. A received authenticated upper view cannot reveal a remote update that was never delivered.

Project source and benign generated fixtures are provided under `LICENSE`. No publisher paper text, third-party implementation, credential, or private data is redistributed. This is an internal named-author research draft produced with substantive AI assistance. It is not a human-only-production statement, external submission approval, independent review, or acceptance claim.
