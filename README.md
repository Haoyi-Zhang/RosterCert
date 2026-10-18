# Causal roster certificates

Artifact for *Causal Roster Certificates for Session-Separated Accountable Multisignatures under Asynchronous Churn*. It supplies finite-poset roster semantics, an executable Ed25519 checkpoint/delegation/session-signature profile, a public fixture, and a self-contained written proof article. The BGLS realization is proof-only: no pairings, production curve/hash-to-group suite, or performance measurements are implemented.

## Setup

Use Python 3.12 (the CI version) with `cryptography>=41`, declared in `requirements.txt`. From this directory, or the root of either flat public repository:

```sh
python -m venv .venv
# POSIX: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

No network service, secret, GPU, private dataset, or external model is required to run the checks after dependency installation. TeX is needed only for the optional article build.

## Run the bounded source checks

```sh
python -B -m unittest discover -s tests -v
python -B tests/regression_current_versions.py -v
python -B audit_artifact.py
python -B .github/scripts/check_repository.py
python -B .github/scripts/scientific_checks.py
python -B verify_reference.py examples/reference-certificate.json examples/reference-history-public-key.txt
```

The verifier prints `VALID` on success. Its inputs are canonical ASCII-JSON certificate bytes and an independently supplied history public key. The fixture check regenerates one deterministic public certificate in memory and compares the certificate and trust anchor byte-for-byte without rewriting them.

The main suite has 50 test methods: 47 interface checks and three manuscript-source synchronization regressions. The separate current-version regression covers named tiny/admission-boundary fixtures, an independent graph-path reference, and exact payloads. Current-version lookup caches strict-descendant masks; no measured speedup is claimed.

`audit_artifact.py` checks the fixture, package, bibliography/claim ledgers, and campaign disclosures. With a sibling `../paper/main.tex`, it compares the recursively expanded scientific body with `proofs/analysis.tex`; flat public repositories explicitly report that comparison as unavailable. CI runs the bounded source checks on Ubuntu 24.04 and retains raw outputs even on failure. These checks establish implementation behavior and source consistency, not theorem correctness, primitive security, independent replication, or deployment readiness.

## Public example

To overwrite the two supplied example files with their deterministic public bytes:

```sh
python -B generate_reference_example.py
python -B verify_reference.py examples/reference-certificate.json examples/reference-history-public-key.txt
```

The test keys are public and unsafe for real authorization. The verifier rejects noncanonical JSON, duplicate members, invalid active Ed25519 keys, role/key aliases, malformed contexts, and oversized reads. Identifiers are nonempty printable US-ASCII; messages are Unicode scalar values, with surrogate code points rejected before canonical encoding. See `BOUNDARY-VALIDATION.md` for the exact interfaces and regression cases.

## Current finite validation

`results/current-validation.zip` contains the independently authorized current-source
study: 141 inputs, frozen executable source, a prospective plan, environment,
outcomes and cumulative accounting. All 141 cases pass, including 2,725 current
states, 2,725 authorization decisions, 141 windows, 141 universal judgments and
ten chain optimum/flow comparisons. The conservative charge is 55,839 against
a separately declared 100,000 ceiling. Candidate subsets that are not cuts and
unused decision slots are still charged.

Any further finite activity requires its own budget authorization. With that
authorization, use an absent directory outside the artifact, inspect the plan
before execution, then execute it once:

```sh
python -B validate_current.py self-test
python -B validate_current.py plan --out ../current-validation
python -B validate_current.py execute --out ../current-validation
```

The runner rejects changed inputs/sources, a repeated or simultaneous start, and
reservations above its ceiling before enumeration. The archived execution driver
is retained exactly; the current driver additionally uses exclusive creation of
the start marker, checked without another finite campaign. The four archived
semantic modules match the current modules byte-for-byte. This study checks current finite roster,
window and chain-flow implementation agreement, not primitive security. It does
not depend on the unavailable early session helper or change the old campaign.

## Historical campaign: not reproducible evidence

The historical finite diagnostic campaign permanently exceeded its cumulative ceiling: **835,446** charged obligations against **600,000**. Later runs cannot reset, exclude, or repair that terminal breach. All frozen `data/` and `results/` files are non-evidentiary provenance/source-inspection material, not support for any theorem, cryptographic property, complexity result, resource claim, or scientific reproduction claim.

`results/campaign-status.json` is authoritative; `results/README.md` explains the retained inputs, ledgers, outputs, and later post-breach activity. The exact pre-V3 two-column session helper behind the archived 12 mutation labels is absent; `results/HISTORICAL-SOURCE-LIMITATION.md` documents the gap. The current V3 identity/event/key codec is not a historical replacement.

```sh
python -B reproduce.py --explain
```

This prints the limitation and intentionally exits **2**, before generator imports, input creation, ledger reservation, or enumeration. It is not a reproduction command.

## Materials and article build

- `src/`: roster semantics, bounded oracle/generator, shared wire encoding, Ed25519 admission, session payloads, and reference profile.
- `examples/`: public certificate and independent history trust anchor; see its README for input semantics.
- `data/`, `results/`: frozen historical diagnostics and required provenance disclosures.
- `claim_evidence_ledger.csv`, `literature.csv`, `bibliography_audit.csv`, `external_resources.csv`: claim/source mappings, 80-source bibliography, reading depth, identifiers, and license boundaries.
- `proofs/analysis.tex`, `proofs/analysis.pdf`: article with 80 embedded references and its vector diagram in `proofs/figures/`; no BibTeX, external TeX inputs, project-tree paths, or network dependency.

With `pdflatex` installed:

```sh
cd proofs
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
pdflatex -interaction=nonstopmode -halt-on-error analysis.tex
```

Compilation checks typesetting and references, not the written proofs. With
Matplotlib installed, `python -B plot_schematics.py --outdir proofs/figures`
regenerates the vector diagram. The complete project uses the same PDF in the
sibling paper's `figures/` directory; the audit checks their byte identity.

## Conditions and licensing

Event authenticity, admission, ownership, and observation completeness are explicit inputs. An authenticated upper view cannot reveal an undelivered remote update. The executable profile separates history-checkpoint, long-term delegation, and fresh session-key roles; it has no secure key store, randomness service, erasure guarantee, rollback protection, replay database, decentralized governance, transparency consistency proof, or availability protocol.

Neither the Ed25519 nor proof-only BGLS profile supplies constant stored registry-key compression or constant-size causal certificates. The BGLS aggregate alone is one source-group element; its table and other evidence remain linear. See the article for the conditional theorems and assumptions.

Project source and benign fixtures are covered by `LICENSE`. No publisher paper text, third-party implementation, credential, or private data is redistributed.

## Portable path notation

Published execution records use `<PYTHON_ROOT>`, `<NODE_ROOT>`, `<RUNTIME_ROOT>` and `<PROJECTS_ROOT>` for machine-local installation and workspace prefixes. These are path aliases, not literal directories; substitute the corresponding local roots when replaying a command. Recorded interpreter and dependency versions, inputs, measurements and outcomes are unchanged. File inventories bind the published portable serializations; any `recorded_` identity denotes the pre-normalization bytes.
