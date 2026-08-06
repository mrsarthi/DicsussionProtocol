# ⚠️ DEVELOPMENT ARTIFACTS — DO NOT SHIP

The `.zkey` and `.ptau` files in this directory come from a **single-party
local ceremony** run by `npm run build:circuits` on a developer machine.

**They provide no security.** One party generated all the entropy, so anyone
who reproduces it can forge proofs for every claim the circuit makes — fake
channel membership, fake reputation tier, and unlimited messages past the rate
limit, all silently verifiable.

They exist so tests can run. Nothing more.

## Before any release

Replace these with artifacts from a real ceremony:

1. Phase 1: the public **Hermez BN254** Powers of Tau transcript — not a
   locally generated `.ptau`.
2. Phase 2: **≥5 independent contributors** plus a public final beacon.
3. Publish the contributor list, contribution hashes, beacon source, and
   `snarkjs zkey verify` output.

Runbook: [`docs/TRUSTED_SETUP_CEREMONY.md`](../../../../../docs/TRUSTED_SETUP_CEREMONY.md)
Normative requirements: RFC 003 §9 and §11.

## How release tooling detects this

The presence of this file marks the directory as development-only. Packaging
MUST fail while it exists (RFC 003 §11.4). Delete it only when the artifacts
beside it came from a verified multi-party ceremony.
