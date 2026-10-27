# Production Difference Report

## OIRAN

Production already contains the four-plane deployment and continuous-certification runtime changes, but its API binary came from a dirty worktree and is not traceable to one clean commit. The candidate adds the reviewed atomic derived-dataset registration, typed E2E-002 correlation evidence, authenticated candidate checks, and a clean integration of the deployed continuous changes. Candidate binary hashes differ from production and require a separately authorized deployment.

## POLARIS

Production API PID 76637 runs `/root/POLARIS_CONTROL/target/release/polaris-control-api`, SHA256 `141605dfa8a506c233091dc6f226a47677fcf991d3d672743bc3ff57dcd7b1e8`. Its source baseline is V3.2.1-era code; the candidate additionally contains durable CPU decision evidence, corrected warning semantics, restored V3.2 controls, portable authenticated checks, and explicit recognition of the existing `INSUFFICIENT_RESOURCES` safe state. The candidate binary differs and is not deployed.

Classification: currently deployed functionality is preserved; candidate-only changes are the reviewed E2E-002 release corrections; no required feature is missing; production source provenance remains unverified at binary-byte equivalence for OIRAN.
