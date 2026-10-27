# Architecture

## Principles

OIRAN-POLARIS is organized around four independent applications with explicit,
versioned contracts. Applications may be built and deployed independently. Shared
packages contain contracts and technical utilities, not domain ownership.

## Application responsibilities

### Simulator Control

Owns UE/gNB simulation and bounded traffic generation. It does not control packet
capture or manufacture decoded network evidence.

### Probe Manager

Owns probe inventory, interfaces, capture lifecycle, capture jobs, and PCAP
management. Privileged capture operations remain isolated from web applications.

### OIRAN Analyzer

Owns protocol decoding, session reconstruction, evidence-based correlation,
packet provenance, and Call Flow. It consumes capture evidence through versioned
contracts and does not control simulators.

### Portal

Provides navigation to the independent applications. It is not a shared business
logic layer and must not proxy privileged lifecycle operations.

## Boundaries

- Identity contracts are stable and versioned.
- Authentication remains owned by each application until a separately reviewed
  shared boundary is approved.
- Persistent state belongs to its owning service and is not stored in the Portal.
- A changed module receives targeted tests, contract tests, and targeted deployment.
- Cross-application integration uses published contracts rather than source imports.

This document defines the target foundation only. It does not migrate the existing
`OIRAN/` or `POLARIS_CONTROL/` snapshots.
