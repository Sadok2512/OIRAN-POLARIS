# OIRAN / POLARIS final release gate

Date: 2026-11-01 UTC
Mode: read-only production verification and offline candidate validation

POLARIS_BINARY = **PASS** — API 0.28.1, source
`8cb356a7e4264b80fb82e2f1c90b9511f581df41`, 21,273,992 bytes, SHA-256
`3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`.

OIRAN_BINARY = **PASS** — API 2.7.3, source
`724e6a0c93fdc09c28dfe9fb255ef64d8a5563bd`, 13,562,040 bytes, SHA-256
`bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`.

GIT_LINEAGE = **PASS** — POLARIS production source `4669de8b` is an ancestor
of 0.28.1; OIRAN production source `6464476a` and 2.7.2 source `430a094` are
ancestors of 2.7.3. The release integration contains both component commits
through a normal Git merge; no `merge -s ours` was used.

HTTP_INTEGRATION = **PASS offline** — the exact POLARIS response was posted to
the isolated OIRAN HTTP route. Publication returned 200, exact replay 200 and
changed evidence 409. Import returned 201, exact replay 200/idempotent and
conflict 409. The final dataset has 3 source events, 3 session events, zero
unmatched/duplicate events, one LTE session and two correlation edges. Call
Flow status is `S1_MME_S11=STRONG`, `S11_S1_U=EXACT`, `E2E=STRONG`.

SECURITY = **PASS offline** — Grant V2 profile/session ownership, canonical
image/Compose digests, Operator RBAC, CSRF, nonce, expiry, revocation,
anti-replay, cleanup, server-side rehashing, canonical path confinement,
idempotence and HTTP 409 conflict handling are covered. Publication does not
set `LTE_E2E_CERTIFIED=true`.

PRIVACY = **PASS offline** — ingress and JSON/HTML datasets, sessions, events,
packets and Call Flow boundaries reject or remove subscriber/equipment
identities and K/OPc/authentication material. The HTTP evidence leak scan found
zero forbidden labels/values. No production capture or subscriber secret was
read into this report.

RESOURCE_GATES = **PASS** — at `2026-11-01T11:31:38Z`, memory used was
16,013,324,288 bytes, available memory 4,957,257,728 bytes, root disk 60% and
12 external dumpcap processes were active. No candidate service was started in
production. Dumpcap PID rotation remains externally managed and continuity
without loss is explicitly **not certified**.

BACKUP_ROLLBACK = **READY** — fresh mode-0600 independent archives:

- `/root/release-gate-backups/20261101T113300Z/polaris-current.tar`, SHA-256
  `c5fc2129ece78c0999a9d389516ded164eed43c77932dbcd556bd631fc9c6dff`;
- `/root/release-gate-backups/20261101T113300Z/oiran-current.tar`, SHA-256
  `73b9e390883693ecd33dc285058f30cafd8de7775868ef5f2ac167193e2071ec`.

Both archives pass `sha256sum -c`. They contain the current APIs, relevant UI,
configuration, units/drop-ins and persistent registries. Dataset/PCAP payloads
were not copied or modified. Current rollback binaries are POLARIS 0.26.0
`5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8`
and OIRAN 2.5.4
`7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657`.

## ABI and dependencies

Both candidates are ELF64 little-endian x86-64 PIE executables, System V ABI.
POLARIS Build ID is `45f776983b4678d536bfbd26c1055a6c1aa4212e`;
OIRAN Build ID is `3fbe643951d7dbf88c64633f5c6d743c42714256`.
Required libraries are `libgcc_s.so.1`, `libm.so.6`, `libc.so.6` and
`ld-linux-x86-64.so.2`; all resolve on the GLIBC 2.39 production host. Maximum
required GLIBC symbol version is 2.34.

## Tests and known skips

- POLARIS exact 0.28.1 tree: 249 passed, zero failed, three explicitly ignored
  manual Mongo/100,000-profile benchmarks. Frontend TypeScript/build and
  235/235 Vitest pass; Playwright 24/24 plus six LTE view variants pass.
- OIRAN 2.7.3: session-engine 18/18, correlation/callflow 18/18, API 41/41;
  live-probe 56 passed, zero failed, four explicitly ignored high-memory tests.
  Frontend TypeScript/build/leak scan and 77/77 Vitest pass.
- No ignored test is counted as PASS. No current functional FAIL remains in the
  offline release recipe.

## Candidate UI assets

- POLARIS deterministic UI archive SHA-256:
  `bd749ab68cd57803d21f43b73baaf0693b3c0487686238d595dde870703cb06d`.
- OIRAN deterministic UI archive SHA-256:
  `09b7a94bf7dd597c07c3503ab51557987854003605f4dadd14b50fb815037b37`.

## Coordinated production recipe — prepared, not executed

1. Recheck memory/disk, record dumpcap PID/start identities and verify both
   candidate hashes immediately before installation.
2. Re-run `sha256sum -c` on the fresh component backups.
3. Deploy POLARIS API/UI atomically, restart only `polaris-control.service`,
   and verify version, health, authentication, Grant V2 locked state, UE
   inventory and no unintended live operation. Roll back POLARIS alone on any
   failure.
4. Deploy OIRAN API/UI atomically, restart only `oiran-api.service`, and verify
   version, health, authentication, probe/dataset/session APIs, bounded Call
   Flow pagination and privacy. Do not restart Capture Helper or dumpcap.
   Roll back OIRAN alone on any failure.
5. Verify Session Explorer and Call Flow with existing authorized data, verify
   all 12 capture processes and compare their start identities. Do not claim
   lossless rotation without packet-level handoff evidence.
6. A real LTE certification remains a separate authorized operation; this gate
   does not set `LTE_E2E_CERTIFIED=true`.

RELEASE_READY = **YES** for coordinated deployment approval.

BLOCKERS = No artifact, lineage, security, privacy, resource or offline HTTP
gate blocker. Operational caveats: dumpcap rotation continuity remains
uncertified; four OIRAN high-memory and three POLARIS manual benchmark tests
remain explicitly ignored; LTE `REAL_PASS` is not claimed.

STOP before deployment. Separate authorization naming both final versions and
SHA-256 values is required.

— ANR1
