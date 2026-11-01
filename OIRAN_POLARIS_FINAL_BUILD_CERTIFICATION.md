# OIRAN / POLARIS final build certification

Date: 2026-11-01 UTC
Scope: offline only; production unchanged

- POLARIS API 0.28.1 source: `8cb356a7e4264b80fb82e2f1c90b9511f581df41`.
- POLARIS binary SHA-256:
  `3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`.
- OIRAN API 2.7.3 source: `724e6a0c93fdc09c28dfe9fb255ef64d8a5563bd`.
- OIRAN binary SHA-256:
  `bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`.

Both ELF64 x86-64 PIE binaries require only `libgcc_s`, `libm`, `libc` and the
system loader. Their highest required GLIBC symbol version is 2.34; the host
provides GLIBC 2.39. All `ldd` dependencies resolve.

The exact offline HTTP recipe passed with three independently hashed LTE plane
artifacts: POLARIS publication 200, exact replay 200, drift 409; OIRAN import
201, replay 200, conflict 409. OIRAN 2.7.3 associated 3/3 events, produced two
evidence edges and reported `S1_MME_S11=STRONG`, `S11_S1_U=EXACT`,
`E2E=STRONG`. This is an offline fixture result, never a real LTE claim.

Security, privacy, test results, backup hashes and the production recipe are
recorded in `OIRAN_POLARIS_FINAL_RELEASE_GATE_REPORT.md`.

— ANR1
