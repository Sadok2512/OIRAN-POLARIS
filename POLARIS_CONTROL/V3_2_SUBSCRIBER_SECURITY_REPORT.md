# V3.2 Subscriber Security Report

- New K and OPc material was generated with `openssl rand -hex 16`.
- Secret material is stored only under `/var/lib/polaris-control` with directory mode 0700 and file mode 0600.
- The provisioning command accepts no subscriber secret through command-line arguments.
- MongoDB provisioning receives its protected script through standard input.
- Reports and sanitized inventory contain pseudonyms and validation booleans only.
- A tracked-source scan found no generated subscriber identity, K, OPc, IMEI, or IMEISV value.
- The Web API returns only pseudonyms, profile names, and provisioning/verification state.
- The existing subscriber was verified and never updated or replaced.
- Partial insertion failure triggers deletion only of records inserted by the current operation.
- No subscriber database schema or index was changed.
