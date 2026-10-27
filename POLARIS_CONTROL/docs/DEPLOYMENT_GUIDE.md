# Deployment guide

## Provisioning attestation

Before enabling additional UE lifecycle, `polaris-provisioning-attest` compares each selected UERANSIM profile with a root-controlled JSON export of the corresponding authoritative Open5GS subscriber record. It checks the exact SUPI/IMSI, K, OPC, AMF, PLMN, DNN, and configured/default/session slices. Output contains only digests and identifiers; authentication material is never printed. The command defaults to dry-run and writes only with `--write`.

The input export and profiles must be root-owned mode `0600`, identify the source as `OPEN5GS/open5gs/subscribers`, and contain the selected Open5GS records in a `subscribers` array. Produce the export independently from the live database immediately before validation; a prepared file is not database proof. Synthetic fixtures are under `tests/fixtures/provisioning/` and require `--offline-fixture`, which cannot be combined with `--write`.

Dry-run the initial three-total-UE selection:

```bash
sudo target/release/polaris-provisioning-attest \
  --open5gs-records /root/.hermes/cache/scratch/open5gs-selected-ue01-03.json \
  --count 3
```

After independent review, explicitly generate the mode-`0600` root-controlled attestation:

```bash
sudo target/release/polaris-provisioning-attest \
  --open5gs-records /root/.hermes/cache/scratch/open5gs-selected-ue01-03.json \
  --count 3 \
  --write
```

Securely remove the secret-bearing export after verification. The resulting attestation is a trust input derived from independently queried records, not ongoing proof of database state.

Build with the commands in `README.md`. Create the untracked mode-0600 runtime environment from the example and provision named Operator/Administrator accounts with `polaris-userctl`.

The binary refuses a non-`127.0.0.1` bind. The public-IP HTTP proxy strips cookies and remains Viewer-only. Use `https://polaris.etv-sadok.duckdns.org/` for privileged sessions.

A root administrator provisions an Operator without placing the password in a command argument or Git:

```bash
sudo POLARIS_USERS_PATH=/var/lib/polaris-control/users.json \
  /root/POLARIS_CONTROL/target/release/polaris-userctl provision \
  --username operator --role operator
```

Enter the username/password on Settings. The browser never stores the password; it receives an HttpOnly session cookie and keeps only the CSRF token in session storage. See `P0_OPERATOR_PROVISIONING.md` for the bootstrap-file option.

Rollback affects only the POLARIS Control binary and Web distribution; this release creates no live simulator jobs.
