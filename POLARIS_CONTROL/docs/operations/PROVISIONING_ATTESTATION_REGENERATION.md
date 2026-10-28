# Provisioning attestation regeneration

This procedure refreshes POLARIS evidence after an existing Open5GS subscriber slot is bound to
a UE profile. It never writes Open5GS. Its only authoritative input is a separately generated,
root-owned mode-`0600` read-only export whose provenance identifies
`OPEN5GS/open5gs/subscribers`.

1. Bind the slot through the Operator profile API. Confirm the profile remains
   `PROVISIONING_REQUIRED`.
2. Produce the restricted Open5GS export using the existing administrative read-only procedure.
3. Run the repository script without `POLARIS_ATTESTATION_WRITE`. This checks the configured
   profile registry, protected generated UERANSIM profile, exact SUPI/K/OPc/AMF/network values,
   and authoritative subscriber record. It emits identifiers and hashes, never secrets.
4. Review the dry-run result. Then run the same command with
   `POLARIS_ATTESTATION_WRITE=1`; the CLI atomically replaces only the private attestation file.
5. Re-run `validate-provisioning`. `VERIFIED` is valid only if the generated profile hash and
   authoritative-record hash still match.

```bash
sudo /opt/polaris-control/tools/regenerate-polaris-provisioning-attestation.sh \
  /run/polaris-control/open5gs-read-only-export.json 1

sudo POLARIS_ATTESTATION_WRITE=1 \
  /opt/polaris-control/tools/regenerate-polaris-provisioning-attestation.sh \
  /run/polaris-control/open5gs-read-only-export.json 1
```

The numeric argument is the exact configured-profile count to attest. A count mismatch fails
closed. Delete the secret-bearing export through the existing secure administrative process after
verification; do not add it to Git or application logs.
