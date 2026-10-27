# Operator Provisioning and Login

## Provisioning

Run as an authorized VPS administrator. The interactive form does not expose the password in process arguments or shell history:

```bash
sudo POLARIS_USERS_PATH=/var/lib/polaris-control/users.json \
  /root/POLARIS_CONTROL/target/release/polaris-userctl provision \
  --username operator --role operator
```

Use `--role administrator` only for a user who must manage the certified-scenario policy. Re-running the command for a username safely replaces that user's password hash. The database must remain owned by root and mode `0600`.

For non-interactive secret-management automation, send the password on standard input with `--password-stdin`; never put it in a command argument.

For a bootstrap account, an administrator can ask the CLI to generate a random initial password and write it once to a root-only file:

```bash
sudo POLARIS_USERS_PATH=/var/lib/polaris-control/users.json \
  /root/POLARIS_CONTROL/target/release/polaris-userctl provision \
  --username operator --role operator \
  --generated-password-file /root/POLARIS_CONTROL/config/operator-initial-password
sudo cat /root/POLARIS_CONTROL/config/operator-initial-password
```

The output file is created with mode `0600` and refuses to overwrite an existing file. Transfer it through an authorized channel, provision a replacement password with the interactive command, then remove the bootstrap file only with explicit administrator approval.

## Exact browser procedure

1. Open `https://polaris.etv-sadok.duckdns.org/`.
2. Select **Sign in as Operator** or open **Settings**.
3. Enter the provisioned username and password and select **Sign in securely**.
4. Return to **Dashboard**.
5. Select **Validate configuration**.
6. Confirm the state is **Ready to Start**.
7. Select **Start Scenario** only when the bounded test is intended.
8. Use **Stop Scenario** for the exact controller-owned active job.
9. Return to **Settings** and select **Sign out** when finished.

Public HTTP remains Viewer-only. New UE creation, multi-UE execution, gNB lifecycle, arbitrary destinations and unrestricted commands remain locked.
