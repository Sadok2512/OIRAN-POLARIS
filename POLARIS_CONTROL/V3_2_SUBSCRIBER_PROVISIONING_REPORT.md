# POLARIS Control V3.2 Subscriber Provisioning Report

## Result

The Open5GS 2.8.0 laboratory now contains exactly ten compatible synthetic 5G subscriber records. One pre-existing record was retained unchanged and nine missing records were inserted.

All ten records have unique subscriber identities, unique authentication keys, and unique OPc values. Every record uses schema version 1, AMF `8000`, PLMN `001/01`, DNN `internet`, and S-NSSAI SST `1` / SD `010203`.

No subscriber identity or authentication material is present in this report.

## Controlled procedure

1. Confirmed MongoDB, AMF, SMF, UPF, gNB, and UE health.
2. Verified the existing one-record inventory and schema without exposing secrets.
3. Created a protected compressed MongoDB backup and validated it with `mongorestore --dryRun`.
4. Generated nine independent authentication tuples from the operating system cryptographic random source via OpenSSL.
5. Verified every existing target record before insertion.
6. Inserted only missing records; the procedure contains compensating rollback for partial insertion failure.
7. Re-ran the procedure idempotently: zero records were created on the second successful run.
8. Validated ten unique, compatible records and ten restricted UERANSIM profiles.

The initial provisioning database operation completed successfully, but its wrapper rejected interactive `mongosh` prompt text while parsing the sanitized result. The invocation was corrected to `--file /dev/stdin`; the idempotent rerun reported 10 existing, 0 created, 10 compatible, and 0 duplicates. No database rollback was needed.

## Process protection

The shared gNB PID remained 2773390 and the shared UE PID remained 2833882. No UE or gNB process was created, stopped, or restarted. Open5GS was not restarted.
