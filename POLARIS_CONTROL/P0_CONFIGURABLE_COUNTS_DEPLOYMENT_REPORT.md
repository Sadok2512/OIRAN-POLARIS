# P0 Configurable Counts Deployment Report

## Deployment result

POLARIS Control 3.1.1 was deployed on 2026-10-25 at 23:26:24 UTC. Only `polaris-control.service` was restarted. The service is healthy on its existing localhost listener and remains available through the existing HTTPS endpoint.

- Source commit: `c0c85d14743a94ced03230178e6d9c7b541a059f`
- Running API SHA256: `fd46d08b81a4295a648a3b383451a0ab739f4fd3436fecba105358b9db2e51d1`
- Frontend index SHA256: `c5bf61d2ed3842bcba30fe794443a159aba2d53a4a3edfd29267ac7e2e581ba6`
- API: 0.7.1
- Platform: 3.1.1
- Multi-UE controller: 0.2.1
- Production URL: `https://polaris.etv-sadok.duckdns.org/`

## Production verification

- Service: active; restart count 0 after deployment.
- Operator login: PASS.
- Viewer configuration mutation: rejected with HTTP 403.
- Operator configuration persistence: PASS using the unchanged 1 UE / 1 gNB desired state.
- Registry permissions: mode 0600.
- Configuration response: `execution_started=false`.
- Configured / running / registered / PDU-active UE counts: 1 / 1 / 1 / 1.
- Maximum configurable: 5 UE profiles and 2 gNB profiles.
- Maximum live-certified: 1 UE and 1 gNB.
- UE-02 through UE-05: `PROVISIONING_REQUIRED` and not configured by default.

No new UE or gNB was started. Shared gNB PID 2773390 and shared UE PID 2833882 remained unchanged. No subscriber was provisioned.

## Browser validation

The deployed HTTPS application passed an authenticated Operator browser smoke test at 1440×900 and 1920×1080 in Light and Dark modes. The test verified enabled selectors, backend-provided maximum values, the Add UE configuration action, actual shared UE state, and absence of horizontal overflow.

Screenshots are stored in `screenshots/p0_configurable_counts/`.

## Resource safety

- Disk utilization after deployment: 50%.
- Free disk: approximately 196 GiB.
- Inode utilization: 2%.
- Service memory at verification: approximately 21 MiB.
- Existing disk, CPU, RAM, and process-ownership lifecycle gates remain unchanged.
