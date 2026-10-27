# POLARIS Control V3.1 Deployment Report

Deployment completed at 2026-10-25T23:09:38Z from reviewed source commit `09e43ff26e1577907318e752acc7d62cd53f9e87`.

## Outcome

- `polaris-control.service` alone was restarted; its production PID is `3349866`.
- API `0.7.0`, platform `3.1.0`, multi-UE controller `0.2.0` and UERANSIM adapter `0.2.0` are active.
- The HTTPS application and local API both return healthy responses.
- Five UE profiles and a two-gNB architecture capacity are exposed, while live certification remains one UE and one gNB.
- UE-02 through UE-05 remain `PROVISIONING_REQUIRED`; GNB-02 remains `NOT_DEPLOYED` and `LIVE_005_APPROVAL_REQUIRED`.
- The shared UE remains registered with one active PDU Session. The shared gNB and Open5GS PIDs did not change.
- No subscriber, UE, gNB, traffic job or simulator configuration was created during deployment.

The previous application was backed up privately at `deployment/backups/20261025T2307Z_pre_v3_1`. Sensitive backup files are mode `0600` and excluded from Git.

## Deployment evidence

- Previous API SHA256: `c5a420ed6407b41c1921cb3cddae3dc705b03137adb2b666c49c7884b74e1be8`
- Deployed API SHA256: `c685ea3220f3fdf08beae9da4e47981e2ad63efdcafb5a298ea7deb859edaa70`
- Frontend aggregate SHA256: `c47cc71d4991f8a34df58b955a3616634ec436847291b4b65cfa73543397e7c0`
- Production index SHA256: `a86a6a3099213f7c41d34a33c4343c5f319a93419c50fed0a517743158efa3d2`
- Production URL: `https://polaris.etv-sadok.duckdns.org/`

