# V3.1 Running Binary Verification

- Service: `polaris-control.service`
- Description: `POLARIS Control V3.1 multi-UE controller`
- ExecStart: `/root/POLARIS_CONTROL/target/release/polaris-control-api`
- PID: `3349866`
- Active since: `2026-10-25 23:09:38 UTC`
- Running executable SHA256: `c685ea3220f3fdf08beae9da4e47981e2ad63efdcafb5a298ea7deb859edaa70`
- Reviewed source commit: `09e43ff26e1577907318e752acc7d62cd53f9e87`
- API response: platform `3.1.0`, API `0.7.0`, controller `0.2.0`, adapter `0.2.0`
- Listener: `127.0.0.1:49153`; HTTPS is terminated by the existing gateway.

The loaded hash matches the Release artifact built from the reviewed source. No candidate listeners remain on ports 49155 or 5175.

