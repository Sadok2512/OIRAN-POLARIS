# LTE SGi overlay — integration request to Codex

**Mission** : `NS-20261102-CLAUDE-SGI-OVERLAY-INTEGRATION`
**BASE_SHA** : `f9e9eb78e03a406dba5cd12dbf386e5fdeef2e8a`
**Author of certified overlay** : Codex (`cert/anr3-polaris-0293-sgi-release-gate`, worktree `/root/ANR3_POLARIS_0293_SGI_GATE`)
**Reference report** : Issue #10 comment [6581518835](https://github.com/Sadok2512/OIRAN-POLARIS/issues/10#issuecomment-6581518835)

## Context

The 0.29.3 fix on `fix/polaris-lte-sgi-dedicated-dn @ f9e9eb78` ships a *candidate*
overlay (`deployment/dn-sender/lte-sgi/compose.yaml` + `polaris-control-lte-sgi.conf`
+ `README.md`) with:

- `SIDE_CAR_IMAGE_DIGEST` placeholder = `sha256:0000…0000`
- 4 required `Environment=…` lines commented out
- No Dockerfile, no route installer, no systemd unit, no packaging test

Codex has since built and certified the real overlay offline but the artefacts
remain **local to OIRAN** and are not reachable from `origin`.

BC3 cannot integrate what it cannot see. The mission is explicit: "ne pas
prétendre l'avoir intégré sans accès réel". This document is BC3's receiving
contract so Codex can push the overlay deterministically.

## Push target

Codex pushes to the following branch, based on `f9e9eb78`:

```
origin/cert/codex-sgi-overlay-0293-staging
```

The branch must contain **exactly** these new files, in these paths, and
nothing else outside this directory tree:

| Path | Expected SHA256 (from Codex Issue #10 report) |
| --- | --- |
| `POLARIS_CONTROL/deployment/dn-sender/lte-sgi/Dockerfile` | `41b26f9011aca1538105f0b5065f473eeb71703e9aa3cb9160acb1d9f103bb7e` |
| `POLARIS_CONTROL/deployment/dn-sender/lte-sgi/compose.yaml` (rewritten; must now carry the real digest and `interface_name: sgi_lte`) | `bdbc199360fc7c0f77e56839240ae13c785728cd4b1e9bbcb6fc60deb91b696a` |
| `POLARIS_CONTROL/deployment/dn-sender/lte-sgi/configure-route.sh` | `3c6e5795e771a73dcb765fcf6f7fa2479360fb2791a530f69063752b1e0b60` *(looks truncated to 60 hex chars in Codex's report — please re-publish the full 64-hex SHA256)* |
| `POLARIS_CONTROL/deployment/dn-sender/lte-sgi/polaris-control-lte-sgi.conf` (rewritten; four `Environment=` lines activated with the values below) | `9ce93ada70a4356d4a4b54ac292c663479a3b6ea3fdd9f5be8bf5a3a8510393d` |
| `POLARIS_CONTROL/deployment/dn-sender/lte-sgi/polaris-lte-sgi.service` (systemd unit) | `069814b68c47911b74fd5a65d5ce378a311ad035d10dfbed974e203d70551bdf` |

The compose must:

- Pin `image: polaris-lte-sgi-dn@sha256:e60eb72bf7619fd049f6bbbc45cf06927eb73ed7c613446678644f6742af31f3` (no `:tag` placeholder).
- Set `interface_name: sgi_lte` on the SGi network attachment.
- Keep `cap_drop: [ALL]`, `no-new-privileges:true`, `read_only: true`, non-root user, memory/CPU/pids limits.
- Expose nothing beyond `iperf3 -s`.

The drop-in must set exactly:

```ini
Environment=POLARIS_LTE_DN_SENDER_CONTAINER=polaris-lte-sgi-dn
Environment=POLARIS_LTE_TRAFFIC_PEER_IP=10.77.16.30
Environment=POLARIS_LTE_PGW_U_NEXT_HOP=10.77.16.15
Environment=POLARIS_LTE_UE_SUBNET=10.45.0.0/16
Environment=POLARIS_LTE_FORBIDDEN_RETURN_DEVS=lo,null0,blackhole,eth0,oiran-lab-n6
```

## Packaging test

Codex also pushes an updated `candidate_lte_sgi_sidecar_pins_image_digest_placeholder_and_hardens_pod`
test in `POLARIS_CONTROL/apps/api/src/srsran_controller.rs` that:

- **No longer** accepts the `0000…0000` placeholder.
- **Requires** the real digest `sha256:e60eb72bf7619fd049f6bbbc45cf06927eb73ed7c613446678644f6742af31f3` to be present in `compose.yaml`.
- Keeps all other hardening markers.

## What Codex must NOT include

- No raw PCAP, no subscriber data, no secret.
- No credentials, no registry token, no `.env` with cleartext.
- No deployment artefact outside `deployment/dn-sender/lte-sgi/`.
- No modification of `anr1/*`, `anr2/*`, `anr3/*` branches.
- No image tar (ship the digest only; the tar `d792d21af493f97da1e464ed98ec535305f45b2d07ff7290600ed247856ea8dd` stays off-tree).

## BC3 integration protocol (after Codex pushes)

Once `origin/cert/codex-sgi-overlay-0293-staging` exists:

1. BC3 fetches and verifies lineage: `git merge-base origin/cert/codex-sgi-overlay-0293-staging f9e9eb78` must equal `f9e9eb78`.
2. BC3 verifies file SHA256s against the table above (and asks for a re-publish if any entry fails).
3. BC3 verifies compose:
   - `grep -q 'image: polaris-lte-sgi-dn@sha256:e60eb72bf7619fd049f6bbbc45cf06927eb73ed7c613446678644f6742af31f3' compose.yaml`
   - `grep -q 'interface_name: sgi_lte' compose.yaml`
   - `docker compose -f compose.yaml config --quiet` (if docker is available on BC3 host; otherwise `python3 -c "import yaml; yaml.safe_load(open('compose.yaml'))"` as structural check)
4. BC3 verifies drop-in: four `Environment=` lines above present and uncommented.
5. BC3 runs `bash -n configure-route.sh` and `systemd-analyze verify --no-pager polaris-lte-sgi.service` (best effort — if systemd is not usable in BC3's sandbox, BC3 reports it transparently).
6. BC3 runs the Rust test suite on the branch (`cargo test -p polaris-control-api --lib srsran_controller::tests --release --locked`); must stay 33/33 PASS or Codex's new packaging assertion must still fail-closed on the placeholder (not pass-closed).
7. On success, BC3 cherry-picks or merges the overlay commit into
   `review/claude-sgi-overlay-integration` and publishes a report.

**No placeholder** survives into the integrated branch — if any file still
contains `PENDING` or `0000…`, BC3 refuses and reports.

## Garde-fous (BC3)

- No deployment, no grant, no UE, no live LTE/5G, no PCAP, no Open5GS/dumpcap change.
- No reservation of `10.77.16.30` on the SGi bridge.
- No execution of the installer or activation of the sidecar.
- No modification of `anr1/*|anr2/*|anr3/*` branches.
- No arbitrary rewrite of the image or invention of a digest.

— BC3
