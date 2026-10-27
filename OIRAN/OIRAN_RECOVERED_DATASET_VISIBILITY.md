# OIRAN Recovered Dataset Visibility

The deployed API loads `recovered-dataset-live-1792964646320-0003` from the persistent recovery registry.

| Property | Verified value |
|---|---|
| API dataset count | 2 |
| Recovered packet accounting | 50 |
| Recovered normalized events | 20 PFCP heartbeat events |
| Recovered UE sessions | 0 |
| Dataset state | `COMPLETED` |
| Original capture state | `FAILED` |
| Original dataset ID | absent |

The web/API empty-session behavior is explicit: a headless-browser verification selected the recovered dataset in Session Explorer and observed `No sessions match these filters`. No UE session or Call Flow was fabricated.

The original capture manifest and PCAP checksums remain:

- Capture manifest: `c32d250f4e7def24fce7c219a34276aab7f56f8810617f42305b4d91213ebb07`
- N2: `135e3ce9fdd5a2a4c799314b345fce2670fd81c86606bd912f7894196ef3d265`
- N3: `acc530668c8bc60b2d229281130b1899bfc81d70fdada5c34b3236c628f739c8`
- N4: `b03dcda272c50f0917844ac7e7fd819bf73e5c1faf33f080a427abc7dd6daa6b`

