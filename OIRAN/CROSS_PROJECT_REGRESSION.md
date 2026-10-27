# Cross-project Regression

| Candidate | Suite | Result |
|---|---:|---:|
| OIRAN | Rust workspace | 196/196 PASS |
| OIRAN | API subset | 21/21 PASS |
| OIRAN | Frontend unit | 20/20 PASS |
| OIRAN | TypeScript / production build | PASS / PASS |
| OIRAN | Browser E2E | 47/47 PASS, 0 skipped |
| POLARIS | Rust workspace | 88/88 PASS |
| POLARIS | API subset | 54/54 PASS |
| POLARIS | Frontend unit | 5/5 PASS |
| POLARIS | TypeScript / production build | PASS / PASS |
| POLARIS | Browser E2E | 20/20 PASS, 0 skipped |

The isolated candidates used copied registries and execution-disabled configuration. No Start Capture, Start UE, or Start Traffic operation was issued. OIRAN historical certified dataset digest remained `0b44367c3ccf483dbdf281191a854e83fd9ecd19cecfdcc679f5e6d5b00893ab` before and after testing.
