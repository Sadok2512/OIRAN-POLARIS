# S3.2.1 independent field parity

## Method

TShark 4.2.2 in the existing healthy capture container was used read-only. Records were aligned by immutable capture SHA-256 plus packet number, not by aggregate count or timestamp proximity. Values were normalized as unsigned integers, canonical IP text, lowercase hexadecimal, and numeric enumeration values before comparison.

The metric is deliberately conservative: only fields for which both decoders exposed an unambiguous scalar value were counted. Protected or structurally unresolved values are listed separately and are **not** counted as matches.

## Results

| Metric | Count |
|---|---:|
| MESSAGE_EXACT | 99 |
| MESSAGE_MISSING | 0 |
| MESSAGE_EXTRA | 0 |
| FIELDS_COMPARABLE | 581 |
| FIELDS_MATCHED | 581 |
| FIELDS_MISMATCHED | 0 |
| FIELDS_UNRESOLVED | 34 |
| UNSUPPORTED_IE observed | 0 |

The 581 comparisons include packet-aligned type, exact timestamp and endpoints for 99 events, NGAP procedure and selected UE/location/session/security fields, PFCP sequence and selected session/rule/tunnel fields, and ten GTP-U TEIDs. Detailed accounting is in [S3_2_1_FIELD_PARITY.csv](S3_2_1_FIELD_PARITY.csv).

Zero mismatch does not mean full protocol parity. Twenty-one protected NAS payloads, five nested resource-transfer bodies, four bitrate scalars and four complex list/node values remain unresolved. Each points to the packet and a raw payload/IE hash.

## Reproduction

```bash
cargo build --workspace --release
cargo test --workspace --no-fail-fast
docker exec oiran-lab-capture-1 tshark -v
# Apply tshark -T fields to the immutable captures listed in the dataset report.
jq -s 'group_by(.protocol)|map({protocol:.[0].protocol,count:length})' \
  S3_2_1_NORMALIZED_EVENTS.jsonl
```

The Docker invocation reads captures and decoder metadata only; it does not alter the lab.
