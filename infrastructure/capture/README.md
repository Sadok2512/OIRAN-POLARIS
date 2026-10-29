# Capture rotation evidence

This staged replacement preserves the approved interface/filter allowlist and adds one JSONL
record per capture worker rotation. It is not active until a reviewed deployment replaces the
lab-mounted scripts.

Default evidence path: `/results/capture-rotation.jsonl`. Each record contains the UTC timestamp,
interface, plane, capture-process exit code, captured packet count and kernel/dumpcap drop count.
