# S4.2 known limitations

- Five-UE POLARIS execution, new PCAPs, TShark parity and five independent real Call Flows are not available without approval.
- Current OIRAN has no authorized live capture writer; the disk guard is implemented and tested but capture controls remain disabled.
- The existing capture service was inspected only; its scripts/configuration were not modified to enforce S4.2 rotation.
- SBI capture is not included in the current certified dataset.
- Optional second PDU session and release/deregistration depend on demonstrated simulator support.
- Current disk state is INFORMATION (≥75%) and close enough to WARNING that an approved run must re-evaluate its entire reserved budget immediately before start.

Final S4.2 status is PARTIAL, awaiting explicit POLARIS live-test approval.
