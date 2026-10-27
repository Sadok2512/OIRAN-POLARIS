# S5.2 Procedure Reconstruction

The session engine now attaches NAS events only through the exact `parent_event_id` chain. It separates repeated attempts: a synchronization failure closes one Authentication attempt, and the following Request starts a new attempt. Requests alone remain `INCOMPLETE`.

Across all 13 corpus files (including intentionally overlapping reference captures):

- Authentication: 16 attempts — 10 success, 6 failure.
- Registration: 12 attempts — 2 explicit reject/failure, 10 incomplete because their completion is ciphered.
- Security Mode: 10 incomplete — Commands are observed, Completes are ciphered.
- NGAP PDU resource setup: 9 successful procedure groups.
- NAS-proven PDU Session Establishment: 0.
- NAS-proven PDU Session Release: 0.

Each procedure records start/end IDs, duration, terminal result, numeric failure cause when present, missing evidence and evidence class. A Request never establishes success by itself.
