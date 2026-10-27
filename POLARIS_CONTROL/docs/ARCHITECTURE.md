# Architecture

The browser and API share one loopback origin. The React application contains presentation and validation feedback only. Rust crates own scenario validation, resource safety, lifecycle ownership, and the UERANSIM adapter boundary.

`simulator-controller` accepts only scenario objects; `job-registry` binds exact handles to one controller owner. The current live adapter is deliberately closed. The disk guard measures the affected filesystem before writes and reserves headroom to the 85% stop threshold. Measurement failure rejects writes.

OIRAN integration uses a versioned manifest contract only. POLARIS Control never writes OIRAN databases or fabricates decoded events.
