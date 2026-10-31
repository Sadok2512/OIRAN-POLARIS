// 0.1.1 — transport layer.
//
// The agent reaches the Probe Manager over mutual TLS and the local
// capture-helper over an owner-UID-gated Unix socket. These are the
// two external surfaces the agent touches; both are isolated in this
// module so unit tests of the pure state machine (`validate_config`,
// `sha256_hex`, enrollment handshake) still run without a network
// stack or a running capture-helper.

pub mod capture;
pub mod mtls;

pub use capture::{CaptureHelperClient, CaptureHelperError};
pub use mtls::{MtlsTransport, MtlsTransportError, MtlsTransportSettings};
