// 0.1.1 — mutual-TLS HTTP transport to the Probe Manager.
//
// Carries the three agent-side calls defined in DESIGN.md:
//   * POST `/agents/enroll`              (one-shot token → signed cert)
//   * POST `/agents/heartbeat`           (10 s interval)
//   * POST `/agents/segments/:id`        (pcap segment upload, SHA-256-tagged)
//
// Enrollment runs **before** mTLS: the agent authenticates with a
// one-shot bootstrap token (header `x-probe-bootstrap-token`), POSTs
// its CSR, and receives the signed client certificate + CA bundle.
// Every subsequent call MUST present the client cert — enrollment is
// a prerequisite, not a shortcut.
//
// Pinned CA roots: the agent never trusts the system root store. The
// Probe Manager's CA PEM comes with the enrollment response and is
// used verbatim for every post-enrollment TLS handshake. Any cert
// outside that pin is rejected, including a different CA on the same
// hostname. This is the "exactly one upstream" rule from DESIGN.md.
//
// Error vocabulary is stable so the agent's heartbeat sink can log
// terminal states without string-matching reqwest's internals.

use std::sync::Arc;
use std::time::Duration;

use reqwest::{Certificate, Client, ClientBuilder, Identity, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{EnrollmentRequest, EnrollmentResponse, Heartbeat, SegmentUpload};

/// Stable error vocabulary for every mTLS transport failure.
#[derive(Debug)]
pub enum MtlsTransportError {
    CaInvalid,
    ClientCertInvalid,
    ClientKeyInvalid,
    ClientBuildFailed,
    RequestFailed,
    HttpStatus(StatusCode),
    ResponseDecodeFailed,
}

#[derive(Clone, Debug)]
pub struct MtlsTransportSettings {
    /// Fully-qualified HTTPS base URL of the Probe Manager mTLS
    /// endpoint (e.g. `https://probe-manager.lab:443`). Trailing slash
    /// is tolerated.
    pub base_url: String,
    /// PEM-encoded CA chain pinned by the agent.
    pub ca_pem: Vec<u8>,
    /// PEM-encoded client certificate chain (leaf first).
    pub client_cert_pem: Vec<u8>,
    /// PEM-encoded client private key, PKCS#8 or SEC1.
    pub client_key_pem: Vec<u8>,
    /// Per-request timeout (connect + response). Defaults to 10 s so
    /// an unresponsive Probe Manager cannot stall the agent heartbeat
    /// loop.
    pub timeout: Duration,
}

impl MtlsTransportSettings {
    pub fn with_defaults(
        base_url: impl Into<String>,
        ca_pem: Vec<u8>,
        client_cert_pem: Vec<u8>,
        client_key_pem: Vec<u8>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            ca_pem,
            client_cert_pem,
            client_key_pem,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Pre-built reqwest client wired for mTLS against the Probe Manager.
/// Clone-cheap (reqwest::Client is Arc-backed) so the agent can hand
/// it to the heartbeat / upload tasks without owning multiple TLS
/// contexts.
#[derive(Clone, Debug)]
pub struct MtlsTransport {
    client: Client,
    base_url: String,
}

impl MtlsTransport {
    /// Build the transport. The CA / cert / key are validated up front
    /// (bad PEM → error here, not on first request) so the agent fails
    /// its config check before any heartbeat tick.
    pub fn new(settings: MtlsTransportSettings) -> Result<Self, MtlsTransportError> {
        Self::ensure_crypto_provider();
        let ca = Certificate::from_pem(&settings.ca_pem)
            .map_err(|_| MtlsTransportError::CaInvalid)?;
        // Validate PEM shapes before handing to reqwest so the error
        // vocabulary distinguishes cert vs. key failures.
        parse_cert_chain(&settings.client_cert_pem)
            .map_err(|_| MtlsTransportError::ClientCertInvalid)?;
        parse_private_key(&settings.client_key_pem)
            .map_err(|_| MtlsTransportError::ClientKeyInvalid)?;
        let identity = Identity::from_pem(
            &[settings.client_cert_pem.as_slice(), b"\n", settings.client_key_pem.as_slice()]
                .concat(),
        )
        .map_err(|_| MtlsTransportError::ClientCertInvalid)?;
        let client = ClientBuilder::new()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .identity(identity)
            .timeout(settings.timeout)
            .build()
            .map_err(|_| MtlsTransportError::ClientBuildFailed)?;
        Ok(Self {
            client,
            base_url: settings.base_url.trim_end_matches('/').to_string(),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// POST a heartbeat snapshot. Any non-2xx is an `HttpStatus`
    /// error so the sink can decide between retry (transient) and
    /// terminal (401 / 403 — rotate the cert).
    pub async fn post_heartbeat(
        &self,
        heartbeat: &Heartbeat,
    ) -> Result<(), MtlsTransportError> {
        let response = self
            .client
            .post(format!("{}/agents/heartbeat", self.base_url))
            .json(heartbeat)
            .send()
            .await
            .map_err(|_| MtlsTransportError::RequestFailed)?;
        if !response.status().is_success() {
            return Err(MtlsTransportError::HttpStatus(response.status()));
        }
        Ok(())
    }

    /// POST a pcap segment. The agent sends the manifest (sha256,
    /// bytes, capture id) separately from the raw bytes so the Probe
    /// Manager can refuse (e.g. storage pressure) without buffering.
    pub async fn post_segment_manifest(
        &self,
        segment: &SegmentUpload,
    ) -> Result<(), MtlsTransportError> {
        let response = self
            .client
            .post(format!(
                "{}/agents/segments/{}",
                self.base_url,
                percent_encode_path(&segment.segment_id),
            ))
            .json(segment)
            .send()
            .await
            .map_err(|_| MtlsTransportError::RequestFailed)?;
        if !response.status().is_success() {
            return Err(MtlsTransportError::HttpStatus(response.status()));
        }
        Ok(())
    }

    /// Enrollment runs **before** mTLS: no client cert, just a
    /// one-shot bootstrap token. The response is signed cert + CA
    /// bundle, which the agent persists and feeds to a fresh
    /// `MtlsTransport::new()` on next startup.
    ///
    /// We expose this as a free function so a brand-new agent (no
    /// cert yet) can call it without constructing an `MtlsTransport`.
    pub async fn enroll(
        probe_manager_https_url: &str,
        bootstrap_token: &str,
        request: &EnrollmentRequest,
        ca_pem_pin: Option<&[u8]>,
    ) -> Result<EnrollmentResponse, MtlsTransportError> {
        Self::ensure_crypto_provider();
        let base = probe_manager_https_url.trim_end_matches('/').to_string();
        let mut builder = ClientBuilder::new()
            .use_rustls_tls()
            .timeout(Duration::from_secs(30));
        if let Some(ca_pem) = ca_pem_pin {
            let ca = Certificate::from_pem(ca_pem)
                .map_err(|_| MtlsTransportError::CaInvalid)?;
            builder = builder.tls_built_in_root_certs(false).add_root_certificate(ca);
        }
        let client = builder
            .build()
            .map_err(|_| MtlsTransportError::ClientBuildFailed)?;
        let response = client
            .post(format!("{base}/agents/enroll"))
            .header("x-probe-bootstrap-token", bootstrap_token)
            .json(request)
            .send()
            .await
            .map_err(|_| MtlsTransportError::RequestFailed)?;
        if !response.status().is_success() {
            return Err(MtlsTransportError::HttpStatus(response.status()));
        }
        response
            .json::<EnrollmentResponse>()
            .await
            .map_err(|_| MtlsTransportError::ResponseDecodeFailed)
    }

    /// rustls 0.23 requires an explicit crypto provider when the
    /// consumer picks a feature set that is not the default. The
    /// agent is pinned to the `ring` provider; this call is a no-op
    /// on re-install.
    fn ensure_crypto_provider() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::CryptoProvider::install_default(
                rustls::crypto::ring::default_provider(),
            );
        });
    }
}

/// Parse a PEM cert chain. Returns the DER bytes so the caller can
/// decide whether to feed them to rustls or just validate the shape.
fn parse_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, &'static str> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &pem[..])
        .filter_map(Result::ok)
        .collect();
    if certs.is_empty() {
        return Err("empty cert chain");
    }
    Ok(certs)
}

/// Parse a PEM private key. Accepts PKCS#8 and SEC1; the agent
/// generates PKCS#8 keys but the Probe Manager might rewrap on
/// renewal.
fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, &'static str> {
    let mut reader = &pem[..];
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| "parse failed")?
        .ok_or("no private key found")
}

/// RFC 3986 percent-encode a path segment. Keeps the surface tiny so
/// the agent does not pull `percent-encoding` for one call.
fn percent_encode_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

impl std::fmt::Display for MtlsTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CaInvalid => "TRANSPORT_CA_INVALID",
            Self::ClientCertInvalid => "TRANSPORT_CLIENT_CERT_INVALID",
            Self::ClientKeyInvalid => "TRANSPORT_CLIENT_KEY_INVALID",
            Self::ClientBuildFailed => "TRANSPORT_CLIENT_BUILD_FAILED",
            Self::RequestFailed => "TRANSPORT_REQUEST_FAILED",
            Self::HttpStatus(_) => "TRANSPORT_HTTP_STATUS",
            Self::ResponseDecodeFailed => "TRANSPORT_RESPONSE_DECODE_FAILED",
        })
    }
}

impl std::error::Error for MtlsTransportError {}

// Marker trait silencer — see `thiserror_lite` note above.
#[allow(dead_code)]
fn _assert_send_sync<T: Send + Sync>() {}
#[allow(dead_code)]
fn _assert_transport_is_send() {
    _assert_send_sync::<MtlsTransport>();
    _assert_send_sync::<Arc<MtlsTransport>>();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_timeout_is_ten_seconds() {
        let s = MtlsTransportSettings::with_defaults(
            "https://probe-manager.lab",
            b"ca".to_vec(),
            b"cert".to_vec(),
            b"key".to_vec(),
        );
        assert_eq!(s.timeout, Duration::from_secs(10));
    }

    #[test]
    fn mtls_transport_rejects_bogus_crypto_material_without_touching_the_network() {
        let s = MtlsTransportSettings::with_defaults(
            "https://probe-manager.lab",
            b"not pem".to_vec(),
            b"not pem".to_vec(),
            b"not pem".to_vec(),
        );
        let err = MtlsTransport::new(s).unwrap_err();
        // Any of the three "crypto material is wrong" codes is acceptable;
        // the invariant we care about is that NO network call ever leaves
        // the process when the PEM bundle is broken.
        assert!(
            matches!(
                err,
                MtlsTransportError::CaInvalid
                    | MtlsTransportError::ClientCertInvalid
                    | MtlsTransportError::ClientKeyInvalid
            ),
            "unexpected err: {err:?}",
        );
    }

    #[test]
    fn percent_encode_keeps_unreserved_characters() {
        assert_eq!(percent_encode_path("seg-abc_12.3"), "seg-abc_12.3");
    }

    #[test]
    fn percent_encode_escapes_reserved_characters() {
        assert_eq!(percent_encode_path("a b/c"), "a%20b%2Fc");
    }
}
