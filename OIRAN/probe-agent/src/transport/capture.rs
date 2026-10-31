// 0.1.1 — Client-side driver for the local `oiran-capture-helper` daemon.
//
// Wire protocol: one JSON request → one JSON response, no framing (the
// helper reads up to `MAX_IPC_BYTES` then dispatches), both ends close
// the socket after each round-trip. This matches the server-side
// implementation in `capture-helper/src/lib.rs` and keeps the agent
// side a thin tokio-io wrapper over `UnixStream`.
//
// Trust boundary: the helper enforces owner-UID gating on the socket
// via SO_PEERCRED. If this agent runs as a different UID the connect
// will succeed but the first command returns `UID_FORBIDDEN`. We do
// not retry on that — it is a configuration mistake, not a transient.

use std::path::{Path, PathBuf};
use std::time::Duration;

use capture_helper::{CaptureSpec, IpcRequest, IpcResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Stable error vocabulary. All failures are terminal from the
/// agent's point of view: the helper owns the capture state machine
/// and this client just forwards.
#[derive(Debug)]
pub enum CaptureHelperError {
    SocketConnectFailed,
    RequestEncodeFailed,
    RequestWriteFailed,
    ResponseReadFailed,
    ResponseDecodeFailed,
    ResponseTooLarge,
    HelperError {
        category: String,
        details: String,
    },
    Timeout,
}

impl std::fmt::Display for CaptureHelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketConnectFailed => f.write_str("CAPTURE_SOCKET_CONNECT_FAILED"),
            Self::RequestEncodeFailed => f.write_str("CAPTURE_REQUEST_ENCODE_FAILED"),
            Self::RequestWriteFailed => f.write_str("CAPTURE_REQUEST_WRITE_FAILED"),
            Self::ResponseReadFailed => f.write_str("CAPTURE_RESPONSE_READ_FAILED"),
            Self::ResponseDecodeFailed => f.write_str("CAPTURE_RESPONSE_DECODE_FAILED"),
            Self::ResponseTooLarge => f.write_str("CAPTURE_RESPONSE_TOO_LARGE"),
            Self::HelperError { category, .. } => write!(f, "CAPTURE_HELPER_{category}"),
            Self::Timeout => f.write_str("CAPTURE_SOCKET_TIMEOUT"),
        }
    }
}

impl std::error::Error for CaptureHelperError {}

/// IPC client for the capture-helper daemon. Clone-cheap (holds only
/// the socket path + timeout). Each method opens a fresh connection;
/// the helper does not keep per-client state.
#[derive(Clone, Debug)]
pub struct CaptureHelperClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl CaptureHelperClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Fire a request + read the response. Blocking is bounded by
    /// `timeout`; the helper has its own internal limits for the
    /// capture lifecycle. Any helper-side error surfaces as
    /// `HelperError{category, details}` with the exact fields the
    /// capture-helper returned.
    pub async fn send(&self, request: &IpcRequest) -> Result<IpcResponse, CaptureHelperError> {
        let bytes = serde_json::to_vec(request).map_err(|_| CaptureHelperError::RequestEncodeFailed)?;
        let fut = async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|_| CaptureHelperError::SocketConnectFailed)?;
            stream
                .write_all(&bytes)
                .await
                .map_err(|_| CaptureHelperError::RequestWriteFailed)?;
            stream
                .shutdown()
                .await
                .map_err(|_| CaptureHelperError::RequestWriteFailed)?;
            let mut buf = Vec::with_capacity(4096);
            stream
                .take(MAX_RESPONSE_BYTES as u64 + 1)
                .read_to_end(&mut buf)
                .await
                .map_err(|_| CaptureHelperError::ResponseReadFailed)?;
            if buf.len() > MAX_RESPONSE_BYTES {
                return Err(CaptureHelperError::ResponseTooLarge);
            }
            let response: IpcResponse = serde_json::from_slice(&buf)
                .map_err(|_| CaptureHelperError::ResponseDecodeFailed)?;
            if !response.ok {
                let err = response.error.clone().unwrap_or_else(|| {
                    capture_helper::HelperFailure {
                        category: "UNKNOWN".into(),
                        details: String::new(),
                        exit_code: None,
                        termination_signal: None,
                    }
                });
                return Err(CaptureHelperError::HelperError {
                    category: err.category,
                    details: err.details,
                });
            }
            Ok(response)
        };
        timeout(self.timeout, fut)
            .await
            .map_err(|_| CaptureHelperError::Timeout)?
    }

    pub async fn validate_capture(
        &self,
        spec: &CaptureSpec,
    ) -> Result<IpcResponse, CaptureHelperError> {
        self.send(&IpcRequest::ValidateCapture(spec.clone())).await
    }

    pub async fn start_capture(
        &self,
        spec: &CaptureSpec,
    ) -> Result<IpcResponse, CaptureHelperError> {
        self.send(&IpcRequest::StartCapture(spec.clone())).await
    }

    pub async fn stop_capture(
        &self,
        capture_id: &str,
    ) -> Result<IpcResponse, CaptureHelperError> {
        self.send(&IpcRequest::StopCapture {
            capture_id: capture_id.to_string(),
        })
        .await
    }

    pub async fn get_status(
        &self,
        capture_id: &str,
    ) -> Result<IpcResponse, CaptureHelperError> {
        self.send(&IpcRequest::GetCaptureStatus {
            capture_id: capture_id.to_string(),
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    async fn mock_helper(socket_path: PathBuf, canned: IpcResponse) {
        let listener = UnixListener::bind(&socket_path).expect("bind");
        let (mut stream, _) = listener.accept().await.expect("accept");
        // Drain the client's request so the socket closes cleanly.
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await;
        let bytes = serde_json::to_vec(&canned).unwrap();
        stream.write_all(&bytes).await.expect("write");
        stream.shutdown().await.expect("shutdown");
    }

    fn ok_response() -> IpcResponse {
        let job = capture_helper::HelperJob {
            capture_id: "cap-abc".into(),
            interfaces: vec![capture_helper::InterfaceId::N2],
            state: capture_helper::HelperState::Starting,
            owner_uid: 0,
            created_epoch_ms: 0,
            started_epoch_ms: None,
            ended_epoch_ms: None,
            metrics: capture_helper::HelperMetrics::default(),
            failure: None,
            manifest_path: None,
        };
        IpcResponse {
            protocol_version: capture_helper::PROTOCOL_VERSION.into(),
            ok: true,
            job: Some(job),
            error: None,
        }
    }

    #[tokio::test]
    async fn client_round_trips_a_start_capture_against_a_mock_helper() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("helper.sock");
        let server = tokio::spawn(mock_helper(sock.clone(), ok_response()));
        // Give the listener a tick to bind before the client dials.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = CaptureHelperClient::new(&sock);
        let spec = CaptureSpec {
            capture_id: "cap-abc".into(),
            interfaces: vec![capture_helper::InterfaceId::N2],
            duration_seconds: 5,
            max_bytes: 1_000_000,
            rotation_files: 1,
        };
        let response = client.start_capture(&spec).await.expect("start");
        assert!(response.ok);
        assert_eq!(
            response.job.as_ref().unwrap().state,
            capture_helper::HelperState::Starting,
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn client_surfaces_helper_errors_as_helper_error_with_category() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("helper.sock");
        let error_body = IpcResponse {
            protocol_version: capture_helper::PROTOCOL_VERSION.into(),
            ok: false,
            job: None,
            error: Some(capture_helper::HelperFailure {
                category: "UID_FORBIDDEN".into(),
                details: "peer uid 1000 not allowed".into(),
                exit_code: None,
                termination_signal: None,
            }),
        };
        let server = tokio::spawn(mock_helper(sock.clone(), error_body));
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = CaptureHelperClient::new(&sock);
        let err = client.stop_capture("cap-missing").await.unwrap_err();
        match err {
            CaptureHelperError::HelperError { category, .. } => {
                assert_eq!(category, "UID_FORBIDDEN");
            }
            other => panic!("expected HelperError, got {other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn client_fails_fast_when_the_socket_does_not_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.sock");
        let client = CaptureHelperClient::new(&missing);
        let err = client.get_status("cap-x").await.unwrap_err();
        assert!(matches!(err, CaptureHelperError::SocketConnectFailed));
        assert_eq!(err.to_string(), "CAPTURE_SOCKET_CONNECT_FAILED");
    }
}
