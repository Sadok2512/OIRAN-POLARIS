// 0.1.1 — End-to-end transport test: real mTLS handshake + real
// Unix-socket capture-helper IPC.
//
// Why this test exists: the mTLS and capture-helper transports are
// the two external surfaces of the agent. The MVP in 0.1.0 only
// unit-tested the pure state machine; 0.1.1 adds the wire-level code,
// and this spec is the "both actually talk to real sockets" proof we
// hand to the deployment team.
//
// What's exercised:
//   1. A self-signed CA signs a server cert and a client cert via
//      `rcgen`. The agent never trusts the system root store — the
//      CA PEM is pinned.
//   2. axum-server serves a tiny `POST /agents/heartbeat` route with
//      rustls configured to REQUIRE a client certificate. Any
//      handshake without the pinned client cert fails at the TLS
//      layer, never reaching the handler.
//   3. The agent builds `MtlsTransport` with the (CA + client cert +
//      key) bundle, POSTs a `Heartbeat`, and the server records it.
//   4. A tokio UnixListener in the test plays the capture-helper.
//      The agent's `CaptureHelperClient` dials in, issues
//      `StartCapture`, and the mock responds with a `Starting` state.
//
// This is NOT a load / soak test — it exercises exactly one
// heartbeat and one capture start so the suite stays fast (sub-5-s).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;

use capture_helper::{
    CaptureSpec, HelperJob, HelperMetrics, HelperState, InterfaceId, IpcRequest,
    IpcResponse, PROTOCOL_VERSION,
};
use probe_agent::transport::{CaptureHelperClient, MtlsTransport, MtlsTransportSettings};
use probe_agent::{Heartbeat, InterfaceRole, InterfaceStats, VERSION};

/// Materials used by both the test server and the test client. Keep
/// them in one place so a cert mismatch between sides fails loud.
struct Pki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

fn generate_pki() -> Pki {
    // CA
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String("probe-agent-test-ca".into()));
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    // Server cert — valid for 127.0.0.1 (the test binds there).
    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String("probe-manager-test".into()));
    server_params.subject_alt_names = vec![
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();
    let server_cert_pem = server_cert.pem();
    let server_key_pem = server_key.serialize_pem();

    // Client cert — the agent presents this during the mTLS handshake.
    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.distinguished_name = DistinguishedName::new();
    client_params
        .distinguished_name
        .push(DnType::CommonName, DnValue::Utf8String("probe-ab12cd34".into()));
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();
    let client_cert_pem = client_cert.pem();
    let client_key_pem = client_key.serialize_pem();

    Pki {
        ca_pem,
        server_cert_pem,
        server_key_pem,
        client_cert_pem,
        client_key_pem,
    }
}

/// Simple shared counter so the test can assert the server actually
/// received the heartbeat (not just that the TLS handshake happened).
#[derive(Clone)]
struct ServerState {
    heartbeat_hits: Arc<AtomicUsize>,
}

async fn heartbeat_handler(
    State(state): State<ServerState>,
    Json(_body): Json<Heartbeat>,
) -> axum::http::StatusCode {
    state.heartbeat_hits.fetch_add(1, Ordering::SeqCst);
    axum::http::StatusCode::OK
}

fn build_rustls_config_requiring_client_auth(pki: &Pki) -> RustlsConfig {
    // Install the default rustls crypto provider once per test process.
    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::ring::default_provider(),
    );
    let ca_der =
        rustls_pemfile::certs(&mut pki.ca_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .expect("client verifier");

    let server_cert = rustls_pemfile::certs(&mut pki.server_cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let server_key = rustls_pemfile::private_key(&mut pki.server_key_pem.as_bytes())
        .unwrap()
        .unwrap();

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![server_cert], server_key)
        .expect("server rustls config");
    RustlsConfig::from_config(Arc::new(config))
}

async fn spawn_mock_helper(socket_path: std::path::PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = UnixListener::bind(&socket_path).expect("bind helper");
        let (mut stream, _) = listener.accept().await.expect("accept helper");
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await;
        let request: IpcRequest = serde_json::from_slice(&buf).expect("decode request");
        let capture_id = match request {
            IpcRequest::StartCapture(spec) => spec.capture_id,
            _ => "unexpected".into(),
        };
        let response = IpcResponse {
            protocol_version: PROTOCOL_VERSION.into(),
            ok: true,
            job: Some(HelperJob {
                capture_id,
                interfaces: vec![InterfaceId::N2],
                state: HelperState::Starting,
                owner_uid: nix_getuid(),
                created_epoch_ms: 0,
                started_epoch_ms: None,
                ended_epoch_ms: None,
                metrics: HelperMetrics::default(),
                failure: None,
                manifest_path: None,
            }),
            error: None,
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        stream.write_all(&bytes).await.expect("write response");
        stream.shutdown().await.expect("shutdown");
    })
}

fn nix_getuid() -> u32 {
    // Keep the test free of a libc dep — SAFETY: getuid is always safe to call.
    unsafe { libc_getuid() }
}

extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_speaks_mtls_to_probe_manager_and_ipc_to_capture_helper() {
    let pki = generate_pki();
    let state = ServerState {
        heartbeat_hits: Arc::new(AtomicUsize::new(0)),
    };

    // ---- HTTPS server (mTLS required) -----------------------------
    let app = Router::new()
        .route("/agents/heartbeat", post(heartbeat_handler))
        .with_state(state.clone());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("tcp bind");
    let addr: SocketAddr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = build_rustls_config_requiring_client_auth(&pki);
    let server = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, config)
            .serve(app.into_make_service())
            .await
            .expect("server");
    });
    // Give the TLS listener a tick to settle before the first dial.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ---- Mock capture-helper over a Unix socket --------------------
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("capture-helper.sock");
    let helper = spawn_mock_helper(socket_path.clone()).await;

    // ---- Build the agent's two transports --------------------------
    let settings = MtlsTransportSettings::with_defaults(
        format!("https://{addr}"),
        pki.ca_pem.into_bytes(),
        pki.client_cert_pem.into_bytes(),
        pki.client_key_pem.into_bytes(),
    );
    let mtls = MtlsTransport::new(settings).expect("transport build");
    let hb = Heartbeat {
        probe_id: "probe-ab12cd34".into(),
        agent_version: VERSION.into(),
        observed_at_epoch_s: 1_700_000_000,
        interfaces: vec![InterfaceStats {
            name: "ens3".into(),
            role: InterfaceRole::N2,
            packets_per_second: 420,
            drops_since_start: 0,
            disk_usage_percent: Some(12),
        }],
        cpu_usage_percent: Some(7),
    };
    mtls.post_heartbeat(&hb)
        .await
        .expect("heartbeat round-trip over mtls");
    assert_eq!(state.heartbeat_hits.load(Ordering::SeqCst), 1);

    // ---- Capture-helper IPC ----------------------------------------
    let helper_client = CaptureHelperClient::new(&socket_path);
    let spec = CaptureSpec {
        capture_id: "cap-e2e-01".into(),
        interfaces: vec![InterfaceId::N2],
        duration_seconds: 5,
        max_bytes: 1_000_000,
        rotation_files: 1,
    };
    let response = helper_client
        .start_capture(&spec)
        .await
        .expect("start capture via helper");
    assert!(response.ok);
    let job = response.job.expect("helper returned a job");
    assert_eq!(job.capture_id, "cap-e2e-01");
    assert_eq!(job.state, HelperState::Starting);

    // Shutdown — don't let the server task leak between integration tests.
    helper.await.expect("mock helper task");
    server.abort();
}
