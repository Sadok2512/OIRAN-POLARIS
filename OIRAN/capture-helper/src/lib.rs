//! Isolated, allowlisted packet-acquisition helper for OIRAN.
//!
//! The public API process talks to this component through a Unix socket. The
//! helper accepts no command line, path, interface or filter supplied by an
//! HTTP client. Production acquisition uses Linux AF_PACKET directly; tests
//! use an in-memory backend and never open a live interface.

use disk_safety::{capture_budget, measure_path, CaptureGuard, Policy};
use event_schema::sha256_hex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    mem,
    os::{
        fd::{AsRawFd, RawFd},
        unix::{
            fs::{FileTypeExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const VERSION: &str = "0.1.0-dev";
pub const PROTOCOL_VERSION: &str = "1.0";
pub const MAX_CAPTURE_PLANES: usize = 4;
const MAX_IPC_BYTES: u64 = 64 * 1024;
const PCAP_GLOBAL_HEADER_BYTES: u64 = 24;
const PCAP_RECORD_HEADER_BYTES: u64 = 16;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterfaceId {
    N2,
    N3,
    N4,
    Sbi,
}

impl InterfaceId {
    pub fn device(self) -> &'static str {
        match self {
            Self::N2 => "br-oiran-n2",
            Self::N3 => "br-oiran-n3",
            Self::N4 => "br-oiran-n4",
            Self::Sbi => "br-oiran-sbi",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::N2 => "N2",
            Self::N3 => "N3",
            Self::N4 => "N4",
            Self::Sbi => "SBI",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureSpec {
    pub capture_id: String,
    pub interfaces: Vec<InterfaceId>,
    pub duration_seconds: u64,
    pub max_bytes: u64,
    pub rotation_files: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "command",
    content = "payload",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum IpcRequest {
    ValidateCapture(CaptureSpec),
    StartCapture(CaptureSpec),
    StopCapture { capture_id: String },
    GetCaptureStatus { capture_id: String },
    GetCaptureMetrics { capture_id: String },
    ForgetCapture { capture_id: String },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HelperState {
    Created,
    Validating,
    Ready,
    Starting,
    Capturing,
    Stopping,
    Completed,
    CompletedEmpty,
    Failed,
}

impl HelperState {
    pub fn active(self) -> bool {
        matches!(self, Self::Starting | Self::Capturing | Self::Stopping)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct HelperMetrics {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub storage_bytes: u64,
    pub packet_drops: Option<u64>,
    pub duration_seconds: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HelperFailure {
    pub category: String,
    pub details: String,
    pub exit_code: Option<i32>,
    pub termination_signal: Option<i32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HelperJob {
    pub capture_id: String,
    pub interfaces: Vec<InterfaceId>,
    pub state: HelperState,
    pub owner_uid: u32,
    pub created_epoch_ms: u64,
    pub started_epoch_ms: Option<u64>,
    pub ended_epoch_ms: Option<u64>,
    pub metrics: HelperMetrics,
    pub failure: Option<HelperFailure>,
    pub manifest_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IpcResponse {
    pub protocol_version: String,
    pub ok: bool,
    pub job: Option<HelperJob>,
    pub error: Option<HelperFailure>,
}

impl IpcResponse {
    fn job(job: HelperJob) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.into(),
            ok: true,
            job: Some(job),
            error: None,
        }
    }

    fn error(category: &str, details: impl Into<String>) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.into(),
            ok: false,
            job: None,
            error: Some(HelperFailure {
                category: category.into(),
                details: sanitize(&details.into()),
                exit_code: None,
                termination_signal: None,
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub capture_root: PathBuf,
    pub interface_root: PathBuf,
    pub allowed_client_uid: u32,
    pub allowed_client_gid: Option<u32>,
    pub socket_gid: Option<u32>,
    pub policy: Policy,
}

pub trait CaptureBackend: Send + Sync + 'static {
    fn initialize(
        &self,
        interfaces: &[InterfaceId],
    ) -> Result<Box<dyn CaptureSession>, HelperFailure>;
}

pub trait CaptureSession: Send {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<CapturedPacket>, HelperFailure>;
    fn packet_drops(&mut self) -> Option<u64> {
        None
    }
}

#[derive(Clone, Debug)]
pub struct CapturedPacket {
    pub interface: InterfaceId,
    pub timestamp: SystemTime,
    pub original_length: u32,
    pub data: Vec<u8>,
}

pub struct CaptureService<B: CaptureBackend> {
    inner: Arc<ServiceInner<B>>,
}

impl<B: CaptureBackend> Clone for CaptureService<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct ServiceInner<B: CaptureBackend> {
    config: ServerConfig,
    backend: Arc<B>,
    jobs: Mutex<BTreeMap<String, HelperJob>>,
    stops: Mutex<BTreeMap<String, Arc<AtomicBool>>>,
}

impl<B: CaptureBackend> CaptureService<B> {
    pub fn new(config: ServerConfig, backend: B) -> Result<Self, String> {
        if !config.capture_root.is_absolute() || !config.interface_root.is_absolute() {
            return Err("capture and interface roots must be absolute".into());
        }
        fs::create_dir_all(&config.capture_root).map_err(io_error)?;
        let service = Self {
            inner: Arc::new(ServiceInner {
                config,
                backend: Arc::new(backend),
                jobs: Mutex::new(BTreeMap::new()),
                stops: Mutex::new(BTreeMap::new()),
            }),
        };
        service.recover_jobs()?;
        Ok(service)
    }

    pub fn bind(&self) -> Result<UnixListener, String> {
        if let Some(parent) = self.inner.config.socket_path.parent() {
            fs::create_dir_all(parent).map_err(io_error)?;
        }
        if self.inner.config.socket_path.exists() {
            let metadata =
                fs::symlink_metadata(&self.inner.config.socket_path).map_err(io_error)?;
            if !metadata.file_type().is_socket() {
                return Err("refusing to replace non-socket IPC path".into());
            }
            fs::remove_file(&self.inner.config.socket_path).map_err(io_error)?;
        }
        let listener = UnixListener::bind(&self.inner.config.socket_path).map_err(io_error)?;
        fs::set_permissions(
            &self.inner.config.socket_path,
            fs::Permissions::from_mode(0o660),
        )
        .map_err(io_error)?;
        if let Some(gid) = self.inner.config.socket_gid {
            let path = std::ffi::CString::new(
                self.inner.config.socket_path.as_os_str().as_encoded_bytes(),
            )
            .map_err(|_| "IPC path contains NUL")?;
            if unsafe { libc::chown(path.as_ptr(), u32::MAX, gid) } != 0 {
                return Err(format!(
                    "IPC socket group assignment: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(listener)
    }

    pub fn serve(&self, listener: UnixListener) -> Result<(), String> {
        for incoming in listener.incoming() {
            let stream = incoming.map_err(io_error)?;
            let service = self.clone();
            thread::spawn(move || {
                let _ = service.handle_stream(stream);
            });
        }
        Ok(())
    }

    pub fn handle_stream(&self, mut stream: UnixStream) -> Result<(), String> {
        let credentials = peer_credentials(&stream)?;
        let response = if !authorize_peer(
            credentials,
            self.inner.config.allowed_client_uid,
            self.inner.config.allowed_client_gid,
        ) {
            IpcResponse::error(
                "IPC_UNAUTHORIZED_PEER",
                "peer credentials are not authorized",
            )
        } else {
            let mut body = String::new();
            std::io::Read::by_ref(&mut stream)
                .take(MAX_IPC_BYTES)
                .read_to_string(&mut body)
                .map_err(io_error)?;
            match serde_json::from_str::<IpcRequest>(&body) {
                Ok(request) => self.handle(credentials, request),
                Err(_) => IpcResponse::error("IPC_INVALID_REQUEST", "invalid request schema"),
            }
        };
        serde_json::to_writer(&mut stream, &response).map_err(json_error)?;
        stream.write_all(b"\n").map_err(io_error)
    }

    pub fn handle(&self, peer: PeerCredentials, request: IpcRequest) -> IpcResponse {
        if !authorize_peer(
            peer,
            self.inner.config.allowed_client_uid,
            self.inner.config.allowed_client_gid,
        ) {
            return IpcResponse::error(
                "IPC_UNAUTHORIZED_PEER",
                "peer credentials are not authorized",
            );
        }
        match request {
            IpcRequest::ValidateCapture(spec) => match self.validate_spec(&spec) {
                Ok(()) => IpcResponse::job(new_job(&spec, peer.uid, HelperState::Ready)),
                Err(error) => IpcResponse::error(&error.category, error.details),
            },
            IpcRequest::StartCapture(spec) => self.start(peer.uid, spec),
            IpcRequest::StopCapture { capture_id } => self.stop(peer.uid, &capture_id),
            IpcRequest::GetCaptureStatus { capture_id }
            | IpcRequest::GetCaptureMetrics { capture_id } => self
                .inner
                .jobs
                .lock()
                .unwrap()
                .get(&capture_id)
                .cloned()
                .map(IpcResponse::job)
                .unwrap_or_else(|| {
                    IpcResponse::error("CAPTURE_NOT_FOUND", "capture job not found")
                }),
            IpcRequest::ForgetCapture { capture_id } => self.forget(peer.uid, &capture_id),
        }
    }

    fn forget(&self, owner_uid: u32, capture_id: &str) -> IpcResponse {
        let mut jobs = self.inner.jobs.lock().unwrap();
        let Some(job) = jobs.get(capture_id) else {
            return IpcResponse::error("CAPTURE_NOT_FOUND", "capture job not found");
        };
        if job.owner_uid != owner_uid {
            return IpcResponse::error("CAPTURE_OWNERSHIP", "capture belongs to another peer");
        }
        if job.state.active() {
            return IpcResponse::error("CAPTURE_ACTIVE", "active capture cannot be forgotten");
        }
        let snapshot = job.clone();
        let job_path = self
            .inner
            .config
            .capture_root
            .join(capture_id)
            .join("helper_job.json");
        if let Err(error) = fs::remove_file(&job_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return IpcResponse::error("CAPTURE_FORGET", error.to_string());
            }
        }
        jobs.remove(capture_id);
        IpcResponse::job(snapshot)
    }

    fn validate_spec(&self, spec: &CaptureSpec) -> Result<(), HelperFailure> {
        if !valid_capture_id(&spec.capture_id) {
            return Err(failure(
                "INVALID_CAPTURE_ID",
                "capture ID is not allowlisted",
            ));
        }
        if spec.interfaces.is_empty() || spec.interfaces.len() > MAX_CAPTURE_PLANES {
            return Err(failure(
                "INVALID_INTERFACES",
                "one to four logical capture planes are required",
            ));
        }
        let mut unique = spec.interfaces.clone();
        unique.sort();
        unique.dedup();
        if unique.len() != spec.interfaces.len() {
            return Err(failure("INVALID_INTERFACES", "duplicate interface"));
        }
        for interface in &spec.interfaces {
            let path = self.inner.config.interface_root.join(interface.device());
            if !path.is_dir() {
                return Err(failure(
                    "INTERFACE_UNAVAILABLE",
                    format!("{} is unavailable", interface.label()),
                ));
            }
        }
        let policy = self.inner.config.policy;
        if spec.duration_seconds == 0 || spec.duration_seconds > policy.max_job_seconds {
            return Err(failure(
                "INVALID_DURATION",
                "capture duration exceeds policy",
            ));
        }
        if spec.rotation_files == 0 || spec.rotation_files > policy.max_files {
            return Err(failure(
                "INVALID_ROTATION",
                "capture rotation exceeds policy",
            ));
        }
        if !capture_budget(
            measure_path(&self.inner.config.capture_root),
            spec.max_bytes,
            policy,
        )
        .allowed
        {
            return Err(failure("DISK_SAFETY", "capture write budget rejected"));
        }
        if self
            .inner
            .jobs
            .lock()
            .unwrap()
            .values()
            .any(|job| job.state.active())
        {
            return Err(failure("CAPTURE_CONFLICT", "another capture is active"));
        }
        Ok(())
    }

    fn start(&self, owner_uid: u32, spec: CaptureSpec) -> IpcResponse {
        if let Err(error) = self.validate_spec(&spec) {
            return IpcResponse::error(&error.category, error.details);
        }
        if self
            .inner
            .jobs
            .lock()
            .unwrap()
            .contains_key(&spec.capture_id)
        {
            return IpcResponse::error("DUPLICATE_CAPTURE", "capture ID already exists");
        }
        let job = new_job(&spec, owner_uid, HelperState::Starting);
        self.inner
            .jobs
            .lock()
            .unwrap()
            .insert(spec.capture_id.clone(), job.clone());
        if let Err(error) = self.persist_job(&job) {
            self.inner.jobs.lock().unwrap().remove(&spec.capture_id);
            return IpcResponse::error("JOB_PERSISTENCE", error);
        }
        let stop = Arc::new(AtomicBool::new(false));
        self.inner
            .stops
            .lock()
            .unwrap()
            .insert(spec.capture_id.clone(), stop.clone());
        let service = self.clone();
        match thread::Builder::new()
            .name(format!("capture-helper-{}", spec.capture_id))
            .spawn(move || service.run_capture(spec, stop))
        {
            Ok(_) => IpcResponse::job(job),
            Err(error) => {
                self.inner.stops.lock().unwrap().remove(&job.capture_id);
                self.update(&job.capture_id, |current| {
                    current.state = HelperState::Failed;
                    current.ended_epoch_ms = Some(epoch_ms());
                    current.failure = Some(failure("HELPER_THREAD_START", error.to_string()));
                });
                IpcResponse::error("HELPER_THREAD_START", error.to_string())
            }
        }
    }

    fn stop(&self, owner_uid: u32, capture_id: &str) -> IpcResponse {
        let mut jobs = self.inner.jobs.lock().unwrap();
        let Some(job) = jobs.get_mut(capture_id) else {
            return IpcResponse::error("CAPTURE_NOT_FOUND", "capture job not found");
        };
        if job.owner_uid != owner_uid {
            return IpcResponse::error("CAPTURE_OWNERSHIP", "capture belongs to another peer");
        }
        if !job.state.active() {
            return IpcResponse::job(job.clone());
        }
        let Some(stop) = self.inner.stops.lock().unwrap().get(capture_id).cloned() else {
            return IpcResponse::error("CAPTURE_RUNTIME_MISSING", "capture runtime is unavailable");
        };
        stop.store(true, Ordering::Release);
        job.state = HelperState::Stopping;
        let snapshot = job.clone();
        drop(jobs);
        let _ = self.persist_job(&snapshot);
        IpcResponse::job(snapshot)
    }

    fn run_capture(&self, spec: CaptureSpec, stop: Arc<AtomicBool>) {
        let result = self.run_capture_inner(&spec, &stop);
        if let Err(error) = result {
            self.update(&spec.capture_id, |job| {
                job.state = HelperState::Failed;
                job.failure = Some(error);
                job.ended_epoch_ms = Some(epoch_ms());
            });
        }
        self.inner.stops.lock().unwrap().remove(&spec.capture_id);
    }

    fn run_capture_inner(
        &self,
        spec: &CaptureSpec,
        stop: &AtomicBool,
    ) -> Result<(), HelperFailure> {
        // CAPTURING is deliberately set only after packet acquisition and all
        // bounded writers are initialized successfully.
        let mut session = self.inner.backend.initialize(&spec.interfaces)?;
        let output = self.inner.config.capture_root.join(&spec.capture_id);
        let pcap_root = output.join("pcap");
        fs::create_dir_all(&pcap_root)
            .map_err(|error| failure("STORAGE_INITIALIZATION", error.to_string()))?;
        let mut writers = WriterSet::new(&pcap_root, spec, self.inner.config.policy)?;
        self.update(&spec.capture_id, |job| {
            job.state = HelperState::Capturing;
            job.started_epoch_ms = Some(epoch_ms());
        });
        let started = Instant::now();
        while started.elapsed().as_secs() < spec.duration_seconds && !stop.load(Ordering::Acquire) {
            if let Some(packet) = session.next_packet(Duration::from_millis(200))? {
                writers.write(packet)?;
            }
            let packet_drops = session.packet_drops();
            let metrics = HelperMetrics {
                packets_received: writers.packets,
                bytes_received: writers.captured_bytes,
                storage_bytes: writers.storage_bytes,
                packet_drops,
                duration_seconds: started.elapsed().as_secs_f64(),
            };
            self.update(&spec.capture_id, |job| job.metrics = metrics);
        }
        let final_drops = session.packet_drops();
        let manifest_path = writers.finalize(&output, final_drops)?;
        let state = if writers.packets == 0 {
            HelperState::CompletedEmpty
        } else {
            HelperState::Completed
        };
        self.update(&spec.capture_id, |job| {
            job.state = state;
            job.ended_epoch_ms = Some(epoch_ms());
            job.metrics.packets_received = writers.packets;
            job.metrics.bytes_received = writers.captured_bytes;
            job.metrics.storage_bytes = writers.storage_bytes;
            job.metrics.duration_seconds = started.elapsed().as_secs_f64();
            job.metrics.packet_drops = final_drops;
            job.manifest_path = Some(manifest_path);
        });
        Ok(())
    }

    fn update(&self, capture_id: &str, update: impl FnOnce(&mut HelperJob)) {
        let snapshot = {
            let mut jobs = self.inner.jobs.lock().unwrap();
            let Some(job) = jobs.get_mut(capture_id) else {
                return;
            };
            update(job);
            job.clone()
        };
        let _ = self.persist_job(&snapshot);
    }

    fn persist_job(&self, job: &HelperJob) -> Result<(), String> {
        let directory = self.inner.config.capture_root.join(&job.capture_id);
        fs::create_dir_all(&directory).map_err(io_error)?;
        let temporary = directory.join("helper_job.json.tmp");
        let destination = directory.join("helper_job.json");
        fs::write(
            &temporary,
            serde_json::to_vec_pretty(job).map_err(json_error)?,
        )
        .map_err(io_error)?;
        fs::rename(temporary, destination).map_err(io_error)
    }

    fn recover_jobs(&self) -> Result<(), String> {
        for entry in fs::read_dir(&self.inner.config.capture_root)
            .map_err(io_error)?
            .filter_map(Result::ok)
        {
            let path = entry.path().join("helper_job.json");
            if !path.is_file() {
                continue;
            }
            let mut job: HelperJob =
                serde_json::from_slice(&fs::read(&path).map_err(io_error)?).map_err(json_error)?;
            if job.state.active() {
                job.state = HelperState::Failed;
                job.ended_epoch_ms = Some(epoch_ms());
                job.failure = Some(failure(
                    "HELPER_RESTART_RECOVERY",
                    "active capture was interrupted by helper restart",
                ));
                self.persist_job(&job)?;
            }
            self.inner
                .jobs
                .lock()
                .unwrap()
                .insert(job.capture_id.clone(), job);
        }
        Ok(())
    }
}

fn new_job(spec: &CaptureSpec, owner_uid: u32, state: HelperState) -> HelperJob {
    HelperJob {
        capture_id: spec.capture_id.clone(),
        interfaces: spec.interfaces.clone(),
        state,
        owner_uid,
        created_epoch_ms: epoch_ms(),
        started_epoch_ms: None,
        ended_epoch_ms: None,
        metrics: HelperMetrics::default(),
        failure: None,
        manifest_path: None,
    }
}

#[derive(Clone, Debug)]
pub struct CaptureHelperClient {
    socket_path: PathBuf,
    expected_server_uid: u32,
}

impl CaptureHelperClient {
    pub fn new(socket_path: PathBuf, expected_server_uid: u32) -> Self {
        Self {
            socket_path,
            expected_server_uid,
        }
    }

    pub fn available(&self) -> bool {
        self.socket_path.exists()
    }

    pub fn request(&self, request: &IpcRequest) -> Result<IpcResponse, String> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(io_error)?;
        let peer = peer_credentials(&stream)?;
        if peer.uid != self.expected_server_uid {
            return Err("capture helper server identity mismatch".into());
        }
        serde_json::to_writer(&mut stream, request).map_err(json_error)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(io_error)?;
        let mut body = String::new();
        stream
            .take(MAX_IPC_BYTES)
            .read_to_string(&mut body)
            .map_err(io_error)?;
        serde_json::from_str(&body).map_err(json_error)
    }
}

pub fn authorize_peer(peer: PeerCredentials, allowed_uid: u32, allowed_gid: Option<u32>) -> bool {
    peer.uid == allowed_uid && allowed_gid.map_or(true, |gid| peer.gid == gid)
}

pub fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, String> {
    let mut credentials: libc::ucred = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut _ as *mut libc::c_void,
            &mut length,
        )
    } != 0
    {
        return Err(format!(
            "IPC peer credentials: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

pub struct AfPacketBackend;

impl CaptureBackend for AfPacketBackend {
    fn initialize(
        &self,
        interfaces: &[InterfaceId],
    ) -> Result<Box<dyn CaptureSession>, HelperFailure> {
        let mut sockets = Vec::new();
        for interface in interfaces {
            sockets.push(PacketSocket::open(*interface)?);
        }
        Ok(Box::new(AfPacketSession {
            sockets,
            cursor: 0,
            buffer: vec![0_u8; 65_535],
            drops: 0,
        }))
    }
}

struct PacketSocket {
    fd: RawFd,
    interface: InterfaceId,
}

impl PacketSocket {
    fn open(interface: InterfaceId) -> Result<Self, HelperFailure> {
        let name = std::ffi::CString::new(interface.device()).unwrap();
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(failure(
                "CAPTURE_INITIALIZATION",
                format!("{} index unavailable", interface.label()),
            ));
        }
        let protocol = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                protocol,
            )
        };
        if fd < 0 {
            return Err(failure(
                "CAPTURE_PRIVILEGE",
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let mut address: libc::sockaddr_ll = unsafe { mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        address.sll_ifindex = index as i32;
        let result = unsafe {
            libc::bind(
                fd,
                &address as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(failure("CAPTURE_INITIALIZATION", error.to_string()));
        }
        Ok(Self { fd, interface })
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

struct AfPacketSession {
    sockets: Vec<PacketSocket>,
    cursor: usize,
    buffer: Vec<u8>,
    drops: u64,
}

impl CaptureSession for AfPacketSession {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<CapturedPacket>, HelperFailure> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut pollfds = self
                .sockets
                .iter()
                .map(|socket| libc::pollfd {
                    fd: socket.fd,
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect::<Vec<_>>();
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
            let result =
                unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, timeout_ms) };
            if result < 0 {
                return Err(failure(
                    "CAPTURE_READ",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            if result == 0 {
                return Ok(None);
            }
            for offset in 0..pollfds.len() {
                let index = (self.cursor + offset) % pollfds.len();
                if pollfds[index].revents & libc::POLLIN == 0 {
                    continue;
                }
                let length = unsafe {
                    libc::recv(
                        self.sockets[index].fd,
                        self.buffer.as_mut_ptr() as *mut libc::c_void,
                        self.buffer.len(),
                        0,
                    )
                };
                if length < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(failure("CAPTURE_READ", error.to_string()));
                }
                self.cursor = (index + 1) % self.sockets.len();
                let data = self.buffer[..length as usize].to_vec();
                if !packet_matches_interface(self.sockets[index].interface, &data) {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    continue;
                }
                return Ok(Some(CapturedPacket {
                    interface: self.sockets[index].interface,
                    timestamp: SystemTime::now(),
                    original_length: length as u32,
                    data,
                }));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        }
    }

    fn packet_drops(&mut self) -> Option<u64> {
        #[repr(C)]
        struct PacketStatistics {
            packets: u32,
            drops: u32,
        }
        for socket in &self.sockets {
            let mut statistics = PacketStatistics {
                packets: 0,
                drops: 0,
            };
            let mut length = mem::size_of::<PacketStatistics>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket.fd,
                    263, // SOL_PACKET
                    6,   // PACKET_STATISTICS
                    &mut statistics as *mut _ as *mut libc::c_void,
                    &mut length,
                )
            } != 0
            {
                return None;
            }
            self.drops = self.drops.saturating_add(u64::from(statistics.drops));
        }
        Some(self.drops)
    }
}

/// Fixed capture-point filters. HTTP clients cannot supply these values.
fn packet_matches_interface(interface: InterfaceId, frame: &[u8]) -> bool {
    if frame.len() < 14 {
        return false;
    }
    let mut offset = 14;
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if matches!(ether_type, 0x8100 | 0x88a8) {
        if frame.len() < 18 {
            return false;
        }
        ether_type = u16::from_be_bytes([frame[16], frame[17]]);
        offset = 18;
    }
    let (protocol, transport) = match ether_type {
        0x0800 if frame.len() >= offset + 20 => {
            let ihl = usize::from(frame[offset] & 0x0f) * 4;
            if ihl < 20 || frame.len() < offset + ihl {
                return false;
            }
            (frame[offset + 9], offset + ihl)
        }
        0x86dd if frame.len() >= offset + 40 => (frame[offset + 6], offset + 40),
        _ => return false,
    };
    if frame.len() < transport + 4 {
        return false;
    }
    let source = u16::from_be_bytes([frame[transport], frame[transport + 1]]);
    let destination = u16::from_be_bytes([frame[transport + 2], frame[transport + 3]]);
    let port = |expected| source == expected || destination == expected;
    match interface {
        InterfaceId::N2 => protocol == 132 && port(38412),
        InterfaceId::N3 => protocol == 17 && port(2152),
        InterfaceId::N4 => protocol == 17 && port(8805),
        InterfaceId::Sbi => protocol == 6 && port(7777),
    }
}

struct PcapWriter {
    interface: InterfaceId,
    root: PathBuf,
    file: Option<File>,
    file_index: u16,
    file_bytes: u64,
    max_file_bytes: u64,
    max_files: u16,
    paths: Vec<PathBuf>,
}

impl PcapWriter {
    fn new(root: &Path, interface: InterfaceId, max_file_bytes: u64, max_files: u16) -> Self {
        Self {
            interface,
            root: root.into(),
            file: None,
            file_index: 0,
            file_bytes: 0,
            max_file_bytes,
            max_files,
            paths: Vec::new(),
        }
    }

    fn write(&mut self, packet: &CapturedPacket) -> Result<u64, HelperFailure> {
        let required = PCAP_RECORD_HEADER_BYTES + packet.data.len() as u64;
        let rotating =
            self.file.is_none() || self.file_bytes.saturating_add(required) > self.max_file_bytes;
        if rotating {
            self.rotate()?;
        }
        let duration = packet
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let file = self.file.as_mut().unwrap();
        file.write_all(&(duration.as_secs() as u32).to_le_bytes())
            .and_then(|_| file.write_all(&duration.subsec_micros().to_le_bytes()))
            .and_then(|_| file.write_all(&(packet.data.len() as u32).to_le_bytes()))
            .and_then(|_| file.write_all(&packet.original_length.to_le_bytes()))
            .and_then(|_| file.write_all(&packet.data))
            .map_err(|error| failure("CAPTURE_WRITE", error.to_string()))?;
        self.file_bytes += required;
        Ok(required
            + if rotating {
                PCAP_GLOBAL_HEADER_BYTES
            } else {
                0
            })
    }

    fn additional_bytes(&self, packet_length: usize) -> u64 {
        let record = PCAP_RECORD_HEADER_BYTES + packet_length as u64;
        record
            + if self.file.is_none() || self.file_bytes.saturating_add(record) > self.max_file_bytes
            {
                PCAP_GLOBAL_HEADER_BYTES
            } else {
                0
            }
    }

    fn rotate(&mut self) -> Result<(), HelperFailure> {
        if self.file_index >= self.max_files {
            return Err(failure("ROTATION_LIMIT", "capture rotation limit reached"));
        }
        if let Some(mut file) = self.file.take() {
            file.flush()
                .and_then(|_| file.sync_all())
                .map_err(|error| failure("CAPTURE_FINALIZE", error.to_string()))?;
        }
        let path = self.root.join(format!(
            "{}.pcap{}",
            self.interface.label(),
            self.file_index
        ));
        let mut file =
            File::create(&path).map_err(|error| failure("CAPTURE_WRITE", error.to_string()))?;
        file.write_all(&pcap_header())
            .map_err(|error| failure("CAPTURE_WRITE", error.to_string()))?;
        self.file = Some(file);
        self.file_bytes = PCAP_GLOBAL_HEADER_BYTES;
        self.file_index += 1;
        self.paths.push(path);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), HelperFailure> {
        if self.file.is_none() {
            self.rotate()?;
        }
        if let Some(mut file) = self.file.take() {
            file.flush()
                .and_then(|_| file.sync_all())
                .map_err(|error| failure("CAPTURE_FINALIZE", error.to_string()))?;
        }
        Ok(())
    }
}

struct WriterSet {
    root: PathBuf,
    writers: BTreeMap<InterfaceId, PcapWriter>,
    guard: CaptureGuard,
    packets: u64,
    captured_bytes: u64,
    storage_bytes: u64,
}

impl WriterSet {
    fn new(root: &Path, spec: &CaptureSpec, policy: Policy) -> Result<Self, HelperFailure> {
        let segments = (spec.interfaces.len() as u64)
            .saturating_mul(u64::from(spec.rotation_files))
            .max(1);
        let max_file_bytes = (spec.max_bytes / segments)
            .max(PCAP_GLOBAL_HEADER_BYTES + PCAP_RECORD_HEADER_BYTES + 1)
            .min(policy.max_file_bytes);
        let guard = CaptureGuard::start(measure_path(root), spec.max_bytes, policy)
            .map_err(|error| failure("DISK_SAFETY", error))?;
        let writers = spec
            .interfaces
            .iter()
            .map(|interface| {
                (
                    *interface,
                    PcapWriter::new(root, *interface, max_file_bytes, spec.rotation_files),
                )
            })
            .collect();
        Ok(Self {
            root: root.into(),
            writers,
            guard,
            packets: 0,
            captured_bytes: 0,
            storage_bytes: 0,
        })
    }

    fn write(&mut self, packet: CapturedPacket) -> Result<(), HelperFailure> {
        let writer = self.writers.get_mut(&packet.interface).ok_or_else(|| {
            failure(
                "INTERFACE_MISMATCH",
                "packet came from an unselected interface",
            )
        })?;
        let required = writer.additional_bytes(packet.data.len());
        self.guard
            .authorize_write(required, measure_path(&self.root))
            .map_err(|error| failure("DISK_SAFETY", error))?;
        self.storage_bytes = self.storage_bytes.saturating_add(writer.write(&packet)?);
        self.packets += 1;
        self.captured_bytes = self.captured_bytes.saturating_add(packet.data.len() as u64);
        Ok(())
    }

    fn finalize(&mut self, output: &Path, drops: Option<u64>) -> Result<String, HelperFailure> {
        let mut files = Vec::new();
        for writer in self.writers.values_mut() {
            if writer.file.is_none() {
                self.guard
                    .authorize_write(PCAP_GLOBAL_HEADER_BYTES, measure_path(&self.root))
                    .map_err(|error| failure("DISK_SAFETY", error))?;
                self.storage_bytes = self.storage_bytes.saturating_add(PCAP_GLOBAL_HEADER_BYTES);
            }
            writer.finish()?;
            for path in &writer.paths {
                let bytes = fs::read(path)
                    .map_err(|error| failure("CAPTURE_FINALIZE", error.to_string()))?;
                files.push(serde_json::json!({
                    "interface": writer.interface,
                    "file": path.file_name().and_then(|name| name.to_str()).unwrap_or("UNKNOWN"),
                    "size_bytes": bytes.len(),
                    "sha256": sha256_hex(&bytes),
                }));
            }
        }
        let manifest = serde_json::json!({
            "schema_version": "1.0",
            "packets": self.packets,
            "captured_bytes": self.captured_bytes,
            "storage_bytes": self.storage_bytes,
            "packet_drops": drops,
            "files": files,
            "finalized_epoch_ms": epoch_ms(),
        });
        let temporary = output.join("capture_manifest.json.tmp");
        let final_path = output.join("capture_manifest.json");
        fs::write(
            &temporary,
            serde_json::to_vec_pretty(&manifest)
                .map_err(|error| failure("MANIFEST", error.to_string()))?,
        )
        .map_err(|error| failure("MANIFEST", error.to_string()))?;
        fs::rename(&temporary, &final_path)
            .map_err(|error| failure("MANIFEST", error.to_string()))?;
        Ok(final_path.display().to_string())
    }
}

fn pcap_header() -> [u8; 24] {
    [
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ]
}

fn valid_capture_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn failure(category: &str, details: impl Into<String>) -> HelperFailure {
    HelperFailure {
        category: category.into(),
        details: sanitize(&details.into()),
        exit_code: None,
        termination_signal: None,
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || *character == '\n')
        .take(1024)
        .collect()
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn io_error(error: std::io::Error) -> String {
    error.to_string()
}

fn json_error(error: serde_json::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Clone)]
    struct MockBackend {
        packets: Arc<Mutex<VecDeque<CapturedPacket>>>,
        initialize_error: Option<HelperFailure>,
    }

    impl CaptureBackend for MockBackend {
        fn initialize(
            &self,
            _interfaces: &[InterfaceId],
        ) -> Result<Box<dyn CaptureSession>, HelperFailure> {
            if let Some(error) = &self.initialize_error {
                return Err(error.clone());
            }
            Ok(Box::new(MockSession {
                packets: self.packets.clone(),
            }))
        }
    }

    struct MockSession {
        packets: Arc<Mutex<VecDeque<CapturedPacket>>>,
    }

    impl CaptureSession for MockSession {
        fn next_packet(
            &mut self,
            _timeout: Duration,
        ) -> Result<Option<CapturedPacket>, HelperFailure> {
            thread::sleep(Duration::from_millis(2));
            Ok(self.packets.lock().unwrap().pop_front())
        }
    }

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("oiran-capture-helper-{name}-{}", epoch_ms()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn service(name: &str, backend: MockBackend) -> CaptureService<MockBackend> {
        let root = root(name);
        let interface_root = root.join("interfaces");
        for interface in [
            InterfaceId::N2,
            InterfaceId::Sbi,
            InterfaceId::N4,
            InterfaceId::N3,
        ] {
            fs::create_dir_all(interface_root.join(interface.device())).unwrap();
        }
        CaptureService::new(
            ServerConfig {
                socket_path: root.join("helper.sock"),
                capture_root: root,
                interface_root,
                allowed_client_uid: unsafe { libc::geteuid() },
                allowed_client_gid: Some(unsafe { libc::getegid() }),
                socket_gid: None,
                policy: Policy::default(),
            },
            backend,
        )
        .unwrap()
    }

    fn spec(id: &str) -> CaptureSpec {
        CaptureSpec {
            capture_id: id.into(),
            interfaces: vec![InterfaceId::N3],
            duration_seconds: 1,
            max_bytes: 1024 * 1024,
            rotation_files: 2,
        }
    }

    fn peer() -> PeerCredentials {
        PeerCredentials {
            pid: std::process::id() as i32,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }

    fn wait_for_terminal(service: &CaptureService<MockBackend>, capture_id: &str) -> HelperJob {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let job = service
                .handle(
                    peer(),
                    IpcRequest::GetCaptureStatus {
                        capture_id: capture_id.into(),
                    },
                )
                .job
                .unwrap();
            if !job.state.active() {
                return job;
            }
            assert!(
                Instant::now() < deadline,
                "capture did not reach a terminal state"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn peer_authorization_requires_uid_and_gid() {
        let allowed = PeerCredentials {
            pid: 1,
            uid: 100,
            gid: 200,
        };
        assert!(authorize_peer(allowed, 100, Some(200)));
        assert!(!authorize_peer(allowed, 101, Some(200)));
        assert!(!authorize_peer(allowed, 100, Some(201)));
    }

    #[test]
    fn unix_socket_round_trip_authenticates_peer() {
        let service = service(
            "ipc-round-trip",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        let socket = service.inner.config.socket_path.clone();
        let listener = service.bind().unwrap();
        assert_eq!(
            fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o660
        );
        let server = service.clone();
        let thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            server.handle_stream(stream).unwrap();
        });
        let client = CaptureHelperClient::new(socket, unsafe { libc::geteuid() });
        let response = client
            .request(&IpcRequest::ValidateCapture(spec("ipc-validated")))
            .unwrap();
        assert!(response.ok);
        assert_eq!(response.job.unwrap().state, HelperState::Ready);
        thread.join().unwrap();
    }

    #[test]
    fn request_schema_has_no_path_filter_or_shell_field() {
        let value = serde_json::to_value(IpcRequest::StartCapture(spec("safe-id"))).unwrap();
        let encoded = value.to_string();
        assert!(!encoded.contains("output_path"));
        assert!(!encoded.contains("filter"));
        assert!(!encoded.contains("command_line"));
    }

    fn ethernet_transport_frame(protocol: u8, source: u16, destination: u16) -> Vec<u8> {
        let mut frame = vec![0_u8; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[23] = protocol;
        frame[34..36].copy_from_slice(&source.to_be_bytes());
        frame[36..38].copy_from_slice(&destination.to_be_bytes());
        frame
    }

    #[test]
    fn fixed_interface_filters_are_allowlisted_per_plane() {
        assert!(packet_matches_interface(
            InterfaceId::N2,
            &ethernet_transport_frame(132, 38412, 49152)
        ));
        assert!(packet_matches_interface(
            InterfaceId::Sbi,
            &ethernet_transport_frame(6, 49152, 7777)
        ));
        assert!(packet_matches_interface(
            InterfaceId::N4,
            &ethernet_transport_frame(17, 8805, 49152)
        ));
        assert!(packet_matches_interface(
            InterfaceId::N3,
            &ethernet_transport_frame(17, 49152, 2152)
        ));
        assert!(!packet_matches_interface(
            InterfaceId::Sbi,
            &ethernet_transport_frame(6, 49152, 443)
        ));
        assert!(!packet_matches_interface(
            InterfaceId::N3,
            &ethernet_transport_frame(17, 49152, 53)
        ));
    }

    #[test]
    fn sbi_is_a_fixed_interface_without_user_supplied_paths_or_filters() {
        assert_eq!(InterfaceId::Sbi.device(), "br-oiran-sbi");
        assert_eq!(InterfaceId::Sbi.label(), "SBI");
        let request = CaptureSpec {
            interfaces: vec![
                InterfaceId::N2,
                InterfaceId::Sbi,
                InterfaceId::N4,
                InterfaceId::N3,
            ],
            ..spec("four-plane")
        };
        let encoded = serde_json::to_string(&IpcRequest::ValidateCapture(request)).unwrap();
        assert!(encoded.contains("Sbi"));
        assert!(!encoded.contains("br-oiran-sbi"));
        assert!(!encoded.contains("7777"));
    }

    #[test]
    fn terminal_continuous_segment_can_be_forgotten_but_active_capture_cannot() {
        let service = service(
            "forget",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        let mut job = new_job(
            &spec("continuous-segment-1"),
            peer().uid,
            HelperState::Capturing,
        );
        service
            .inner
            .jobs
            .lock()
            .unwrap()
            .insert(job.capture_id.clone(), job.clone());
        let active = service.handle(
            peer(),
            IpcRequest::ForgetCapture {
                capture_id: job.capture_id.clone(),
            },
        );
        assert!(!active.ok);
        assert_eq!(active.error.unwrap().category, "CAPTURE_ACTIVE");
        job.state = HelperState::Completed;
        service
            .inner
            .jobs
            .lock()
            .unwrap()
            .insert(job.capture_id.clone(), job.clone());
        let forgotten = service.handle(
            peer(),
            IpcRequest::ForgetCapture {
                capture_id: job.capture_id.clone(),
            },
        );
        assert!(forgotten.ok);
        assert!(!service
            .inner
            .jobs
            .lock()
            .unwrap()
            .contains_key(&job.capture_id));
    }

    #[test]
    fn validator_accepts_one_through_four_allowlisted_planes() {
        let service = service(
            "plane-cardinality",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        let allowed = [
            InterfaceId::N2,
            InterfaceId::Sbi,
            InterfaceId::N4,
            InterfaceId::N3,
        ];
        for count in 1..=MAX_CAPTURE_PLANES {
            let mut request = spec(&format!("planes-{count}"));
            request.interfaces = allowed[..count].to_vec();
            request.max_bytes = 64 * 1024 * 1024;
            let response = service.handle(peer(), IpcRequest::ValidateCapture(request));
            assert!(response.ok, "{count}-plane validation failed: {response:?}");
            assert_eq!(response.job.unwrap().state, HelperState::Ready);
        }
    }

    #[test]
    fn validator_rejects_five_duplicate_and_unknown_planes() {
        let service = service(
            "plane-rejection",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        let mut five = spec("five-planes");
        five.interfaces = vec![
            InterfaceId::N2,
            InterfaceId::Sbi,
            InterfaceId::N4,
            InterfaceId::N3,
            InterfaceId::N2,
        ];
        let response = service.handle(peer(), IpcRequest::ValidateCapture(five));
        assert_eq!(response.error.unwrap().category, "INVALID_INTERFACES");

        let mut duplicate = spec("duplicate-planes");
        duplicate.interfaces = vec![InterfaceId::N2, InterfaceId::N2];
        let response = service.handle(peer(), IpcRequest::ValidateCapture(duplicate));
        assert_eq!(response.error.unwrap().category, "INVALID_INTERFACES");

        let unknown = r#"{"command":"VALIDATE_CAPTURE","payload":{"capture_id":"unknown-plane","interfaces":["N2","UNKNOWN"],"duration_seconds":1,"max_bytes":1048576,"rotation_files":1}}"#;
        assert!(serde_json::from_str::<IpcRequest>(unknown).is_err());
    }

    #[test]
    fn four_plane_writer_reservation_stays_within_global_budget() {
        let capture_root = root("four-plane-budget");
        let spec = CaptureSpec {
            capture_id: "four-plane-budget".into(),
            interfaces: vec![
                InterfaceId::N2,
                InterfaceId::Sbi,
                InterfaceId::N4,
                InterfaceId::N3,
            ],
            duration_seconds: 60,
            max_bytes: 64 * 1024 * 1024,
            rotation_files: 4,
        };
        let writers = WriterSet::new(&capture_root, &spec, Policy::default()).unwrap();
        assert_eq!(writers.writers.len(), MAX_CAPTURE_PLANES);
        let allocated = writers
            .writers
            .values()
            .map(|writer| writer.max_file_bytes * u64::from(writer.max_files))
            .sum::<u64>();
        assert!(allocated <= spec.max_bytes);
    }

    #[test]
    fn invalid_capture_id_is_rejected() {
        let service = service(
            "invalid",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        let response = service.handle(peer(), IpcRequest::ValidateCapture(spec("../escape")));
        assert!(!response.ok);
        assert_eq!(response.error.unwrap().category, "INVALID_CAPTURE_ID");
    }

    #[test]
    fn unauthorized_peer_is_rejected() {
        let service = service(
            "unauthorized",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        let mut unauthorized = peer();
        unauthorized.uid = unauthorized.uid.saturating_add(1);
        let response = service.handle(unauthorized, IpcRequest::ValidateCapture(spec("denied")));
        assert_eq!(response.error.unwrap().category, "IPC_UNAUTHORIZED_PEER");
    }

    #[test]
    fn initialization_failure_never_transitions_to_capturing() {
        let service = service(
            "init-failure",
            MockBackend {
                packets: Default::default(),
                initialize_error: Some(failure("CAPTURE_INITIALIZATION", "offline failure")),
            },
        );
        let response = service.handle(peer(), IpcRequest::StartCapture(spec("init-failure")));
        assert!(response.ok);
        thread::sleep(Duration::from_millis(30));
        let result = service.handle(
            peer(),
            IpcRequest::GetCaptureStatus {
                capture_id: "init-failure".into(),
            },
        );
        let job = result.job.unwrap();
        assert_eq!(job.state, HelperState::Failed);
        assert_eq!(job.failure.unwrap().category, "CAPTURE_INITIALIZATION");
    }

    #[test]
    fn offline_packet_produces_valid_pcap_and_atomic_manifest() {
        let packets = Arc::new(Mutex::new(VecDeque::from([CapturedPacket {
            interface: InterfaceId::N3,
            timestamp: UNIX_EPOCH + Duration::from_secs(10),
            original_length: 4,
            data: vec![1, 2, 3, 4],
        }])));
        let service = service(
            "pcap",
            MockBackend {
                packets,
                initialize_error: None,
            },
        );
        let response = service.handle(peer(), IpcRequest::StartCapture(spec("offline-pcap")));
        assert!(response.ok);
        let job = wait_for_terminal(&service, "offline-pcap");
        assert_eq!(job.state, HelperState::Completed);
        assert_eq!(job.metrics.packets_received, 1);
        let manifest = PathBuf::from(job.manifest_path.unwrap());
        assert!(manifest.is_file());
        assert!(!manifest.with_extension("json.tmp").exists());
        let pcap = fs::read(manifest.parent().unwrap().join("pcap/N3.pcap0")).unwrap();
        assert_eq!(&pcap[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(pcap.len(), 44);
        let manifest_value: serde_json::Value =
            serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
        assert_eq!(manifest_value["packets"], 1);
        assert_eq!(manifest_value["files"][0]["sha256"], sha256_hex(&pcap));
    }

    #[test]
    fn empty_capture_is_explicit() {
        let service = service(
            "empty",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        service.handle(peer(), IpcRequest::StartCapture(spec("offline-empty")));
        thread::sleep(Duration::from_millis(1100));
        let job = service
            .handle(
                peer(),
                IpcRequest::GetCaptureStatus {
                    capture_id: "offline-empty".into(),
                },
            )
            .job
            .unwrap();
        assert_eq!(job.state, HelperState::CompletedEmpty);
        assert_eq!(job.metrics.packets_received, 0);
    }

    #[test]
    fn stop_is_owner_scoped_and_idempotent() {
        let service = service(
            "stop",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        let mut long = spec("owned");
        long.duration_seconds = 10;
        service.handle(peer(), IpcRequest::StartCapture(long));
        thread::sleep(Duration::from_millis(20));
        let mut other = peer();
        other.uid = other.uid.saturating_add(1);
        let denied = service.stop(other.uid, "owned");
        assert_eq!(denied.error.unwrap().category, "CAPTURE_OWNERSHIP");
        assert!(service.stop(peer().uid, "owned").ok);
        thread::sleep(Duration::from_millis(30));
        assert!(service.stop(peer().uid, "owned").ok);
    }

    #[test]
    fn manual_stop_gracefully_finalizes_owned_capture() {
        let packets = Arc::new(Mutex::new(VecDeque::from([CapturedPacket {
            interface: InterfaceId::N3,
            timestamp: UNIX_EPOCH + Duration::from_secs(11),
            original_length: 4,
            data: vec![1, 2, 3, 4],
        }])));
        let service = service(
            "manual-stop-finalize",
            MockBackend {
                packets,
                initialize_error: None,
            },
        );
        let mut request = spec("manual-stop-finalize");
        request.duration_seconds = 10;
        assert!(service.handle(peer(), IpcRequest::StartCapture(request)).ok);
        thread::sleep(Duration::from_millis(30));
        assert!(service.stop(peer().uid, "manual-stop-finalize").ok);
        let job = wait_for_terminal(&service, "manual-stop-finalize");
        assert_eq!(job.state, HelperState::Completed);
        assert_eq!(job.metrics.packets_received, 1);
        assert!(Path::new(job.manifest_path.as_deref().unwrap()).is_file());
        assert!(service.stop(peer().uid, "manual-stop-finalize").ok);
    }

    #[test]
    fn rotation_produces_bounded_structurally_complete_segments() {
        let packets = Arc::new(Mutex::new(VecDeque::from([
            CapturedPacket {
                interface: InterfaceId::N3,
                timestamp: UNIX_EPOCH + Duration::from_secs(20),
                original_length: 4,
                data: vec![1, 2, 3, 4],
            },
            CapturedPacket {
                interface: InterfaceId::N3,
                timestamp: UNIX_EPOCH + Duration::from_secs(21),
                original_length: 4,
                data: vec![5, 6, 7, 8],
            },
            CapturedPacket {
                interface: InterfaceId::N3,
                timestamp: UNIX_EPOCH + Duration::from_secs(22),
                original_length: 4,
                data: vec![9, 10, 11, 12],
            },
        ])));
        let service = service(
            "rotation",
            MockBackend {
                packets,
                initialize_error: None,
            },
        );
        let mut request = spec("rotation");
        request.max_bytes = 160;
        request.rotation_files = 3;
        service.handle(peer(), IpcRequest::StartCapture(request));
        let job = wait_for_terminal(&service, "rotation");
        assert_eq!(job.state, HelperState::Completed);
        let manifest_path = PathBuf::from(job.manifest_path.unwrap());
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["files"].as_array().unwrap().len(), 3);
        assert_eq!(manifest["packets"], 3);
        for index in 0..3 {
            let bytes = fs::read(
                manifest_path
                    .parent()
                    .unwrap()
                    .join(format!("pcap/N3.pcap{index}")),
            )
            .unwrap();
            assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
            assert_eq!(bytes.len(), 44);
        }
    }

    #[test]
    fn selected_interface_without_packets_is_preserved_not_failed() {
        let packets = Arc::new(Mutex::new(VecDeque::from([CapturedPacket {
            interface: InterfaceId::N2,
            timestamp: UNIX_EPOCH + Duration::from_secs(30),
            original_length: 4,
            data: vec![1, 2, 3, 4],
        }])));
        let service = service(
            "partial-interface",
            MockBackend {
                packets,
                initialize_error: None,
            },
        );
        let mut request = spec("partial-interface");
        request.interfaces = vec![InterfaceId::N2, InterfaceId::N3];
        service.handle(peer(), IpcRequest::StartCapture(request));
        let job = wait_for_terminal(&service, "partial-interface");
        assert_eq!(job.state, HelperState::Completed);
        assert_eq!(job.metrics.packets_received, 1);
        assert_eq!(job.metrics.storage_bytes, 68);
        let manifest_path = PathBuf::from(job.manifest_path.unwrap());
        let n3 = fs::read(manifest_path.parent().unwrap().join("pcap/N3.pcap0")).unwrap();
        assert_eq!(n3.len(), PCAP_GLOBAL_HEADER_BYTES as usize);
    }

    #[test]
    fn partial_interface_initialization_failure_fails_closed() {
        let service = service(
            "partial-interface-init-failure",
            MockBackend {
                packets: Default::default(),
                initialize_error: Some(failure(
                    "CAPTURE_INITIALIZATION",
                    "N4 packet acquisition unavailable",
                )),
            },
        );
        let mut request = spec("partial-interface-init-failure");
        request.interfaces = vec![InterfaceId::N2, InterfaceId::N3, InterfaceId::N4];
        service.handle(peer(), IpcRequest::StartCapture(request));
        let job = wait_for_terminal(&service, "partial-interface-init-failure");
        assert_eq!(job.state, HelperState::Failed);
        assert_eq!(
            job.failure
                .as_ref()
                .map(|failure| failure.category.as_str()),
            Some("CAPTURE_INITIALIZATION")
        );
        assert!(job.manifest_path.is_none());
    }

    #[test]
    fn signal_failure_is_serialized_without_false_exit_code() {
        let failure = HelperFailure {
            category: "SUBPROCESS_SIGNAL".into(),
            details: "helper terminated by signal".into(),
            exit_code: None,
            termination_signal: Some(libc::SIGSEGV),
        };
        let value = serde_json::to_value(failure).unwrap();
        assert_eq!(value["termination_signal"], libc::SIGSEGV);
        assert!(value["exit_code"].is_null());
    }

    #[test]
    fn interrupted_job_is_recovered_as_failed() {
        let capture_root = root("recovery");
        let interface_root = capture_root.join("interfaces");
        fs::create_dir_all(&interface_root).unwrap();
        let config = ServerConfig {
            socket_path: capture_root.join("helper.sock"),
            capture_root,
            interface_root,
            allowed_client_uid: unsafe { libc::geteuid() },
            allowed_client_gid: Some(unsafe { libc::getegid() }),
            socket_gid: None,
            policy: Policy::default(),
        };
        let backend = MockBackend {
            packets: Default::default(),
            initialize_error: None,
        };
        let first = CaptureService::new(config.clone(), backend.clone()).unwrap();
        let mut interrupted_spec = spec("interrupted");
        interrupted_spec.interfaces = vec![InterfaceId::Sbi];
        let interrupted = new_job(&interrupted_spec, peer().uid, HelperState::Capturing);
        first.persist_job(&interrupted).unwrap();
        let recovered = CaptureService::new(config.clone(), backend.clone()).unwrap();
        let job = recovered
            .handle(
                peer(),
                IpcRequest::GetCaptureStatus {
                    capture_id: "interrupted".into(),
                },
            )
            .job
            .unwrap();
        assert_eq!(job.state, HelperState::Failed);
        assert_eq!(job.interfaces, vec![InterfaceId::Sbi]);
        let forgotten = recovered.handle(
            peer(),
            IpcRequest::ForgetCapture {
                capture_id: "interrupted".into(),
            },
        );
        assert!(forgotten.ok);
        let restarted = CaptureService::new(config, backend).unwrap();
        let missing = restarted.handle(
            peer(),
            IpcRequest::GetCaptureStatus {
                capture_id: "interrupted".into(),
            },
        );
        assert_eq!(missing.error.unwrap().category, "CAPTURE_NOT_FOUND");
        assert_eq!(job.failure.unwrap().category, "HELPER_RESTART_RECOVERY");
    }

    #[test]
    fn disk_quota_rejects_oversized_request() {
        let service = service(
            "quota",
            MockBackend {
                packets: Default::default(),
                initialize_error: None,
            },
        );
        let mut request = spec("too-large");
        request.max_bytes = u64::MAX;
        let response = service.handle(peer(), IpcRequest::ValidateCapture(request));
        assert_eq!(response.error.unwrap().category, "DISK_SAFETY");
    }
}
