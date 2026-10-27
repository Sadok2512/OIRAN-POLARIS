use capture_helper::{AfPacketBackend, CaptureService, ServerConfig};
use disk_safety::Policy;
use std::path::PathBuf;

fn main() {
    let socket_path = std::env::var_os("OIRAN_CAPTURE_HELPER_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/oiran/capture-helper.sock"));
    let capture_root = std::env::var_os("OIRAN_CAPTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/oiran/captures"));
    let allowed_uid = required_u32("OIRAN_CAPTURE_CLIENT_UID");
    let allowed_gid = optional_u32("OIRAN_CAPTURE_CLIENT_GID");
    let socket_gid = optional_u32("OIRAN_CAPTURE_SOCKET_GID");
    let service = CaptureService::new(
        ServerConfig {
            socket_path,
            capture_root,
            interface_root: PathBuf::from("/sys/class/net"),
            allowed_client_uid: allowed_uid,
            allowed_client_gid: allowed_gid,
            socket_gid,
            policy: Policy::default(),
        },
        AfPacketBackend,
    )
    .unwrap_or_else(|error| fail(&error));
    let listener = service.bind().unwrap_or_else(|error| fail(&error));
    service.serve(listener).unwrap_or_else(|error| fail(&error));
}

fn required_u32(name: &str) -> u32 {
    std::env::var(name)
        .unwrap_or_else(|_| fail(&format!("{name} is required")))
        .parse()
        .unwrap_or_else(|_| fail(&format!("{name} must be an unsigned integer")))
}

fn optional_u32(name: &str) -> Option<u32> {
    std::env::var(name).ok().map(|value| {
        value
            .parse()
            .unwrap_or_else(|_| fail(&format!("{name} must be an unsigned integer")))
    })
}

fn fail(message: &str) -> ! {
    eprintln!("oiran-capture-helper: {message}");
    std::process::exit(1)
}
