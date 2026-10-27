use oiran_api::{router, ApiConfig, AppState};
use std::{env, net::SocketAddr, path::PathBuf};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error={error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let workspace = env::var("OIRAN_WORKSPACE").unwrap_or_else(|_| "/root/OIRAN_VPROBE".into());
    let bind: SocketAddr = env::var("OIRAN_API_BIND")
        .unwrap_or_else(|_| "127.0.0.1:49152".into())
        .parse()
        .map_err(|_| "invalid OIRAN_API_BIND")?;
    if !bind.ip().is_loopback() {
        return Err("S4 permits loopback binding only".into());
    }
    let workspace = PathBuf::from(workspace);
    let state = AppState::load(ApiConfig::from_workspace(&workspace))?;
    let dist = workspace.join("apps/web/dist");
    let frontend = dist.is_dir().then_some(dist);
    let app = router(state, frontend);
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| e.to_string())?;
    println!("OIRAN API listening on http://{bind} mode=LIVE_CAPTURE_CAPABLE_EXECUTION_GATED");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())
}
