use polaris_control_api::{app, AppState};
#[tokio::main]
async fn main() {
    let bind = std::env::var("POLARIS_BIND").unwrap_or_else(|_| "127.0.0.1:49153".into());
    if !bind.starts_with("127.0.0.1:") {
        eprintln!("refusing non-loopback bind: {bind}");
        std::process::exit(2)
    }
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("bind POLARIS Control");
    println!("POLARIS Control listening on http://{bind}");
    let state = AppState::from_env().unwrap_or_else(|error| {
        eprintln!("secure configuration error: {error}");
        std::process::exit(2)
    });
    axum::serve(listener, app(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap();
}
