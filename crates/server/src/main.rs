mod routes;
mod security;
mod state;
mod storage;

use anyhow::Result;
use state::AppState;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let state = AppState::from_env().await?;
    let address = std::env::var("RPROBE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    let listener = TcpListener::bind(&address).await?;
    info!(%address, "rprobe-server listening");
    axum::serve(listener, routes::router(state.clone()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    state.close().await;
    Ok(())
}
