use std::{sync::mpsc, time::Duration};

use esphome_native_api::server::Server;
use log::{info, LevelFilter};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Debug)
        .init();

    let server = async {
        let server = Server::new("0.0.0.0:6053".to_string());
        server.start().await.unwrap();
    };

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = server => {},
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Stopped");

    std::process::exit(0);

    Ok(())
}
