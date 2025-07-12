use std::{sync::mpsc, time::Duration};

use esphome_native_api::server::Server;
use log::{info, LevelFilter};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Debug)
        .init();

    let server = Server::builder().build();

    server.start().await?;


    Ok(())
}
