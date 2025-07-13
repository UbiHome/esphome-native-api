use std::{sync::mpsc, time::Duration};

use esphome_native_api::server::Server;
use log::{info, LevelFilter};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Debug)
        .init();

    let mut server = Server::builder()
        .address("0.0.0.0:7000".to_string())
        .name("test_device".to_string())
        .build();

    server.start().await?;


    Ok(())
}
