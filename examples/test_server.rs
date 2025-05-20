use esphome_native_api::server::Server;
use log::LevelFilter;



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder().filter_level(LevelFilter::Debug).init();



    let server = Server::new("0.0.0.0:6053".to_string());

    // server
    server.start().await?;

    Ok(())
}