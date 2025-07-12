use esphome_native_api::server::Server;
use log::{info, LevelFilter};
use tokio::signal;
use esphome_native_api::proto::version_2025_4_2::ListEntitiesButtonResponse;



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder().filter_level(LevelFilter::Debug).init();


    let mut server = Server::builder()
        .api_version_major(1)
        .api_version_minor(42)
        .server_info("test_server".to_string())
        // Attention test servers uses a different port than the default one
        .address("0.0.0.0:7000".to_string())
        .name("test_device".to_string())
        .friendly_name("friendly_test_device".to_string())
        .bluetooth_mac_address("B0:00:00:00:00:00".to_string())
        .mac("00:00:00:00:00:01".to_string())
        .manufacturer("Test Inc.".to_string())
        .model("Test Model".to_string())
        .suggested_area("Test Area".to_string())
        .build();

    let main_server = async {
        let entity = esphome_native_api::ProtoMessage::ListEntitiesButtonResponse(
            ListEntitiesButtonResponse { 
                object_id: "test_object_id".to_string(), 
                key: 0, 
                name: "test".to_string(), 
                unique_id: "unique_test_id".to_string(), 
                icon: "mdi:test-icon".to_string(), 
                disabled_by_default: false, 
                entity_category: 0, 
                device_class: "test_device_class".to_string(),
            },
        );
        server.send(entity);
        server.start().await.unwrap();
    };

    // TODO: For later

    // server.add_entity("test", entity);

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
        _ = main_server => {},
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Stopped");

    std::process::exit(0);

}