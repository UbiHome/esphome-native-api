use std::{future, net::SocketAddr, time::Duration};

use esphome_native_api::{proto::version_2025_6_3::{ListEntitiesBinarySensorResponse, ListEntitiesLightResponse, ListEntitiesSensorResponse, ListEntitiesSwitchResponse, SensorStateResponse}};
use log::{debug, info, LevelFilter};
use tokio::{net::TcpSocket, signal, time::sleep};
use esphome_native_api::proto::version_2025_6_3::ListEntitiesButtonResponse;
use esphome_native_api::ProtoMessage;
use esphome_native_api::esphomeapi::EspHomeApi;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder().filter_level(LevelFilter::Trace).init();

    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 7001));
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();

    socket.bind(addr).unwrap();
    let listener = socket.listen(128).unwrap();

    debug!("Listening on: {}", addr);

    let main_server = async {

        loop {
            let (stream, _) = listener.accept().await
                .expect("Failed to accept connection");
            debug!("Accepted request from {}", stream.peer_addr().unwrap());

            // Spawn a tokio task to serve multiple connections concurrently
            tokio::task::spawn(async move {

                let mut server = EspHomeApi::builder()
                    .api_version_major(1)
                    .api_version_minor(42)
                    // .password("password".to_string())
                    .server_info("test_server_info".to_string())
                    .name("test_device".to_string())
                    .friendly_name("friendly_test_device".to_string())
                    .bluetooth_mac_address("B0:00:00:00:00:00".to_string())
                    .mac("00:00:00:00:00:01".to_string())
                    .manufacturer("Test Inc.".to_string())
                    .model("Test Model".to_string())
                    .suggested_area("Test Area".to_string())
                    .encryption_key("px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA=".to_string())
                    .build();

                let tx = server.start(stream).await
                    .expect("Failed to start server");

                debug!("Server started");
                sleep(Duration::from_secs(4)).await;

                let message = ProtoMessage::SensorStateResponse(
                    SensorStateResponse {
                        key: 0,
                        state: 25.0,
                        missing_state: false,
                    },
                );
                tx.send(message.clone()).expect("Failed to send message");

                // Wait indefinitely for the interrupts
                let future = future::pending();
                let () = future.await;

                let message = ProtoMessage::SensorStateResponse(
                    SensorStateResponse {
                        key: 0,
                        state: 25.0,
                        missing_state: false,
                    },
                );
                tx.send(message.clone()).expect("Failed to send message");

            });
        }
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
        _ = main_server => {},
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("Stopped");

    std::process::exit(0);

}