use std::{future, net::SocketAddr, time::Duration};

use esphome_native_api::esphomeapi::EspHomeApi;
use esphome_native_api::parser::ProtoMessage;
use esphome_native_api::proto::version_2025_6_3::{ListEntitiesButtonResponse, ListEntitiesDoneResponse};
use esphome_native_api::proto::version_2025_6_3::{
    ListEntitiesBinarySensorResponse, ListEntitiesLightResponse, ListEntitiesSensorResponse,
    ListEntitiesSwitchResponse, SensorStateResponse,
};
use log::{LevelFilter, debug, info};
use tokio::{net::TcpSocket, signal, time::sleep};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Trace)
        .init();

    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 7002));
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();

    socket.bind(addr).unwrap();
    let listener = socket.listen(128).unwrap();

    debug!("Listening on: {}", addr);

    let main_server = async {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");
            debug!("Accepted request from {}", stream.peer_addr().unwrap());

            // Spawn a tokio task to serve multiple connections concurrently
            tokio::task::spawn(async move {
                let mut server = EspHomeApi::builder()
                    .password("password".to_string())
                    .name("test_device".to_string())
                    .build();



                let (tx, mut rx) = server.start(stream).await.expect("Failed to start server");
                let tx_clone = tx.clone();
                debug!("Server started");
                sleep(Duration::from_secs(3)).await;

                tokio::spawn(async move {
                    loop {
                        let message = rx.recv().await.unwrap();
                        // Process the received message
                        debug!("Received message: {:?}", message);

                        match message {
                            ProtoMessage::ListEntitiesRequest(list_entities_request) => {
                                debug!("ListEntitiesRequest: {:?}", list_entities_request);

                                tx_clone.send(ProtoMessage::ListEntitiesDoneResponse(
                                    ListEntitiesDoneResponse {},
                                ))
                                .unwrap();
                            }
                            _ => {}
                        }
                    }
                });


                // Wait indefinitely for the interrupts
                let future = future::pending();
                let () = future.await;
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
