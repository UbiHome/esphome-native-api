//! Example: Easy server setup (work in progress)
//!
//! This example is currently under development and demonstrates how to use
//! the higher-level `EspHomeServer` abstraction for easier setup and entity
//! management.
//!
//! # Status
//!
//! Most of the server setup code is currently commented out as this example
//! is being refined. See `test_server.rs` or `encrypted_server.rs` for
//! working examples.
//!
//! # Usage
//!
//! Run with:
//! ```bash
//! cargo run --example easy_server
//! ```
//!
//! Set a custom port:
//! ```bash
//! SERVER_PORT=6053 cargo run --example easy_server
//! ```

use std::env;
use std::{future, net::SocketAddr, time::Duration};

use esphome_native_api::{
    esphomeapi::EspHomeApi,
    esphomeserver::EspHomeServer,
    parser::ProtoMessage,
    proto::{
        ListEntitiesBinarySensorResponse, ListEntitiesButtonResponse, ListEntitiesLightResponse,
        ListEntitiesSensorResponse, ListEntitiesSwitchResponse, SensorStateResponse,
    },
};
use log::{LevelFilter, debug, info};
use tokio::{net::TcpSocket, signal, time::sleep};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Debug)
        .init();

    let addr: SocketAddr = SocketAddr::from((
        [127, 0, 0, 1],
        env::var("SERVER_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6053),
    ));
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
            // tokio::task::spawn(async move {

            //     let mut server = EspHomeServer::builder()
            //             .api_version_major(1)
            //             .api_version_minor(42)
            //             // .password("password".to_string())
            //             .server_info("test_server_info".to_string())
            //             .name("test_device".to_string())
            //             .friendly_name("friendly_test_device".to_string())
            //             .bluetooth_mac_address("B0:00:00:00:00:00".to_string())
            //             .mac("00:00:00:00:00:01".to_string())
            //             .manufacturer("Test Inc.".to_string())
            //             .model("Test Model".to_string())
            //             .suggested_area("Test Area".to_string())
            //             .build();

            //     // All supported entities in alphabetical order
            //     let binary_sensor =
            //         ProtoMessage::ListEntitiesBinarySensorResponse(
            //             ListEntitiesBinarySensorResponse {
            //                 object_id: "test_binary_sensor_object_id".to_string(),
            //                 key: 3,
            //                 name: "test_binary_sensor".to_string(),
            //                 unique_id: "test_binary_sensor_unique_id".to_string(),
            //                 icon: "mdi:test-binary-sensor-icon".to_string(),
            //                 device_class: "test_binary_sensor_device_class".to_string(),
            //                 is_status_binary_sensor: true,
            //                 disabled_by_default: false,
            //                 entity_category: 0, // EntityCategory::None as i32
            //             },
            //         );
            //     server.add_entity("test_binary_sensor", binary_sensor.clone());

            //     let button = ProtoMessage::ListEntitiesButtonResponse(
            //         ListEntitiesButtonResponse {
            //             object_id: "test_button_object_id".to_string(),
            //             key: 0,
            //             name: "test_button".to_string(),
            //             unique_id: "test_button_unique_id".to_string(),
            //             icon: "mdi:test-button-icon".to_string(),
            //             disabled_by_default: false,
            //             entity_category: 0,
            //             device_class: "test_button_device_class".to_string(),
            //         },
            //     );
            //     server.add_entity("test_button", button.clone());

            //     let light = ProtoMessage::ListEntitiesLightResponse(
            //         ListEntitiesLightResponse {
            //             object_id: "test_light_object_id".to_string(),
            //             key: 4,
            //             name: "test_light".to_string(),
            //             unique_id: "test_light_unique_id".to_string(),
            //             icon: "mdi:test-light-icon".to_string(),
            //             disabled_by_default: false,
            //             entity_category: 0, // EntityCategory::None as i32
            //             supported_color_modes: vec![], // Can be populated based on capabilities
            //             min_mireds: 153.0,
            //             max_mireds: 500.0,
            //             effects: vec![], // Light effects can be added later
            //             legacy_supports_brightness: false,
            //             legacy_supports_rgb: false,
            //             legacy_supports_white_value: false,
            //             legacy_supports_color_temperature: false,
            //         },
            //     );
            //     server.add_entity("test_light", light.clone());

            //     let sensor = ProtoMessage::ListEntitiesSensorResponse(
            //         ListEntitiesSensorResponse {
            //             object_id: "test_sensor_object_id".to_string(),
            //             key: 2,
            //             name: "test_sensor".to_string(),
            //             unique_id: "test_sensor_unique_id".to_string(),
            //             icon: "mdi:test-sensor-icon".to_string(),
            //             unit_of_measurement: "°C".to_string(),
            //             accuracy_decimals: 2,
            //             force_update: false,
            //             device_class: "temperature".to_string(),
            //             state_class: 1, // SensorStateClass::StateClassMeasurement as i32
            //             legacy_last_reset_type: 0, // SensorLastResetType::LastResetNone as i32
            //             disabled_by_default: false,
            //             entity_category: 0, // EntityCategory::None as i32
            //         },
            //     );
            //     server.add_entity("test_sensor", sensor.clone());

            //     let switch = ProtoMessage::ListEntitiesSwitchResponse(
            //         ListEntitiesSwitchResponse {
            //             object_id: "test_switch_object_id".to_string(),
            //             key: 1,
            //             name: "test_switch".to_string(),
            //             unique_id: "test_switch_unique_id".to_string(),
            //             icon: "mdi:test-switch-icon".to_string(),
            //             device_class: "test_switch_device_class".to_string(),
            //             disabled_by_default: false,
            //             entity_category: 0,
            //             assumed_state: false,
            //         }
            //     );
            //     server.add_entity("test_switch", switch.clone());

            //     let (tx) = server.start(stream).await
            //         .expect("Failed to start server");

            //     debug!("Server started");
            //     sleep(Duration::from_secs(3)).await;

            //     let message = ProtoMessage::SensorStateResponse(
            //         SensorStateResponse {
            //             key: 0,
            //             state: 25.0,
            //             missing_state: false,
            //         },
            //     );
            //     for n in 1..=10 {
            //     sleep(Duration::from_secs(3)).await;
            //         debug!("Sending message number {}", n);
            //         tx.send(message.clone()).await.expect("Failed to send message");
            //     }

            //     debug!("Queue message to sent");

            //     // Wait indefinitely for the interrupts
            //     let future = future::pending();
            //     let () = future.await;
            //     tx.send(message.clone()).await.expect("Failed to send message");
            // });
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
