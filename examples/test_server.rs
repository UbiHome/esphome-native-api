use std::{future, net::SocketAddr, time::Duration};

use esphome_native_api::esphomeapi::EspHomeApi;
use esphome_native_api::parser::ProtoMessage;
use esphome_native_api::proto::version_2025_12_1::{
    ListEntitiesBinarySensorResponse, ListEntitiesLightResponse, ListEntitiesSensorResponse,
    ListEntitiesSwitchResponse, SensorStateResponse,
};
use esphome_native_api::proto::version_2025_12_1::{
    ListEntitiesButtonResponse, ListEntitiesDoneResponse,
};
use log::{LevelFilter, debug, info};
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider;
// use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_semantic_conventions::{SCHEMA_URL, attribute::SERVICE_VERSION};
use tokio::{net::TcpSocket, signal, time::sleep};
use tracing_core::Level;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Construct TracerProvider for OpenTelemetryLayer
fn init_tracer_provider() -> SdkTracerProvider {
    let exporter = SpanExporter::builder().with_http().build().unwrap();

    SdkTracerProvider::builder()
        .with_resource(resource())
        .with_batch_exporter(exporter)
        .build()
}

fn resource() -> Resource {
    Resource::builder()
        .with_service_name(env!("CARGO_PKG_NAME"))
        .with_schema_url(
            [KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION"))],
            SCHEMA_URL,
        )
        .build()
}

fn init_tracing_subscriber() -> OtelGuard {
    let tracer_provider = init_tracer_provider();

    let tracer = tracer_provider.tracer("tracing-otel-subscriber");

    tracing_subscriber::registry()
        // The global level filter prevents the exporter network stack
        // from reentering the globally installed OpenTelemetryLayer with
        // its own spans while exporting, as the libraries should not use
        // tracing levels below DEBUG. If the OpenTelemetry layer needs to
        // trace spans and events with higher verbosity levels, consider using
        // per-layer filtering to target the telemetry layer specifically,
        // e.g. by target matching.
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            Level::INFO,
        ))
        .with(tracing_subscriber::fmt::layer())
        .with(OpenTelemetryLayer::new(tracer))
        .init();

    OtelGuard { tracer_provider }
}

struct OtelGuard {
    tracer_provider: SdkTracerProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = self.tracer_provider.shutdown() {
            eprintln!("{err:?}");
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::formatted_builder()
        .filter_level(LevelFilter::Debug)
        .init();
    let _guard = init_tracing_subscriber();

    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 7000));
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
                    .api_version_major(1)
                    .api_version_minor(42)
                    .password_opt(Option::None)
                    .encryption_key_opt(Option::None)
                    .server_info("test_server_info".to_string())
                    .name("test_device".to_string())
                    .friendly_name("friendly_test_device".to_string())
                    .bluetooth_mac_address("B0:00:00:00:00:00".to_string())
                    .mac("00:00:00:00:00:01".to_string())
                    .manufacturer("Test Inc.".to_string())
                    .model("Test Model".to_string())
                    .suggested_area("Test Area".to_string())
                    .build();

                let entities = vec![
                    // All supported entities in alphabetical order
                    ProtoMessage::ListEntitiesBinarySensorResponse(
                        ListEntitiesBinarySensorResponse {
                            object_id: "test_binary_sensor_object_id".to_string(),
                            key: 3,
                            name: "test_binary_sensor".to_string(),
                            // unique_id: "test_binary_sensor_unique_id".to_string(),
                            device_id: 0,
                            icon: "mdi:test-binary-sensor-icon".to_string(),
                            device_class: "test_binary_sensor_device_class".to_string(),
                            is_status_binary_sensor: true,
                            disabled_by_default: false,
                            entity_category: 0, // EntityCategory::None as i32
                        },
                    ),
                    ProtoMessage::ListEntitiesButtonResponse(ListEntitiesButtonResponse {
                        object_id: "test_button_object_id".to_string(),
                        key: 0,
                        name: "test_button".to_string(),
                        // unique_id: "test_button_unique_id".to_string(),
                        device_id: 0,

                        icon: "mdi:test-button-icon".to_string(),
                        disabled_by_default: false,
                        entity_category: 0,
                        device_class: "test_button_device_class".to_string(),
                    }),
                    ProtoMessage::ListEntitiesLightResponse(ListEntitiesLightResponse {
                        object_id: "test_light_object_id".to_string(),
                        key: 4,
                        name: "test_light".to_string(),
                        // unique_id: "test_light_unique_id".to_string(),
                        device_id: 0,

                        icon: "mdi:test-light-icon".to_string(),
                        disabled_by_default: false,
                        entity_category: 0, // EntityCategory::None as i32
                        supported_color_modes: vec![], // Can be populated based on capabilities
                        min_mireds: 153.0,
                        max_mireds: 500.0,
                        effects: vec![], // Light effects can be added later
                        legacy_supports_brightness: false,
                        legacy_supports_rgb: false,
                        legacy_supports_white_value: false,
                        legacy_supports_color_temperature: false,
                    }),
                    ProtoMessage::ListEntitiesSensorResponse(ListEntitiesSensorResponse {
                        object_id: "test_sensor_object_id".to_string(),
                        key: 2,
                        name: "test_sensor".to_string(),
                        // unique_id: "test_sensor_unique_id".to_string(),
                        device_id: 0,

                        icon: "mdi:test-sensor-icon".to_string(),
                        unit_of_measurement: "°C".to_string(),
                        accuracy_decimals: 2,
                        force_update: false,
                        device_class: "temperature".to_string(),
                        state_class: 1, // SensorStateClass::StateClassMeasurement as i32
                        legacy_last_reset_type: 0, // SensorLastResetType::LastResetNone as i32
                        disabled_by_default: false,
                        entity_category: 0, // EntityCategory::None as i32
                    }),
                    ProtoMessage::ListEntitiesSwitchResponse(ListEntitiesSwitchResponse {
                        object_id: "test_switch_object_id".to_string(),
                        key: 1,
                        name: "test_switch".to_string(),
                        // unique_id: "test_switch_unique_id".to_string(),
                        device_id: 0,

                        icon: "mdi:test-switch-icon".to_string(),
                        device_class: "test_switch_device_class".to_string(),
                        disabled_by_default: false,
                        entity_category: 0,
                        assumed_state: false,
                    }),
                ];

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

                                for sensor in &entities {
                                    tx_clone.send(sensor.clone()).unwrap();
                                }
                                tx_clone
                                    .send(ProtoMessage::ListEntitiesDoneResponse(
                                        ListEntitiesDoneResponse {},
                                    ))
                                    .unwrap();
                            }
                            _ => {}
                        }
                    }
                });

                let message = ProtoMessage::SensorStateResponse(SensorStateResponse {
                    device_id: 0,
                    key: 0,
                    state: 25.0,
                    missing_state: false,
                });
                for n in 1..=10 {
                    sleep(Duration::from_secs(3)).await;
                    debug!("Sending message number {}", n);
                    tx.send(message.clone()).expect("Failed to send message");
                }

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
