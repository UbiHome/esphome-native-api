//! Embassy-rs example for esphome-native-api.
//!
//! This example has one purpose: **verify that `esphome-native-api` works
//! correctly when compiled without the `std` feature** (i.e. in a no_std
//! context).
//!
//! The `esphome-native-api` crate is added with `default-features = false`,
//! which enables the `#![no_std]` code path.  Only the `proto` module is
//! available in that mode; everything else (TCP, encryption, codec) is gated
//! behind the `std` feature.
//!
//! The example itself runs on a standard desktop OS via embassy-executor's
//! `arch-std` feature so that it can be executed without any special hardware.
//! To target real embedded hardware (e.g. Raspberry Pi Pico W) you would:
//!
//! 1. Replace `arch-std` with `arch-cortex-m` (or the arch for your chip).
//! 2. Add the appropriate HAL crate (`embassy-rp`, `embassy-stm32`, …).
//! 3. Add `embassy-net` + a network driver for TCP/IP.
//! 4. Add a `#[global_allocator]` (e.g. `embedded-alloc`) if your target has
//!    no built-in allocator.
//!
//! # Running
//!
//! ```bash
//! cargo run -p embassy-esphome
//! ```

use embassy_executor::Spawner;

// Only the proto module is available when std is disabled.
use esphome_native_api::proto::{
    HelloRequest, HelloResponse, ListEntitiesSensorResponse, SensorStateResponse,
};
use prost::Message;

// ── Embassy tasks ────────────────────────────────────────────────────────────

/// Simulates a sensor-polling task.
///
/// On real hardware this task would read from a peripheral (e.g. I²C) and
/// publish readings through an `embassy_sync::channel::Channel`.  It would
/// use `embassy_time::Timer::after(…).await` to sleep between samples.
#[embassy_executor::task]
async fn sensor_task() {
    // Build an ESPHome entity descriptor for a temperature sensor using only
    // the proto types provided by esphome-native-api (no std required).
    let entity = ListEntitiesSensorResponse {
        object_id: "temperature".to_string(),
        key: 0x0000_0001,
        name: "Temperature".to_string(),
        unit_of_measurement: "°C".to_string(),
        device_class: "temperature".to_string(),
        accuracy_decimals: 1,
        state_class: 1, // measurement
        ..Default::default()
    };

    // Encode to wire format — this exercises the prost-generated code that
    // lives inside the proto module of esphome-native-api.
    let encoded = entity.encode_to_vec();
    println!(
        "[sensor_task] ListEntitiesSensorResponse '{}' encoded to {} bytes",
        entity.name,
        encoded.len()
    );

    // Build a state update the same way.
    let state = SensorStateResponse {
        key: entity.key,
        state: 21.5,
        missing_state: false,
        device_id: 0,
    };
    let state_encoded = state.encode_to_vec();
    println!(
        "[sensor_task] SensorStateResponse ({} °C) encoded to {} bytes",
        state.state,
        state_encoded.len()
    );
}

// ── Embassy entry point ───────────────────────────────────────────────────────

/// Embassy async main.
///
/// On embedded hardware the signature stays the same; only the underlying
/// executor and the concrete peripherals change.
#[embassy_executor::main]
async fn main(spawner: Spawner) {
    println!("[main] esphome-native-api embassy example");

    // ── Spawn background tasks ──────────────────────────────────────────────
    spawner.spawn(sensor_task()).unwrap();

    // ── Demonstrate Hello handshake using proto types only ─────────────────
    //
    // Encode a HelloRequest (as Home Assistant would send it).
    let request = HelloRequest {
        client_info: "aioesphomeapi 24.0.0".to_string(),
        api_version_major: 1,
        api_version_minor: 10,
    };
    let request_bytes = request.encode_to_vec();

    // Decode it back (as the ESPHome device would do) and build a response.
    let decoded_request = HelloRequest::decode(request_bytes.as_slice()).unwrap();
    let response = HelloResponse {
        api_version_major: 1,
        api_version_minor: 10,
        server_info: "esphome-native-api/embassy-example".to_string(),
        name: "embassy-device".to_string(),
    };
    let response_bytes = response.encode_to_vec();

    println!(
        "[main] HelloRequest from '{}' (API {}.{})",
        decoded_request.client_info,
        decoded_request.api_version_major,
        decoded_request.api_version_minor,
    );
    println!(
        "[main] HelloResponse '{}' encoded to {} bytes",
        response.name,
        response_bytes.len()
    );
    println!("[main] All proto types from esphome-native-api work in embassy context ✓");
}
