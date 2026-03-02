//! Embassy-rs example for esphome-native-api.
//!
//! **Purpose:** Verify that `esphome-native-api` works correctly when compiled
//! *without* the `std` feature, i.e. in a no_std context.
//!
//! The crate is added with `default-features = false` which enables the
//! `#![no_std]` code path.  In this mode **all** modules are available:
//!
//! - `proto` — generated protobuf types
//! - `parser` — message encoding / decoding
//! - `packet_plaintext` / `packet_encrypted` — frame serialisation
//! - `frame` — raw frame encode / decode helpers
//! - `hash` — FNV-1 entity key hashing
//! - `esphomeapi` — full server protocol via [`EspHomeApi::init_connection`],
//!   [`EspHomeApi::process_message`], and [`EspHomeApi::send_message`]
//! - `esphomeserver` — high-level entity management via [`EspHomeServer`]
//!
//! The example runs on the desktop using embassy-executor's `arch-std` feature
//! so it can be executed without hardware.  The ESPHome protocol is exercised
//! against an in-memory byte pipe (see [`ServerReader`] / [`ServerWriter`])
//! that acts as a fake client speaking plaintext ESPHome protocol.
//!
//! # Porting to embedded hardware
//!
//! 1. Replace `arch-std` with the arch for your chip (`arch-cortex-m`, …).
//! 2. Add the matching HAL crate (`embassy-rp`, `embassy-stm32`, …).
//! 3. Add `embassy-net` + a network driver; `embassy_net::tcp::TcpSocket`
//!    already implements `embedded_io_async::Read + Write`.
//! 4. Add a `#[global_allocator]` (e.g. `embedded-alloc`) and declare
//!    `#![no_std] extern crate alloc;` in `main.rs`.
//!
//! # Running
//!
//! ```bash
//! cargo run -p embassy-esphome
//! ```

use embassy_executor::Spawner;
use embedded_io_async::{Read, Write};

// esphome-native-api compiled WITHOUT std — the no_std API is active.
use esphome_native_api::esphomeapi::EspHomeApi;
use esphome_native_api::esphomeserver::{BinarySensor, Entity, EspHomeServer};
use esphome_native_api::frame::{decode_frame, encode_frame};
use esphome_native_api::hash::hash_fnv1;
use esphome_native_api::parser::ProtoMessage;
use esphome_native_api::proto::{
    BinarySensorStateResponse, HelloRequest, ListEntitiesBinarySensorResponse,
    ListEntitiesDoneResponse, ListEntitiesRequest, SubscribeStatesRequest,
};

use prost::Message;

// ── In-memory byte pipe ───────────────────────────────────────────────────────

/// Simple synchronised in-memory pipe for testing.
///
/// Two `Vec<u8>` buffers carry bytes in each direction.  One half is given
/// to the "server" ([`EspHomeApi`]) and the other acts as a fake "client".
struct StaticPipe {
    client_to_server: std::sync::Mutex<Vec<u8>>,
    server_to_client: std::sync::Mutex<Vec<u8>>,
}

impl StaticPipe {
    fn new() -> Self {
        Self {
            client_to_server: std::sync::Mutex::new(Vec::new()),
            server_to_client: std::sync::Mutex::new(Vec::new()),
        }
    }
}

/// Read half handed to the server: reads bytes that the client placed in the pipe.
struct ServerReader<'a>(&'a StaticPipe);
/// Write half handed to the server: writes bytes the client will read later.
struct ServerWriter<'a>(&'a StaticPipe);

impl embedded_io_async::ErrorType for ServerReader<'_> {
    type Error = core::convert::Infallible;
}
impl embedded_io_async::ErrorType for ServerWriter<'_> {
    type Error = core::convert::Infallible;
}

impl Read for ServerReader<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            let mut data = self.0.client_to_server.lock().unwrap();
            if !data.is_empty() {
                let n = buf.len().min(data.len());
                buf[..n].copy_from_slice(&data[..n]);
                data.drain(..n);
                return Ok(n);
            }
            drop(data);
            std::thread::yield_now();
        }
    }
}

impl Write for ServerWriter<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0.server_to_client.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ── Plain-text frame helpers (fake client side) ───────────────────────────────

/// Send a proto message as a plain-text ESPHome frame from the fake client.
fn client_send(pipe: &StaticPipe, msg_type: u8, msg: &impl Message) {
    let mut payload = vec![msg_type];
    payload.extend_from_slice(&msg.encode_to_vec());
    let frame = encode_frame(&payload, false).unwrap();
    pipe.client_to_server.lock().unwrap().extend_from_slice(&frame);
}

/// Spin until one complete plain-text frame has been written by the server,
/// then return `(msg_type, proto_bytes)`.
fn client_recv(pipe: &StaticPipe) -> (u8, Vec<u8>) {
    loop {
        let mut buf = pipe.server_to_client.lock().unwrap();
        if let Some((payload, consumed)) = decode_frame(&buf, false).unwrap() {
            buf.drain(..consumed);
            return (payload[0], payload[1..].to_vec());
        }
        drop(buf);
        std::thread::yield_now();
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    println!("[main] esphome-native-api embassy no_std example");
    println!();

    // ── hash module ───────────────────────────────────────────────────────────
    let entity_key = hash_fnv1(&"motion".to_string());
    println!("[hash]   FNV-1 key for 'motion' = 0x{entity_key:08X}");

    // ── EspHomeServer: entity management ─────────────────────────────────────
    let mut server = EspHomeServer::builder()
        .name("embassy-device".to_string())
        .server_info("esphome-native-api/embassy".to_string())
        .build();
    server.add_entity(
        "motion",
        Entity::BinarySensor(BinarySensor {
            object_id: "motion".to_string(),
        }),
    );
    let mut api: EspHomeApi = server.build_api();

    // ── In-memory pipe (stands in for embassy-net TcpSocket) ─────────────────
    let pipe = StaticPipe::new();
    let mut reader = ServerReader(&pipe);
    let mut writer = ServerWriter(&pipe);

    // ── Protocol exchange ─────────────────────────────────────────────────────

    // 1. Client → HelloRequest (msg type 1)
    client_send(
        &pipe,
        1,
        &HelloRequest {
            client_info: "aioesphomeapi 24.0.0".to_string(),
            api_version_major: 1,
            api_version_minor: 10,
        },
    );

    // 2. Server init: reads HelloRequest, replies with HelloResponse
    api.init_connection(&mut reader, &mut writer)
        .await
        .expect("init_connection failed");

    // 3. Client reads HelloResponse (msg type 2)
    let (t, b) = client_recv(&pipe);
    assert_eq!(t, 2);
    let hello = esphome_native_api::proto::HelloResponse::decode(b.as_slice()).unwrap();
    println!(
        "[proto]  HelloResponse: name='{}' API={}.{}",
        hello.name, hello.api_version_major, hello.api_version_minor
    );

    // 4. Client → ListEntitiesRequest (msg type 11)
    client_send(&pipe, 11, &ListEntitiesRequest {});

    // 5. Server processes it → returns the message to the application layer
    let msg = api
        .process_message(&mut reader, &mut writer)
        .await
        .expect("process_message failed");
    assert!(matches!(msg, ProtoMessage::ListEntitiesRequest(_)));
    println!("[server] Received ListEntitiesRequest — sending entity list");

    // 6. Server sends entity + done
    api.send_message(
        &mut writer,
        &ProtoMessage::ListEntitiesBinarySensorResponse(ListEntitiesBinarySensorResponse {
            object_id: "motion".to_string(),
            key: entity_key,
            name: "Motion Sensor".to_string(),
            device_class: "motion".to_string(),
            ..Default::default()
        }),
    )
    .await
    .expect("send entity failed");
    api.send_message(
        &mut writer,
        &ProtoMessage::ListEntitiesDoneResponse(ListEntitiesDoneResponse {}),
    )
    .await
    .expect("send done failed");

    // 7. Client reads entity (type 12) and done (type 19)
    let (t12, b12) = client_recv(&pipe);
    assert_eq!(t12, 12);
    let entity =
        ListEntitiesBinarySensorResponse::decode(b12.as_slice()).unwrap();
    println!(
        "[proto]  Entity: '{}' key=0x{:08X}",
        entity.name, entity.key
    );
    let (t19, _) = client_recv(&pipe);
    assert_eq!(t19, 19);
    println!("[proto]  ListEntitiesDone received");

    // 8. Client → SubscribeStatesRequest (msg type 20)
    client_send(&pipe, 20, &SubscribeStatesRequest {});

    // 9. Server processes subscribe → returns it to application layer
    let msg2 = api
        .process_message(&mut reader, &mut writer)
        .await
        .expect("process_message failed");
    assert!(matches!(msg2, ProtoMessage::SubscribeStatesRequest(_)));
    println!("[server] Received SubscribeStatesRequest — sending state update");

    // 10. Server sends state update
    api.send_message(
        &mut writer,
        &ProtoMessage::BinarySensorStateResponse(BinarySensorStateResponse {
            key: entity_key,
            state: true,
            missing_state: false,
            device_id: 0,
        }),
    )
    .await
    .expect("send state failed");

    // 11. Client reads state (type 21)
    let (t21, b21) = client_recv(&pipe);
    assert_eq!(t21, 21);
    let state = BinarySensorStateResponse::decode(b21.as_slice()).unwrap();
    println!(
        "[proto]  State update: key=0x{:08X} state={}",
        state.key, state.state
    );

    println!();
    println!("[main]   All modules verified in no_std (embassy) context ✓");
    println!("         proto  parser  packet_plaintext  frame  hash");
    println!("         esphomeapi (init_connection / process_message / send_message)");
    println!("         esphomeserver (build_api / add_entity)");
}
