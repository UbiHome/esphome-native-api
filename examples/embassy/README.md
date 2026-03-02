# embassy-esphome

Embassy-rs example that verifies **all** `esphome-native-api` modules work
correctly in a `no_std` context.

## What this example proves

`esphome-native-api` is added with `default-features = false`, which activates
the `#![no_std]` code path.  **Every module** is then exercised:

| Module | Tested |
|---|---|
| `proto` | generated protobuf types encode/decode correctly |
| `parser` | `parse_proto_message` / `proto_to_vec` / `message_to_num` |
| `packet_plaintext` | plaintext packet serialisation |
| `frame` | `encode_frame` / `decode_frame` standalone helpers |
| `hash` | FNV-1 entity key hashing |
| `esphomeapi` | `init_connection` / `process_message` / `send_message` (no_std API) |
| `esphomeserver` | `build_api` / `add_entity` entity management |

The example runs on the **desktop** using embassy-executor's `arch-std` feature.
The protocol is exercised against an in-memory byte pipe that simulates a
client speaking plain-text ESPHome protocol.

## Running

```bash
cargo run -p embassy-esphome
```

Expected output:

```
[main] esphome-native-api embassy no_std example

[hash]   FNV-1 key for 'motion' = 0x77F53707
[proto]  HelloResponse: name='embassy-device' API=1.10
[server] Received ListEntitiesRequest — sending entity list
[proto]  Entity: 'Motion Sensor' key=0x77F53707
[proto]  ListEntitiesDone received
[server] Received SubscribeStatesRequest — sending state update
[proto]  State update: key=0x77F53707 state=true

[main]   All modules verified in no_std (embassy) context ✓
```

## Porting to embedded hardware

1. Swap `arch-std` → `arch-cortex-m` (or the arch for your chip).
2. Add the matching HAL crate (`embassy-rp`, `embassy-stm32`, `embassy-nrf`, …).
3. Add `embassy-net` + a network driver.
   `embassy_net::tcp::TcpSocket` already implements
   `embedded_io_async::Read + Write`, so it can be passed directly to
   `EspHomeApi::init_connection` / `process_message` / `send_message`.
4. Add a `#[global_allocator]` (e.g. `embedded-alloc`) and add
   `#![no_std] extern crate alloc;` at the top of `main.rs`.
5. For noise encryption, configure `getrandom` with the `custom` feature and
   register a hardware RNG implementation.
