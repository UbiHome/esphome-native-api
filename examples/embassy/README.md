# embassy-esphome example

Embassy-rs example that verifies **`esphome-native-api` works without the `std`
feature**.

The crate is added with `default-features = false` so only the `proto` module
is available (the networking/codec code is gated behind `std`).  The example
encodes and decodes a selection of ESPHome proto messages to confirm the
generated code compiles and runs correctly in a no_std context.

The example itself runs on a standard desktop OS using embassy-executor's
`arch-std` feature.

## Running

```bash
cargo run -p embassy-esphome
```

Expected output:

```
[main] esphome-native-api embassy example
[main] HelloRequest from 'aioesphomeapi 24.0.0' (API 1.10)
[main] HelloResponse 'embassy-device' encoded to 56 bytes
[main] All proto types from esphome-native-api work in embassy context ✓
[sensor_task] ListEntitiesSensorResponse 'Temperature' encoded to 53 bytes
[sensor_task] SensorStateResponse (21.5 °C) encoded to 10 bytes
```

## Porting to embedded hardware

1. In `Cargo.toml`, replace `arch-std` with the arch for your chip:
   - Cortex-M: `arch-cortex-m`
   - RISC-V 32: `arch-riscv32`
   - AVR: `arch-avr`

2. Add the matching HAL crate (`embassy-rp`, `embassy-stm32`, `embassy-nrf`, …).

3. Add `embassy-net` and a network driver for TCP/IP support.

4. If your target has no built-in heap, add a `#[global_allocator]`
   (e.g. [`embedded-alloc`](https://crates.io/crates/embedded-alloc)) and
   declare `#![no_std] extern crate alloc;` in `main.rs`.

5. In `sensor_task`, replace the stub with actual peripheral reads and use
   `embassy_time::Timer::after(…).await` for delays.
