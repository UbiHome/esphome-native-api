[Documentation](https://ubihome.github.io/esphome-native-api/) | [GitHub](https://github.com/ubihome/esphome-native-api) | [Crate](https://crates.io/crates/esphome-native-api) | [docs.rs](https://docs.rs/esphome-native-api/latest/esphome_native_api/)

---

# Rust Crate for the esphome native api

Implementation of the [esphome native api](https://esphome.io/components/api.html) for Rust.

> This is still work in progress, so the API surface may change. But it is already quite usable. Just try the [examples](./examples/).
> The implementation is already used by [UbiHome](https://github.com/ubihome/ubihome) to make OS based devices available to Home Assistant.


## Features

- Full support for ESPHome native API protocol, including encryption. The crate can be used for Server and Client implementations.
- [ ] Support for multiple ESPHome versions via feature flags (not yet implemented)


## Usage

`cargo add esphome_native_api`

Look at the [examples folder](./examples/) for reference implementations, e.g. [encrypted_server.rs](./examples/encrypted_server.rs). 

> #### Version Compatibility
> This crate only supports one ESPHome protocol version (marked by the default feature flag). 
>
> If you only need the Proto Messages you can install the crate with the feature flags enabled for the version you plan to use. 
> Example: 
> ```toml
> [dependencies]
> esphome-native-api = { version = "0.0.0", features = ["version_2025_12_1"] }
> ```


### Basic Example

```rust,no_run
use esphome_native_api::esphomeapi::EspHomeApi;
use tokio::net::TcpStream;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to an ESPHome device
    let stream = TcpStream::connect("192.168.1.100:6053").await?;
    
    // Create API instance
    let mut api = EspHomeApi::builder()
        .name("my-client".to_string())
        .build();
    
    // Start communication
    let (tx, mut rx) = api.start(stream).await?;
    
    // Process messages
    while let Ok(message) = rx.recv().await {
        println!("Received: {:?}", message);
    }
    
    Ok(())
}
```

### Using the Server API

The `EspHomeServer` provides a higher-level abstraction that manages entity keys internally (work in progress):

```rust,no_run
use esphome_native_api::esphomeserver::EspHomeServer;
use tokio::net::TcpStream;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = TcpStream::connect("192.168.1.100:6053").await?;
    
    let mut server = EspHomeServer::builder()
        .name("my-server".to_string())
        .build();
    
    let (tx, mut rx) = server.start(stream).await?;
    
    // Handle incoming messages
    while let Ok(message) = rx.recv().await {
        // Process message
    }
    
    Ok(())
}
```

## Trivia

While reverse engineering the "missing" documentation of the API was reconstructed: [https://ubihome.github.io/esphome-native-api/native_api/](https://ubihome.github.io/esphome-native-api/native_api/)
