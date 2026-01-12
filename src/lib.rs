//! # esphome-native-api
//!
//! A Rust implementation of the [ESPHome native API](https://esphome.io/components/api.html)
//! for communicating with ESPHome devices.
//!
//! This crate provides a complete implementation of the ESPHome native API protocol,
//! supporting both encrypted and plaintext connections. It enables Rust applications
//! to interact with ESPHome-based IoT devices, allowing control and monitoring of
//! sensors, switches, lights, and other entities.
//!
//! ## Features
//!
//! - Full support for ESPHome native API protocol
//! - Encrypted connections using Noise protocol framework
//! - Plaintext connections for backward compatibility
//! - Asynchronous I/O with Tokio
//! - Protocol buffer message encoding/decoding with Prost
//! - Type-safe message handling
//! - Support for multiple ESPHome versions via feature flags
//!
//! ## Usage
//!
//! ### Basic Example
//!
//! ```rust,no_run
//! use esphome_native_api::esphomeapi::EspHomeApi;
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to an ESPHome device
//!     let stream = TcpStream::connect("192.168.1.100:6053").await?;
//!     
//!     // Create API instance
//!     let mut api = EspHomeApi::builder()
//!         .name("my-client")
//!         .build();
//!     
//!     // Start communication
//!     let (tx, mut rx) = api.start(stream).await?;
//!     
//!     // Process messages
//!     while let Ok(message) = rx.recv().await {
//!         println!("Received: {:?}", message);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### Using the Server API
//!
//! The `EspHomeServer` provides a higher-level abstraction that manages entity keys internally:
//!
//! ```rust,no_run
//! use esphome_native_api::esphomeserver::EspHomeServer;
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let stream = TcpStream::connect("192.168.1.100:6053").await?;
//!     
//!     let mut server = EspHomeServer::builder()
//!         .name("my-server")
//!         .build();
//!     
//!     let (tx, mut rx) = server.start(stream).await?;
//!     
//!     // Handle incoming messages
//!     while let Ok(message) = rx.recv().await {
//!         // Process message
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Version Compatibility
//!
//! This crate supports multiple ESPHome versions through feature flags. The default feature
//! enables support for the latest stable version. You can enable specific versions as needed:
//!
//! ```toml
//! [dependencies]
//! esphome-native-api = { version = "0.0.0", features = ["version_2025_12_1"] }
//! ```
//!
//! ## Module Overview
//!
//! - [`esphomeapi`]: Low-level API for direct protocol communication
//! - [`esphomeserver`]: High-level server abstraction with entity management
//! - [`parser`]: Protocol message parsing and serialization
//! - [`proto`]: Generated protocol buffer definitions
//!
//! ## Security
//!
//! This crate supports encrypted connections using the Noise protocol framework with
//! ChaCha20-Poly1305 encryption. Always prefer encrypted connections in production
//! environments by providing an encryption key.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod proto;

#[cfg(feature = "std")]
pub mod esphomeapi;
#[cfg(feature = "std")]
pub mod esphomeserver;
#[cfg(feature = "std")]
mod frame;
#[cfg(feature = "std")]
mod packet_plaintext;
#[cfg(feature = "std")]
pub mod parser;
// #[cfg(feature = "std")]
#[cfg(feature = "std")]
mod packet_encrypted;
