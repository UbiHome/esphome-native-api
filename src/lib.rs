#![warn(missing_docs)]
#![cfg_attr(feature = "std", doc = include_str!("../README.md"))]
#![cfg_attr(
    not(feature = "std"),
    doc = "Rust implementation of the ESPHome native API (built without the `std` feature)."
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(feature = "protocol")]
extern crate alloc;

pub mod proto;

// Runtime-free protocol core. Everything in here only needs `core` + `alloc`.
#[cfg(feature = "protocol")]
pub mod error;
#[cfg(feature = "protocol")]
pub use error::{DisconnectReason, Error, FrameError, HandshakeError};

#[cfg(feature = "protocol")]
mod frame;
#[cfg(feature = "protocol")]
pub mod hash;
#[cfg(feature = "protocol")]
mod packet_encrypted;
#[cfg(feature = "protocol")]
mod packet_plaintext;
#[cfg(feature = "protocol")]
pub mod parser;
#[cfg(feature = "protocol")]
pub mod protocol;

// Tokio based front end.
#[cfg(feature = "std")]
pub mod connection;
#[cfg(feature = "std")]
pub use connection::Connection;

#[cfg(feature = "std")]
pub mod esphomeapi;
#[cfg(feature = "std")]
pub mod esphomeserver;
