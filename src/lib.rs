#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod proto;

#[cfg(feature = "std")]
pub mod error;
#[cfg(feature = "std")]
pub use error::{DisconnectReason, Error, FrameError, HandshakeError};

#[cfg(feature = "std")]
pub mod connection;
#[cfg(feature = "std")]
pub use connection::Connection;

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

#[cfg(feature = "std")]
pub mod hash;