#![cfg_attr(not(feature = "std"), no_std)]
pub mod proto;

#[cfg(feature = "std")]
pub mod esphomeapi;
#[cfg(all(feature = "std", feature = "server"))]
pub mod esphomeserver;
#[cfg(feature = "std")]
mod frame;
#[cfg(feature = "std")]
pub mod messages;
#[cfg(feature = "std")]
mod packet_encrypted;
#[cfg(feature = "std")]
mod packet_plaintext;
