#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
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
