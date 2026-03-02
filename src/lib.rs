#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod proto;

pub mod esphomeapi;
pub mod esphomeserver;
pub mod frame;
mod packet_plaintext;
pub mod parser;
mod packet_encrypted;

pub mod hash;