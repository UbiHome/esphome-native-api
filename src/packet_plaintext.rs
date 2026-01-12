//! Plaintext packet encoding and decoding.
//!
//! This module provides functions for converting between [`ProtoMessage`] enums
//! and binary packet format for plaintext (unencrypted) communication.
//!
//! # Packet Format
//!
//! Plaintext packets consist of:
//! - 1 byte: Message type identifier
//! - N bytes: Protocol buffer encoded message content
//!
//! # Examples
//!
//! ```rust
//! use esphome_native_api::packet_plaintext::{message_to_packet, packet_to_message};
//! use esphome_native_api::parser::ProtoMessage;
//! use esphome_native_api::proto::PingRequest;
//!
//! // Convert message to packet
//! let message = ProtoMessage::PingRequest(PingRequest {});
//! let packet = message_to_packet(&message).unwrap();
//!
//! // Convert packet back to message
//! let decoded = packet_to_message(&packet).unwrap();
//! ```

use log::debug;

use crate::parser;
pub use parser::ProtoMessage;

/// Converts a binary packet to a [`ProtoMessage`].
///
/// Parses a plaintext packet by extracting the message type from the first byte
/// and then decoding the remaining bytes as a protocol buffer message.
///
/// # Arguments
///
/// * `buffer` - The binary packet data, including the message type byte
///
/// # Returns
///
/// Returns the decoded [`ProtoMessage`] on success.
///
/// # Errors
///
/// Returns an error if:
/// - The message type is unknown
/// - The protocol buffer data is invalid
pub fn packet_to_message(buffer: &[u8]) -> Result<ProtoMessage, Box<dyn std::error::Error>> {
    let message_type = buffer[0] as usize;
    let packet_content = &buffer[1..];
    debug!("Message type: {}", message_type);
    debug!("Message: {:02X?}", packet_content);
    Ok(parser::parse_proto_message(message_type, packet_content).unwrap())
}

/// Converts a [`ProtoMessage`] to a binary packet.
///
/// Encodes a message by first encoding it as a protocol buffer, then prepending
/// the message type identifier byte.
///
/// # Arguments
///
/// * `message` - The message to encode
///
/// # Returns
///
/// Returns the binary packet data on success.
///
/// # Errors
///
/// Returns an error if the protocol buffer encoding fails.
pub fn message_to_packet(message: &ProtoMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response_content = parser::proto_to_vec(message)?;
    let message_type = parser::message_to_num(message)?;
    let message_bit: Vec<u8> = vec![message_type];

    Ok([message_bit, response_content].concat())
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use crate::proto::HelloRequest;

    use super::*;

    #[test]
    fn hello_message_short_parse() {
        let bytes: Vec<u8> = vec![
            0x01, 0x0a, 0x0d, 0x61, 0x69, 0x6f, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d, 0x65, 0x61,
            0x70, 0x69, 0x10, 0x01, 0x18, 0x0a,
        ];

        let message = packet_to_message(&bytes).unwrap();
        match message {
            ProtoMessage::HelloRequest(msg) => {
                assert_eq!(msg.api_version_major, 1);
                assert_eq!(msg.api_version_minor, 10);
                assert_eq!(msg.client_info, "aioesphomeapi");
            }
            _ => panic!("Expected HelloRequest message"),
        }
    }

    #[test]
    fn hello_message_short_serialize() {
        let message = ProtoMessage::HelloRequest(HelloRequest {
            api_version_major: 1,
            api_version_minor: 10,
            client_info: "aioesphomeapi".to_string(),
        });
        let bytes = message_to_packet(&message).unwrap();

        assert_eq!(
            bytes,
            vec![
                1, 10, 13, 97, 105, 111, 101, 115, 112, 104, 111, 109, 101, 97, 112, 105, 16, 1,
                24, 10
            ]
        );
    }
}
