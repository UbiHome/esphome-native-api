use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use log::debug;
use noise_protocol::CipherState;
use noise_rust_crypto::ChaCha20Poly1305;

use crate::error::FrameError;
use crate::parser;
pub use parser::ProtoMessage;

/// Bytes an encrypted frame adds around the protobuf payload: the 4 byte
/// message header and the 16 byte AEAD tag.
const ENCRYPTION_OVERHEAD: usize = 4 + 16;

/// Content of the `ServerHello` frame: the chosen protocol (`1`), the device
/// name and optionally its MAC address, each null terminated.
pub(crate) fn generate_server_hello_frame(name: &str, mac: Option<&str>) -> Vec<u8> {
    let mut message_server_hello: Vec<u8> = Vec::new();

    message_server_hello.push(1);
    message_server_hello.extend(name.as_bytes());
    if let Some(mac) = mac {
        message_server_hello.extend(b"\0");
        message_server_hello.extend(mac.as_bytes());
    }
    message_server_hello.extend(b"\0");

    message_server_hello
}

pub(crate) fn packet_to_message(
    buffer: &[u8],
    cipher_decrypt: &mut CipherState<ChaCha20Poly1305>,
) -> Result<ProtoMessage, FrameError> {
    let decrypted_message_frame = cipher_decrypt
        .decrypt_vec(buffer)
        .map_err(|_| FrameError::Decrypt)?;

    if decrypted_message_frame.len() < 4 {
        return Err(FrameError::Malformed(
            "encrypted frame shorter than header".to_string(),
        ));
    }

    let message_type =
        u16::from_be_bytes([decrypted_message_frame[0], decrypted_message_frame[1]]) as usize;
    let packet_content = &decrypted_message_frame[4..];
    debug!("Message type: {}", message_type);
    debug!("Message: {:?}", packet_content);

    parser::parse_proto_message(message_type, packet_content)
}

/// Encodes and encrypts `message`.
///
/// The size is checked against `max_frame_length` (and the `u16` length field
/// of encrypted frames) *before* encrypting: a message that is rejected must
/// not advance the cipher's nonce, or the peer could not decrypt anything sent
/// afterwards.
pub(crate) fn message_to_packet(
    message: &ProtoMessage,
    cipher_encrypt: &mut CipherState<ChaCha20Poly1305>,
    max_frame_length: usize,
) -> Result<Vec<u8>, FrameError> {
    let response_content =
        parser::proto_to_vec(message).map_err(|e| FrameError::Malformed(e.to_string()))?;
    let message_type =
        parser::message_to_num(message).map_err(|e| FrameError::Malformed(e.to_string()))? as u16;
    let frame_length = response_content.len() + ENCRYPTION_OVERHEAD;
    if frame_length > max_frame_length.min(u16::MAX as usize) {
        return Err(FrameError::Malformed(format!(
            "Frame of length {} is too large.",
            frame_length
        )));
    }

    let mut unencrypted_message_frame: Vec<u8> = Vec::with_capacity(4 + response_content.len());
    unencrypted_message_frame.extend_from_slice(&message_type.to_be_bytes());
    unencrypted_message_frame.extend_from_slice(&(response_content.len() as u16).to_be_bytes());
    unencrypted_message_frame.extend_from_slice(&response_content);
    Ok(cipher_encrypt.encrypt_vec(&unencrypted_message_frame))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use test_log::test;

    use crate::proto;

    use super::*;

    #[test]
    fn test_message_to_packet() {
        let hello_message = ProtoMessage::HelloResponse(proto::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server".to_string(),
        });
        let key: [u8; 32] = [0; 32];
        let mut cipher = CipherState::<ChaCha20Poly1305>::new(&key, 1);
        let bytes = message_to_packet(&hello_message, &mut cipher, usize::MAX).unwrap();
        let expected_bytes: Vec<u8> = vec![
            // Encrypted message content
            83, 7, 229, 250, 66, 254, 9, 179, 47, 152, 53, 33, 20, 42, 219, 183, 37, 236, 193, 141,
            151, 211, 72, 91, 58, 43, 66, 142, 231, 254, 199, 68, 238, 115, 218, 97, 216, 136, 154,
            178, 100, 72, 12, 2, 175, 160, 139, 112, 115, 123,
        ];
        assert_eq!(bytes, expected_bytes);
    }

    #[test]
    fn test_packet_to_message() {
        let encrypted_packet: Vec<u8> = vec![
            // Encrypted message content
            83, 7, 229, 250, 66, 254, 9, 179, 47, 152, 53, 33, 20, 42, 219, 183, 37, 236, 193, 141,
            151, 211, 72, 91, 58, 43, 66, 142, 231, 254, 199, 68, 238, 115, 218, 97, 216, 136, 154,
            178, 100, 72, 12, 2, 175, 160, 139, 112, 115, 123,
        ];
        let key: [u8; 32] = [0; 32];
        let mut cipher = CipherState::<ChaCha20Poly1305>::new(&key, 1);

        let message = packet_to_message(&encrypted_packet, &mut cipher).unwrap();

        match message {
            ProtoMessage::HelloResponse(msg) => {
                assert_eq!(msg.api_version_major, 1);
                assert_eq!(msg.api_version_minor, 1);
                assert_eq!(msg.server_info, "Test Server");
                assert_eq!(msg.name, "Test Server");
            }
            _ => panic!("Expected HelloResponse message"),
        }
    }

    #[test]
    fn test_server_hello_frame() {
        assert_eq!(
            generate_server_hello_frame("dev", None),
            vec![1, b'd', b'e', b'v', 0]
        );
        assert_eq!(
            generate_server_hello_frame("dev", Some("AB")),
            vec![1, b'd', b'e', b'v', 0, b'A', b'B', 0]
        );
    }

    #[test]
    fn test_round_trip() {
        let key: [u8; 32] = [7; 32];
        let mut encrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);
        let mut decrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);
        let message = ProtoMessage::PingRequest(proto::PingRequest {});

        let packet = message_to_packet(&message, &mut encrypt, usize::MAX).unwrap();
        // 4 byte header, empty payload, 16 byte AEAD tag
        assert_eq!(packet.len(), 20);
        assert!(matches!(
            packet_to_message(&packet, &mut decrypt),
            Ok(ProtoMessage::PingRequest(_))
        ));
    }

    #[test]
    fn test_tampered_packet_fails_to_decrypt() {
        let key: [u8; 32] = [7; 32];
        let mut encrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);
        let mut decrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);
        let message = ProtoMessage::PingRequest(proto::PingRequest {});

        let mut packet = message_to_packet(&message, &mut encrypt, usize::MAX).unwrap();
        packet[0] ^= 0xFF;
        assert!(matches!(
            packet_to_message(&packet, &mut decrypt),
            Err(FrameError::Decrypt)
        ));
    }

    #[test]
    fn test_decrypted_frame_shorter_than_header_is_malformed() {
        let key: [u8; 32] = [7; 32];
        let mut encrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);
        let mut decrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);

        let packet = encrypt.encrypt_vec(&[0, 1]);
        assert!(matches!(
            packet_to_message(&packet, &mut decrypt),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn test_oversized_message_is_rejected() {
        let key: [u8; 32] = [7; 32];
        let mut encrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);
        let message = ProtoMessage::HelloResponse(proto::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "x".repeat(70_000),
            name: "Test Server".to_string(),
        });

        assert!(matches!(
            message_to_packet(&message, &mut encrypt, usize::MAX),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn test_rejected_message_does_not_advance_the_nonce() {
        let key: [u8; 32] = [7; 32];
        let mut encrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);
        let mut decrypt = CipherState::<ChaCha20Poly1305>::new(&key, 0);
        let too_large = ProtoMessage::HelloResponse(proto::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "x".repeat(100),
            name: "Test Server".to_string(),
        });
        let ping = ProtoMessage::PingRequest(proto::PingRequest {});

        assert!(matches!(
            message_to_packet(&too_large, &mut encrypt, 64),
            Err(FrameError::Malformed(_))
        ));
        // A frame of exactly the maximum length is still fine.
        let packet = message_to_packet(&ping, &mut encrypt, 20).unwrap();
        assert!(matches!(
            packet_to_message(&packet, &mut decrypt),
            Ok(ProtoMessage::PingRequest(_))
        ));
    }
}
