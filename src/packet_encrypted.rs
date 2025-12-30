use byteorder::BigEndian;
use byteorder::ByteOrder;
use log::debug;
use noise_protocol::CipherState;
use noise_rust_crypto::ChaCha20Poly1305;

use crate::parser;
pub use parser::ProtoMessage;

pub fn generate_server_hello_frame(name: String, mac: Option<String>) -> Vec<u8> {
    let mut message_server_hello: Vec<u8> = Vec::new();

    let encryption_protocol: Vec<u8> = vec![1];
    message_server_hello.extend(encryption_protocol);
    message_server_hello.extend(name.as_bytes());
    if let Some(mac) = mac.clone() {
        message_server_hello.extend(b"\0");
        message_server_hello.extend(mac.as_bytes());
    }
    message_server_hello.extend(b"\0");

    message_server_hello
}

pub fn packet_to_message(
    buffer: &[u8],
    cipher_decrypt: &mut CipherState<ChaCha20Poly1305>,
) -> Result<ProtoMessage, Box<dyn std::error::Error>> {
    let decrypted_message_frame = cipher_decrypt.decrypt_vec(buffer).unwrap(); // "Error during decryption".to_string()

    let message_type = BigEndian::read_u16(&decrypted_message_frame[0..2]);
    debug!("Message type: {message_type}");

    let packet_content = &decrypted_message_frame[4..];
    debug!("Message: {packet_content:02X?}");

    let message_type = u8::try_from(message_type).unwrap(); // FIXME: Why is this a `u16`?
    Ok(ProtoMessage::parse(message_type, packet_content)?)
}

pub fn message_to_packet(
    message: &ProtoMessage,
    cipher_encrypt: &mut CipherState<ChaCha20Poly1305>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response_content = message.to_bytes();
    let message_type = (message.message_type() as u16).to_be_bytes().to_vec();
    let message_length = (response_content.len() as u16).to_be_bytes().to_vec();

    let unencrypted_message_frame: Vec<u8> =
        [message_type, message_length, response_content].concat();
    Ok(cipher_encrypt.encrypt_vec(&unencrypted_message_frame))
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
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
        let bytes = message_to_packet(&hello_message, &mut cipher).unwrap();
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
}
