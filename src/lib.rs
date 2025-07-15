pub mod parser;
pub mod proto;
pub mod esphomeapi;
mod frame;
mod packet_plaintext;
mod packet_encrypted;

use noise_protocol::CipherState;
use noise_rust_crypto::ChaCha20Poly1305;
pub use parser::ProtoMessage;

use crate::{frame::construct_frame, packet_plaintext::message_to_packet};

pub fn to_unencrypted_frame(obj: &ProtoMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let packet = message_to_packet(obj)?;

    Ok(construct_frame(&packet, false)?)
}

pub fn to_encrypted_frame(obj: &ProtoMessage, cipher_encrypt: &mut CipherState<ChaCha20Poly1305>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let packet = packet_encrypted::message_to_packet(obj, cipher_encrypt)?;
    Ok(construct_frame(&packet, true)?)

    
    
    
    
    
    // let response_content = parser::proto_to_vec(&obj).unwrap().to_vec();

    // let message_type = (parser::message_to_num(&obj).unwrap() as u16).to_be_bytes().to_vec();
    // let message_length = (response_content.len() as u16).to_be_bytes().to_vec();

    // let unencrypted_message_frame: Vec<u8> = [message_type, message_length, response_content].concat();
    // let encrypted_message_frame = cipher_encrypt.encrypt_vec(&unencrypted_message_frame);


    // let message_length: Vec<u8> = (encrypted_message_frame.len() as u16).to_be_bytes().to_vec();
    
    // let encrypted_identifier = vec![1];
    
    // let answer_buf: Vec<u8> = [encrypted_identifier, message_length, encrypted_message_frame].concat();
    // Ok(answer_buf)
}


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn hello_message_short() {
        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_6_3::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server".to_string(),
        });
        let bytes = to_unencrypted_frame(&hello_message).unwrap();
        let expected_bytes: Vec<u8> = vec![
            0, // Zero byte
            30, // Length of the message
            2, // Message type for HelloResponse
            8, // Field descriptor: api_version_major
            1, // API version major
            16, // Field descriptor: api_version_minor
            1, // API version minor
            26, // Field descriptor: server_info
            11, // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v',b'e', b'r',
            34, // Field descriptor: name
            11, // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v', b'e', b'r',
        ];
        assert_eq!(bytes, expected_bytes);
    }

  #[test]
    fn hello_message_short_encrypted() {
        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_6_3::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server".to_string(),
        });
        let key: [u8; 32] = [0; 32];
        let mut cipher = CipherState::<ChaCha20Poly1305>::new(&key, 1);
        let bytes = to_encrypted_frame(&hello_message, &mut cipher).unwrap();
        let expected_bytes: Vec<u8> = vec![
            1, // Preamble: encrypted
            0, // Length
            50, // Length
            // Encrypted message content
            83, 7, 229, 250, 66, 254, 9, 179, 47, 152, 53, 33, 20, 42, 219, 183, 37, 236, 193, 141, 151, 211, 72, 91, 58, 43, 66, 142, 231, 254, 199, 68, 238, 115, 218, 97, 216, 136, 154, 178, 100, 72, 12, 2, 175, 160, 139, 112, 115, 123
        ];
        assert_eq!(bytes, expected_bytes);
    }


    #[test]
    fn hello_message_overall_length_varint() {
        // Test that varint length encoding works correctly for long strings

        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_6_3::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very lon String".to_string(),
        });
        let bytes = to_unencrypted_frame(&hello_message).unwrap();
        let expected_bytes: Vec<u8> = vec![
            0, // Zero byte
            128, // Length of the message
            1, // Length of the message
            2, // Message type for HelloResponse
            8, // Field descriptor: api_version_major
            1, // API version major
            16, // Field descriptor: api_version_minor
            1, // API version minor
            26, // Field descriptor: server_info
            11, // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v',b'e', b'r',
            34, // Field descriptor: name
            109, // Field length
            b'T', b'e', b's', b't', b' ',
        ];
        assert_eq!(bytes[0..23], expected_bytes[0..23]);
    }

    #[test]
    fn hello_message_overall_length_varint_longer() {
        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_6_3::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very very very v very long String".to_string(),
        });
        let bytes = to_unencrypted_frame(&hello_message).unwrap();
        let expected_bytes: Vec<u8> = vec![
            0, // Zero byte
            146, // Length of the message
            1, // Length of the message
            2, // Message type for HelloResponse
            8, // Field descriptor: api_version_major
            1, // API version major
            16, // Field descriptor: api_version_minor
            1, // API version minor
            26, // Field descriptor: server_info
            11, // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v',b'e', b'r',
            34, // Field descriptor: name
            127, // Field length
            b'T', b'e', b's', b't', b' ',
        ];
        assert_eq!(bytes[0..23], expected_bytes[0..23]);
    }

    #[test]
    fn hello_message_longer() {
        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_6_3::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very very very very very long String".to_string(),
        });
        let bytes = to_unencrypted_frame(&hello_message).unwrap();
        let expected_bytes: Vec<u8> = vec![
            0, // Zero byte
            150, // Length of the message
            1, // Length of the message
            2, // Message type for HelloResponse
            8, // Field descriptor: api_version_major
            1, // API version major
            16, // Field descriptor: api_version_minor
            1, // API version minor
            26, // Field descriptor: server_info
            11, // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v',b'e', b'r',
            34, // Field descriptor: name
            130, // Field length
            1, // Field
            b'T', b'e', b's', b't', b' '
        ];
        assert_eq!(bytes[0..24], expected_bytes[0..24]);
    }
}