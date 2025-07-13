pub mod parser;
pub mod proto;
pub mod esphomeapi;
pub mod frame;

pub use parser::ProtoMessage;
use prost::encode_length_delimiter;

pub fn to_packet_from_ref(obj: &ProtoMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response_content = parser::proto_to_vec(&obj)?;
    let message_type = parser::message_to_num(&obj)?;
    let zero: Vec<u8> = vec![0];
    let mut length: Vec<u8> = Vec::new();
    encode_length_delimiter(response_content.len(), &mut length).unwrap();
    let message_bit: Vec<u8> = vec![message_type];

    let answer_buf: Vec<u8> = [zero, length, message_bit, response_content].concat();
    Ok(answer_buf)
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
        let bytes = to_packet_from_ref(&hello_message).unwrap();
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
    fn hello_message_overall_length_varint() {
        // Test that varint length encoding works correctly for long strings

        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_6_3::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very lon String".to_string(),
        });
        let bytes = to_packet_from_ref(&hello_message).unwrap();
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
        let bytes = to_packet_from_ref(&hello_message).unwrap();
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
        let bytes = to_packet_from_ref(&hello_message).unwrap();
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