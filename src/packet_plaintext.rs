use crate::parser;
pub use crate::parser::ProtoMessage;
use log::debug;

pub fn packet_to_message(buffer: &[u8]) -> Result<ProtoMessage, Box<dyn std::error::Error>> {
    let message_type = buffer[0] as usize;
    let packet_content = &buffer[1..];
    debug!("Message type: {}", message_type);
    debug!("Message: {:02X?}", packet_content);
    Ok(parser::parse_proto_message(message_type, &packet_content).unwrap())
}

pub fn message_to_packet(message: &ProtoMessage) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response_content = parser::proto_to_vec(&message)?;
    let message_type = parser::message_to_num(&message)?;
    let message_bit: Vec<u8> = vec![message_type];

    Ok([message_bit, response_content].concat())
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use crate::proto::version_2025_12_1::HelloRequest;

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
