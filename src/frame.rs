use byteorder::BigEndian;
use byteorder::ByteOrder;
use log::debug;
use log::info;
use prost::decode_length_delimiter;
use prost::encode_length_delimiter;

use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;
use tokio_util::codec::Encoder;

pub struct FrameCodec {
    encrypted: bool,
    max_length: usize,
}

impl FrameCodec {
    pub fn new(encrypted: bool) -> Self {
        FrameCodec {
            encrypted,
            max_length: 8 * 1024 * 1024,
        }
    }
}

impl Decoder for FrameCodec {
    type Item = Vec<u8>;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Check if var uint is completely read

        if src.len() < 1 {
            // Not enough data t0o read length marker.
            return Ok(None);
        }

        // Check encryption byte
        let mut varint_length = 1;
        let length: usize;
        if self.encrypted {
            if src[0] != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected encrypted frame, but got plaintext frame.",
                ));
            }
            varint_length = 2;
            if src.len() < varint_length + 1 {
                // Not enough data to read length marker.
                return Ok(None);
            }
            info!("length bytes: {:?}", &src[1..3]);
            length = BigEndian::read_u16(&src[1..3]) as usize;
        } else {
            if src[0] != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected plaintext frame, but got encrypted frame.",
                ));
            }
            loop {
                if src.len() < varint_length + 1 {
                    // Not enough data to read length marker.
                    return Ok(None);
                }
                if src[varint_length] & (1 << 7) == 0 {
                    break;
                }
                varint_length += 1;
                if varint_length > 4 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Varint length marker is too long.",
                    ));
                }
            }
            info!("Varint cursor at: {}", varint_length);
            info!("Varint bytes: {:?}", &src[1..varint_length + 1]);
            // Read length marker.
            length = decode_length_delimiter(&src[1..varint_length + 1]).unwrap() as usize + 1; // Add one extra byte for the packet type (which is not included in the frame length).
        }
        info!("Frame length: {}", &length);

        // info!("Buffer: {:?}", src);

        // Already reserve space when the length is known
        if src.capacity() < 1 + varint_length + length {
            // The full string has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            src.reserve(1 + varint_length + length - src.len());
        }

        info!("Buffer length: {}", src.len());

        if src.len() < 1 + varint_length + length {
            // The full string has not yet arrived.
            info!("Not enough data yet.");
            return Ok(None);
        }

        // Get complete data from buffer
        let data_start = varint_length + 1;
        let data = src[data_start..data_start + length].to_vec();
        let new_cursor = 1 + varint_length + length;

        // Use advance to modify src such that it no longer contains this frame.
        info!("Advancing cursor to: {}", new_cursor);
        src.advance(new_cursor);

        // Convert the data to a string, or fail if it is not valid utf-8.
        return Ok(Some(data));
    }
}

impl Encoder<Vec<u8>> for FrameCodec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Don't send a string if it is longer than the other end will
        // accept.
        let length = if self.encrypted {
            item.len()
        } else {
            // For plaintext, the length does not include the message type byte
            item.len() - 1
        };

        if item.len() > self.max_length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", item.len()),
            ));
        }

        let len_slice;
        if self.encrypted {
            len_slice = (length as u16).to_be_bytes().to_vec();
        } else {
            let mut length_buffer: Vec<u8> = Vec::new();
            encode_length_delimiter(length, &mut length_buffer).unwrap();
            len_slice = length_buffer;
        }

        // Reserve space in the buffer.
        dst.reserve(len_slice.len() + item.len()); // Length bytes + string bytes (not length!)

        // Write the length and string to the buffer.
        if self.encrypted {
            // Encrypted identifier
            dst.extend_from_slice(vec![1].as_slice());
        } else {
            // Plaintext identifier
            dst.extend_from_slice(vec![0].as_slice());
        }

        dst.extend_from_slice(&len_slice);
        dst.extend_from_slice(item.as_slice());
        debug!("Sending server hello: {:02X?}", &dst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures::sink::SinkExt;
    use noise_protocol::CipherState;
    use noise_rust_crypto::ChaCha20Poly1305;
    use std::io::Cursor;
    use tokio_stream::StreamExt;

    use tokio_util::codec::{FramedRead, FramedWrite};

    #[tokio::test]
    #[test_log::test]
    async fn decode_frame_size_1() {
        let message: Vec<u8> = vec![0, 1, 4, 3];
        let decoder = FrameCodec::new(false);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        let frame1 = reader.next().await.unwrap().unwrap();

        assert!(reader.next().await.is_none());
        assert_eq!(frame1, vec![4, 3]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn decode_frame_size_0() {
        let message: Vec<u8> = vec![0, 0, 1];
        let decoder = FrameCodec::new(false);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        let frame1 = reader.next().await.unwrap().unwrap();

        assert!(reader.next().await.is_none());
        assert_eq!(frame1, vec![1]);
    }

    #[tokio::test]
    async fn decode_frame_encrypted() {
        let message: Vec<u8> = vec![1, 0, 1, 3];
        let decoder = FrameCodec::new(true);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        let frame1 = reader.next().await.unwrap().unwrap();

        assert!(reader.next().await.is_none());
        assert_eq!(frame1, vec![3]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn decode_frame_plaintext() {
        let message: Vec<u8> = vec![
            0x00, 0x13, 0x01, 0x0a, 0x0d, 0x61, 0x69, 0x6f, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d,
            0x65, 0x61, 0x70, 0x69, 0x10, 0x01, 0x18, 0x0a,
        ];
        let decoder = FrameCodec::new(false);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        let frame1 = reader.next().await.unwrap().unwrap();

        assert_eq!(
            frame1,
            vec![
                0x01, 0x0a, 0x0d, 0x61, 0x69, 0x6f, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d, 0x65, 0x61,
                0x70, 0x69, 0x10, 0x01, 0x18, 0x0a,
            ]
        );
        assert!(reader.next().await.is_none());
    }

    #[tokio::test]
    #[test_log::test]
    async fn decode_frame_multiple() {
        let message: Vec<u8> = vec![0, 5, 1, 4, 3, 2, 1, 0, 0, 2, b'a', b'b', b'c'];
        let decoder = FrameCodec::new(false);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        let frame1 = reader.next().await.unwrap().unwrap();
        let frame2 = reader.next().await.unwrap().unwrap();

        assert!(reader.next().await.is_none());
        assert_eq!(frame1, vec![1, 4, 3, 2, 1, 0]);
        assert_eq!(frame2, vec![b'a', b'b', b'c']);
    }

    #[tokio::test]
    #[test_log::test]
    async fn decode_frame_varint_2() {
        let message = [vec![0, 148, 2], vec![0; 277]].concat();
        let decoder = FrameCodec::new(false);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        let frame1 = reader.next().await.unwrap().unwrap();

        assert!(reader.next().await.is_none());
        assert_eq!(frame1, vec![0; 277]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn decode_frame_varint_3() {
        let message = [vec![0, 128, 128, 1], vec![0; 16385]].concat();
        let decoder = FrameCodec::new(false);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        let frame1 = reader.next().await.unwrap().unwrap();

        assert!(reader.next().await.is_none());
        assert_eq!(frame1, vec![0; 16385]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn decode_frame_varint_4() {
        let message = [vec![0, 128, 128, 128, 1], vec![0; 2097153]].concat();
        let decoder = FrameCodec::new(false);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        let frame1 = reader.next().await.unwrap().unwrap();

        assert!(reader.next().await.is_none());
        assert_eq!(frame1, vec![0; 2097153]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn decode_frame_varint_5() {
        let message = [vec![0, 128, 128, 128, 128, 1], vec![0; 268435457]].concat();
        let decoder = FrameCodec::new(false);

        let mut reader = FramedRead::new(Cursor::new(message), decoder);

        assert!(reader.next().await.unwrap().is_err());
    }

    use crate::{packet_encrypted, packet_plaintext, parser::ProtoMessage, proto};

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[tokio::test]
    #[test_log::test]
    async fn hello_message_short() {
        let hello_message = ProtoMessage::HelloResponse(proto::version_2025_12_1::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server".to_string(),
        });
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FramedWrite::new(buffer, encoder);
        writer
            .send(packet_plaintext::message_to_packet(&hello_message).unwrap())
            .await
            .unwrap();

        // let bytes = to_unencrypted_frame(&hello_message).unwrap();
        let expected_bytes: Vec<u8> = vec![
            0,  // Zero byte
            30, // Length of the message
            2,  // Message type for HelloResponse
            8,  // Field descriptor: api_version_major
            1,  // API version major
            16, // Field descriptor: api_version_minor
            1,  // API version minor
            26, // Field descriptor: server_info
            11, // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v', b'e', b'r',
            34, // Field descriptor: name
            11, // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v', b'e', b'r',
        ];

        assert_eq!(writer.get_ref().as_slice(), expected_bytes);
    }

    #[tokio::test]
    #[test_log::test]
    async fn hello_message_short_encrypted() {
        // Arrange
        let hello_message = ProtoMessage::HelloResponse(proto::version_2025_12_1::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server".to_string(),
        });
        let key: [u8; 32] = [0; 32];
        let mut cipher = CipherState::<ChaCha20Poly1305>::new(&key, 1);
        let encoder = FrameCodec::new(true);
        let buffer = Vec::new();
        let mut writer = FramedWrite::new(buffer, encoder);

        // Act
        writer
            .send(packet_encrypted::message_to_packet(&hello_message, &mut cipher).unwrap())
            .await
            .unwrap();

        // Assert
        let expected_bytes: Vec<u8> = vec![
            1,  // Preamble: encrypted
            0,  // Length
            50, // Length
            // Encrypted message content
            83, 7, 229, 250, 66, 254, 9, 179, 47, 152, 53, 33, 20, 42, 219, 183, 37, 236, 193, 141,
            151, 211, 72, 91, 58, 43, 66, 142, 231, 254, 199, 68, 238, 115, 218, 97, 216, 136, 154,
            178, 100, 72, 12, 2, 175, 160, 139, 112, 115, 123,
        ];
        assert_eq!(writer.get_ref().as_slice(), expected_bytes);
    }

    #[tokio::test]
    #[test_log::test]
    async fn hello_message_overall_length_varint() {
        // Test that varint length encoding works correctly for long strings

        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_12_1::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very lon String".to_string(),
        });
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FramedWrite::new(buffer, encoder);
        writer
            .send(packet_plaintext::message_to_packet(&hello_message).unwrap())
            .await
            .unwrap();

        let expected_bytes: Vec<u8> = vec![
            0,   // Zero byte
            128, // Length of the message
            1,   // Length of the message
            2,   // Message type for HelloResponse
            8,   // Field descriptor: api_version_major
            1,   // API version major
            16,  // Field descriptor: api_version_minor
            1,   // API version minor
            26,  // Field descriptor: server_info
            11,  // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v', b'e', b'r',
            34,  // Field descriptor: name
            109, // Field length
            b'T', b'e', b's', b't', b' ',
        ];
        assert_eq!(writer.get_ref().as_slice()[0..23], expected_bytes[0..23]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn hello_message_overall_length_varint_longer() {
        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_12_1::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very very very v very long String".to_string(),
        });
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FramedWrite::new(buffer, encoder);
        writer
            .send(packet_plaintext::message_to_packet(&hello_message).unwrap())
            .await
            .unwrap();
        let expected_bytes: Vec<u8> = vec![
            0,   // Zero byte
            146, // Length of the message
            1,   // Length of the message
            2,   // Message type for HelloResponse
            8,   // Field descriptor: api_version_major
            1,   // API version major
            16,  // Field descriptor: api_version_minor
            1,   // API version minor
            26,  // Field descriptor: server_info
            11,  // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v', b'e', b'r',
            34,  // Field descriptor: name
            127, // Field length
            b'T', b'e', b's', b't', b' ',
        ];
        assert_eq!(writer.get_ref().as_slice()[0..23], expected_bytes[0..23]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn hello_message_longer() {
        let hello_message: ProtoMessage = ProtoMessage::HelloResponse(
            proto::version_2025_12_1::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very very very very very long String".to_string(),
        });
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FramedWrite::new(buffer, encoder);
        writer
            .send(packet_plaintext::message_to_packet(&hello_message).unwrap())
            .await
            .unwrap();
        let expected_bytes: Vec<u8> = vec![
            0,   // Zero byte
            150, // Length of the message
            1,   // Length of the message
            2,   // Message type for HelloResponse
            8,   // Field descriptor: api_version_major
            1,   // API version major
            16,  // Field descriptor: api_version_minor
            1,   // API version minor
            26,  // Field descriptor: server_info
            11,  // Field length
            b'T', b'e', b's', b't', b' ', b'S', b'e', b'r', b'v', b'e', b'r',
            34,  // Field descriptor: name
            130, // Field length
            1,   // Field
            b'T', b'e', b's', b't', b' ',
        ];
        assert_eq!(writer.get_ref().as_slice()[0..24], expected_bytes[0..24]);
    }
    #[tokio::test]
    #[test_log::test]
    async fn construct_frame_plaintext() {
        let bytes = vec![8; 5];
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FramedWrite::new(buffer, encoder);
        writer.send(bytes).await.unwrap();
        assert_eq!(writer.get_ref().as_slice()[0..3], vec![0, 4, 8]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn construct_frame_plaintext_long() {
        let bytes = vec![8; 131];
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FramedWrite::new(buffer, encoder);
        writer.send(bytes).await.unwrap();
        assert_eq!(writer.get_ref().as_slice()[0..4], vec![0, 130, 1, 8]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn construct_frame_encrypted() {
        let bytes = vec![8; 5];
        let encoder = FrameCodec::new(true);
        let buffer = Vec::new();
        let mut writer = FramedWrite::new(buffer, encoder);

        // Act
        writer.send(bytes).await.unwrap();
        assert_eq!(writer.get_ref().as_slice()[0..4], vec![1, 0, 5, 8]);
    }

    #[tokio::test]
    #[test_log::test]
    async fn construct_frame_encrypted_long() {
        let bytes = vec![8; 128];

        let encoder = FrameCodec::new(true);
        let buffer = Vec::new();
        let mut writer = FramedWrite::new(buffer, encoder);

        // Act
        writer.send(bytes).await.unwrap();
        assert_eq!(writer.get_ref().as_slice()[0..4], vec![1, 0, 128, 8]);
    }
}
