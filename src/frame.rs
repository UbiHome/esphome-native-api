//! Framing of the ESPHome native API byte stream.
//!
//! A frame starts with a preamble byte (`0` plaintext, `1` encrypted) followed
//! by the payload length (a varint for plaintext, a big endian `u16` for
//! encrypted frames) and the payload itself. This module is pure: it works on
//! byte slices and performs no I/O.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use log::trace;

use crate::error::FrameError;

/// Largest frame accepted or produced unless configured otherwise.
pub(crate) const DEFAULT_MAX_FRAME_LENGTH: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameCodec {
    encrypted: bool,
    max_length: usize,
}

impl FrameCodec {
    #[cfg(test)]
    pub fn new(encrypted: bool) -> Self {
        Self::with_max_length(encrypted, DEFAULT_MAX_FRAME_LENGTH)
    }

    pub fn with_max_length(encrypted: bool, max_length: usize) -> Self {
        FrameCodec {
            encrypted,
            max_length,
        }
    }

    /// Try to split one frame off the front of `src`.
    ///
    /// Returns `Ok(None)` when `src` does not hold a complete frame yet.
    /// Otherwise returns the frame's payload together with the total number of
    /// bytes the frame occupies in `src` (header included), which the caller
    /// has to discard before decoding the next frame.
    pub fn decode<'a>(&self, src: &'a [u8]) -> Result<Option<(&'a [u8], usize)>, FrameError> {
        let Some(&preamble) = src.first() else {
            // Not enough data to read the preamble.
            return Ok(None);
        };

        let header_length: usize;
        let length: usize;
        if self.encrypted {
            if preamble != 1 {
                return Err(FrameError::Malformed(
                    "Expected encrypted frame, but got plaintext frame.".to_string(),
                ));
            }
            header_length = 3;
            if src.len() < header_length {
                // Not enough data to read length marker.
                return Ok(None);
            }
            length = u16::from_be_bytes([src[1], src[2]]) as usize;
        } else {
            if preamble != 0 {
                return Err(FrameError::Malformed(
                    "Expected plaintext frame, but got encrypted frame.".to_string(),
                ));
            }
            // Read the varint length marker (at most 4 bytes).
            let mut cursor = 1;
            let mut value: usize = 0;
            loop {
                let Some(&byte) = src.get(cursor) else {
                    // Not enough data to read length marker.
                    return Ok(None);
                };
                value |= ((byte & 0x7F) as usize) << (7 * (cursor - 1));
                if byte & 0x80 == 0 {
                    break;
                }
                cursor += 1;
                if cursor > 4 {
                    return Err(FrameError::Malformed(
                        "Varint length marker is too long.".to_string(),
                    ));
                }
            }
            header_length = cursor + 1;
            // Add one extra byte for the packet type (which is not included in the frame length).
            length = value + 1;
        }
        trace!("Frame length: {}", length);

        if length > self.max_length {
            return Err(FrameError::Malformed(format!(
                "Frame of length {} is too large.",
                length
            )));
        }

        let frame_length = header_length + length;
        if src.len() < frame_length {
            // The full frame has not yet arrived.
            trace!("Not enough data yet.");
            return Ok(None);
        }

        let data = &src[header_length..frame_length];
        trace!("Received frame: {:02X?}", data);
        Ok(Some((data, frame_length)))
    }

    /// Append `item` to `dst` as one frame.
    ///
    /// For plaintext frames `item` has to start with the message type byte,
    /// which is not counted in the length marker.
    pub fn encode(&self, item: &[u8], dst: &mut Vec<u8>) -> Result<(), FrameError> {
        // Don't send a frame if it is longer than the other end will accept.
        if item.len() > self.max_length {
            return Err(FrameError::Malformed(format!(
                "Frame of length {} is too large.",
                item.len()
            )));
        }

        if self.encrypted {
            let length = u16::try_from(item.len()).map_err(|_| {
                FrameError::Malformed(format!(
                    "Frame of length {} does not fit into an encrypted frame.",
                    item.len()
                ))
            })?;
            dst.reserve(3 + item.len());
            // Encrypted identifier
            dst.push(1);
            dst.extend_from_slice(&length.to_be_bytes());
        } else {
            // For plaintext, the length does not include the message type byte
            let mut length = item.len().checked_sub(1).ok_or_else(|| {
                FrameError::Malformed("Plaintext frame is missing its message type.".to_string())
            })?;
            dst.reserve(6 + item.len());
            // Plaintext identifier
            dst.push(0);
            // Varint length marker
            loop {
                let byte = (length & 0x7F) as u8;
                length >>= 7;
                if length == 0 {
                    dst.push(byte);
                    break;
                }
                dst.push(byte | 0x80);
            }
        }

        dst.extend_from_slice(item);
        trace!("Sending frame: {:02X?}", dst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;
    use noise_protocol::CipherState;
    use noise_rust_crypto::ChaCha20Poly1305;

    /// Minimal stand-ins for a framed reader / writer, so the tests read like
    /// the transport code that drives the codec.
    struct FrameReader {
        codec: FrameCodec,
        buffer: Vec<u8>,
    }

    impl FrameReader {
        fn new(buffer: Vec<u8>, codec: FrameCodec) -> Self {
            Self { codec, buffer }
        }

        /// `None` once the buffer holds no further complete frame.
        fn next(&mut self) -> Option<Result<Vec<u8>, FrameError>> {
            match self.codec.decode(&self.buffer) {
                Ok(Some((frame, consumed))) => {
                    let frame = frame.to_vec();
                    self.buffer.drain(..consumed);
                    Some(Ok(frame))
                }
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        }
    }

    struct FrameWriter {
        codec: FrameCodec,
        buffer: Vec<u8>,
    }

    impl FrameWriter {
        fn new(buffer: Vec<u8>, codec: FrameCodec) -> Self {
            Self { codec, buffer }
        }

        fn send(&mut self, item: Vec<u8>) -> Result<(), FrameError> {
            self.codec.encode(&item, &mut self.buffer)
        }

        fn get_ref(&self) -> &Vec<u8> {
            &self.buffer
        }
    }

    #[test_log::test]
    fn decode_frame_size_1() {
        let message: Vec<u8> = vec![0, 1, 4, 3];
        let decoder = FrameCodec::new(false);

        let mut reader = FrameReader::new(message, decoder);

        let frame1 = reader.next().unwrap().unwrap();

        assert!(reader.next().is_none());
        assert_eq!(frame1, vec![4, 3]);
    }

    #[test_log::test]
    fn decode_frame_size_0() {
        let message: Vec<u8> = vec![0, 0, 1];
        let decoder = FrameCodec::new(false);

        let mut reader = FrameReader::new(message, decoder);

        let frame1 = reader.next().unwrap().unwrap();

        assert!(reader.next().is_none());
        assert_eq!(frame1, vec![1]);
    }

    #[test]
    fn decode_frame_encrypted() {
        let message: Vec<u8> = vec![1, 0, 1, 3];
        let decoder = FrameCodec::new(true);

        let mut reader = FrameReader::new(message, decoder);

        let frame1 = reader.next().unwrap().unwrap();

        assert!(reader.next().is_none());
        assert_eq!(frame1, vec![3]);
    }

    #[test_log::test]
    fn decode_frame_plaintext() {
        let message: Vec<u8> = vec![
            0x00, 0x13, 0x01, 0x0a, 0x0d, 0x61, 0x69, 0x6f, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d,
            0x65, 0x61, 0x70, 0x69, 0x10, 0x01, 0x18, 0x0a,
        ];
        let decoder = FrameCodec::new(false);

        let mut reader = FrameReader::new(message, decoder);

        let frame1 = reader.next().unwrap().unwrap();

        assert_eq!(
            frame1,
            vec![
                0x01, 0x0a, 0x0d, 0x61, 0x69, 0x6f, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d, 0x65, 0x61,
                0x70, 0x69, 0x10, 0x01, 0x18, 0x0a,
            ]
        );
        assert!(reader.next().is_none());
    }

    #[test_log::test]
    fn decode_frame_multiple() {
        let message: Vec<u8> = vec![0, 5, 1, 4, 3, 2, 1, 0, 0, 2, b'a', b'b', b'c'];
        let decoder = FrameCodec::new(false);

        let mut reader = FrameReader::new(message, decoder);

        let frame1 = reader.next().unwrap().unwrap();
        let frame2 = reader.next().unwrap().unwrap();

        assert!(reader.next().is_none());
        assert_eq!(frame1, vec![1, 4, 3, 2, 1, 0]);
        assert_eq!(frame2, vec![b'a', b'b', b'c']);
    }

    #[test_log::test]
    fn decode_frame_varint_2() {
        let message = [vec![0, 148, 2], vec![0; 277]].concat();
        let decoder = FrameCodec::new(false);

        let mut reader = FrameReader::new(message, decoder);

        let frame1 = reader.next().unwrap().unwrap();

        assert!(reader.next().is_none());
        assert_eq!(frame1, vec![0; 277]);
    }

    #[test_log::test]
    fn decode_frame_varint_3() {
        let message = [vec![0, 128, 128, 1], vec![0; 16385]].concat();
        let decoder = FrameCodec::new(false);

        let mut reader = FrameReader::new(message, decoder);

        let frame1 = reader.next().unwrap().unwrap();

        assert!(reader.next().is_none());
        assert_eq!(frame1, vec![0; 16385]);
    }

    #[test_log::test]
    fn decode_frame_varint_4() {
        let message = [vec![0, 128, 128, 128, 1], vec![0; 2097153]].concat();
        let decoder = FrameCodec::new(false);

        let mut reader = FrameReader::new(message, decoder);

        let frame1 = reader.next().unwrap().unwrap();

        assert!(reader.next().is_none());
        assert_eq!(frame1, vec![0; 2097153]);
    }

    #[test_log::test]
    fn decode_frame_varint_5() {
        let message = [vec![0, 128, 128, 128, 128, 1], vec![0; 64]].concat();
        let decoder = FrameCodec::new(false);

        let mut reader = FrameReader::new(message, decoder);

        assert!(reader.next().unwrap().is_err());
    }

    use crate::{packet_encrypted, packet_plaintext, parser::ProtoMessage, proto};

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test_log::test]
    fn hello_message_short() {
        let hello_message = ProtoMessage::HelloResponse(proto::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server".to_string(),
        });
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FrameWriter::new(buffer, encoder);
        writer
            .send(packet_plaintext::message_to_packet(&hello_message).unwrap())
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

    #[test_log::test]
    fn hello_message_short_encrypted() {
        // Arrange
        let hello_message = ProtoMessage::HelloResponse(proto::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server".to_string(),
        });
        let key: [u8; 32] = [0; 32];
        let mut cipher = CipherState::<ChaCha20Poly1305>::new(&key, 1);
        let encoder = FrameCodec::new(true);
        let buffer = Vec::new();
        let mut writer = FrameWriter::new(buffer, encoder);

        // Act
        writer
            .send(
                packet_encrypted::message_to_packet(&hello_message, &mut cipher, usize::MAX)
                    .unwrap(),
            )
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

    #[test_log::test]
    fn hello_message_overall_length_varint() {
        // Test that varint length encoding works correctly for long strings

        let hello_message = ProtoMessage::HelloResponse(
            proto::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very lon String".to_string(),
        });
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FrameWriter::new(buffer, encoder);
        writer
            .send(packet_plaintext::message_to_packet(&hello_message).unwrap())
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

    #[test_log::test]
    fn hello_message_overall_length_varint_longer() {
        let hello_message = ProtoMessage::HelloResponse(
            proto::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very very very v very long String".to_string(),
        });
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FrameWriter::new(buffer, encoder);
        writer
            .send(packet_plaintext::message_to_packet(&hello_message).unwrap())
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

    #[test_log::test]
    fn hello_message_longer() {
        let hello_message: ProtoMessage = ProtoMessage::HelloResponse(
            proto::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server with a very very very very very very very very very very very very very very very very very very very very long String".to_string(),
        });
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FrameWriter::new(buffer, encoder);
        writer
            .send(packet_plaintext::message_to_packet(&hello_message).unwrap())
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
    #[test_log::test]
    fn construct_frame_plaintext() {
        let bytes = vec![8; 5];
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FrameWriter::new(buffer, encoder);
        writer.send(bytes).unwrap();
        assert_eq!(writer.get_ref().as_slice()[0..3], vec![0, 4, 8]);
    }

    #[test_log::test]
    fn construct_frame_plaintext_long() {
        let bytes = vec![8; 131];
        let encoder = FrameCodec::new(false);
        let buffer = Vec::new();

        let mut writer = FrameWriter::new(buffer, encoder);
        writer.send(bytes).unwrap();
        assert_eq!(writer.get_ref().as_slice()[0..4], vec![0, 130, 1, 8]);
    }

    #[test_log::test]
    fn construct_frame_encrypted() {
        let bytes = vec![8; 5];
        let encoder = FrameCodec::new(true);
        let buffer = Vec::new();
        let mut writer = FrameWriter::new(buffer, encoder);

        // Act
        writer.send(bytes).unwrap();
        assert_eq!(writer.get_ref().as_slice()[0..4], vec![1, 0, 5, 8]);
    }

    #[test_log::test]
    fn construct_frame_encrypted_long() {
        let bytes = vec![8; 128];

        let encoder = FrameCodec::new(true);
        let buffer = Vec::new();
        let mut writer = FrameWriter::new(buffer, encoder);

        // Act
        writer.send(bytes).unwrap();
        assert_eq!(writer.get_ref().as_slice()[0..4], vec![1, 0, 128, 8]);
    }

    #[test]
    fn decode_needs_more_data_for_every_strict_prefix() {
        for (encrypted, message) in [
            (false, vec![0, 3, 1, 4, 3, 2]),
            (false, [vec![0, 148, 2], vec![7; 277]].concat()),
            (true, vec![1, 0, 3, 4, 3, 2]),
        ] {
            let codec = FrameCodec::new(encrypted);
            for end in 0..message.len() {
                assert_eq!(
                    codec.decode(&message[..end]).unwrap(),
                    None,
                    "prefix of {end} bytes must not decode"
                );
            }
            let (frame, consumed) = codec.decode(&message).unwrap().unwrap();
            assert_eq!(consumed, message.len());
            assert_eq!(frame, &message[message.len() - frame.len()..]);
        }
    }

    #[test]
    fn decode_leaves_following_bytes_untouched() {
        let message: Vec<u8> = vec![0, 0, 7, 0, 0];
        let (frame, consumed) = FrameCodec::new(false).decode(&message).unwrap().unwrap();
        assert_eq!(frame, [7]);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn decode_rejects_wrong_preamble() {
        assert!(matches!(
            FrameCodec::new(false).decode(&[1, 0, 1, 3]),
            Err(FrameError::Malformed(_))
        ));
        assert!(matches!(
            FrameCodec::new(true).decode(&[0, 1, 4, 3]),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn decode_rejects_frames_above_max_length() {
        // The limit is checked from the header alone, before the body arrived.
        assert!(matches!(
            FrameCodec::with_max_length(false, 16).decode(&[0, 16]),
            Err(FrameError::Malformed(_))
        ));
        assert!(matches!(
            FrameCodec::with_max_length(true, 16).decode(&[1, 0, 17]),
            Err(FrameError::Malformed(_))
        ));
        // A frame of exactly the maximum length is still fine.
        assert_eq!(
            FrameCodec::with_max_length(false, 16)
                .decode(&[0, 15])
                .unwrap(),
            None
        );
    }

    #[test]
    fn encode_rejects_frames_above_max_length() {
        let mut buffer = Vec::new();
        assert!(matches!(
            FrameCodec::with_max_length(false, 16).encode(&[0; 17], &mut buffer),
            Err(FrameError::Malformed(_))
        ));
        assert!(buffer.is_empty());
    }

    #[test]
    fn encode_rejects_empty_plaintext_frame() {
        let mut buffer = Vec::new();
        assert!(matches!(
            FrameCodec::new(false).encode(&[], &mut buffer),
            Err(FrameError::Malformed(_))
        ));
        assert!(buffer.is_empty());
    }

    #[test]
    fn encode_rejects_encrypted_frame_exceeding_u16_length() {
        let mut buffer = Vec::new();
        assert!(matches!(
            FrameCodec::new(true).encode(&vec![0; 65536], &mut buffer),
            Err(FrameError::Malformed(_))
        ));
        assert!(buffer.is_empty());
        assert!(
            FrameCodec::new(true)
                .encode(&vec![0; 65535], &mut buffer)
                .is_ok()
        );
    }

    #[test]
    fn encode_appends_to_existing_buffer() {
        let mut buffer = vec![9];
        FrameCodec::new(false).encode(&[5], &mut buffer).unwrap();
        FrameCodec::new(true).encode(&[5], &mut buffer).unwrap();
        assert_eq!(buffer, vec![9, 0, 0, 5, 1, 0, 1, 5]);
    }

    #[test]
    fn encode_decode_round_trip() {
        for encrypted in [false, true] {
            let codec = FrameCodec::new(encrypted);
            for length in [1, 2, 127, 128, 129, 16384, 16385, 65535] {
                let item = vec![0xAB; length];
                let mut buffer = Vec::new();
                codec.encode(&item, &mut buffer).unwrap();
                let (frame, consumed) = codec.decode(&buffer).unwrap().unwrap();
                assert_eq!(frame, item.as_slice());
                assert_eq!(consumed, buffer.len());
            }
        }
    }
}
