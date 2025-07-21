
use crate::parser;
pub use crate::parser::ProtoMessage;
use log::debug;
use prost::encode_length_delimiter;
use prost::decode_length_delimiter;
use std::fmt::Error;
use noise_protocol::HandshakeStateBuilder;
use noise_protocol::patterns::noise_nn_psk0;
use noise_rust_crypto::ChaCha20Poly1305;
use noise_rust_crypto::X25519;
use noise_rust_crypto::Sha256;


pub fn construct_frame(packet: &Vec<u8>, encrypted: bool) -> Result<Vec<u8>, String> {
    let preamble: Vec<u8>;
    let length: Vec<u8>;
    if encrypted {
        preamble = vec![1]; // Encrypted identifier
        // Packet length is the total length minus the 2 messageType bits (inside the packet)
        length = (packet.len() as u16).to_be_bytes().to_vec();

        // // Ensure the length is 2 bytes
        // match length.len() {
        //         1 => length.insert(0, 0),
        //         2 => {},
        //         _ => return Err("Length byte is invalid".to_string())
        // }
    } else {
        preamble = vec![0]; // Plaintext identifier
        let mut length_buffer: Vec<u8> = Vec::new();
        // Packet length is the total length minus the messageType bit (inside the packet)
        encode_length_delimiter(packet.len() - 1, &mut length_buffer).unwrap();
        length = length_buffer;
    }

    let answer_buf: Vec<u8> = [preamble, length, packet.clone()].concat();
    Ok(answer_buf)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_frame_plaintext() {
        let bytes = vec![8; 5];
        let frame = construct_frame(&bytes, false).unwrap();
        assert_eq!(frame[0..3], vec![0, 4, 8]);
    }

    #[test]
    fn construct_frame_plaintext_long() {
        let bytes = vec![8; 131];
        let frame = construct_frame(&bytes, false).unwrap();
        assert_eq!(frame[0..4], vec![0, 130, 1, 8]);
    }

    #[test]
    fn construct_frame_encrypted() {
        let bytes = vec![8; 5];

        let frame = construct_frame(&bytes, true).unwrap();
        assert_eq!(frame[0..4], vec![1, 0, 5, 8]);
    }

    
    #[test]
    fn construct_frame_encrypted_long() {
        let bytes = vec![8; 128];

        let frame = construct_frame(&bytes, true).unwrap();
        assert_eq!(frame[0..4], vec![1, 0, 128, 8]);
    }
}