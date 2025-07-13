
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

pub fn plaintext_frame_to_message(buffer: &[u8]) -> Result<ProtoMessage, Box<dyn std::error::Error>> {
    let message_type = buffer[0];
    let packet_content = &buffer[1..];
    debug!("Message type: {}", message_type);
    debug!("Message: {:?}", packet_content);
    Ok(parser::parse_proto_message(message_type, &packet_content).unwrap())
}

pub fn encrypted_frame_to_message(buffer: &[u8], key: &Vec<u8>) -> Result<ProtoMessage, String> {
    let length = decode_length_delimiter(&buffer[0..1]).unwrap();
    let encrypted_data = &buffer[1..];

    // let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    // let key = GenericArray::clone_from_slice(key);
    // let cipher = ChaCha20Poly1305::new(&key);
    // let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

    // // let ciphertext = cipher.encrypt(&nonce, encrypted_data.as_ref()).unwrap();
    // match cipher.decrypt(&nonce, encrypted_data) {
    //     Ok(plaintext) => {
    //         debug!("Decrypted plaintext: {:?}", plaintext);
            
    //         debug!("Decrypted plaintext: {:?}", plaintext);
    //         assert_eq!(&plaintext, b"plaintext message");

    //         let decrypted_buffer = vec![0];
    //         let message_type = decrypted_buffer[0];
            
    //         Ok(parser::parse_proto_message(message_type, &decrypted_buffer[1..]).unwrap())
    //     },
    //     Err(e) => {
    //         debug!("Decryption failed: {}", e);
    //         Err("Decryption failed".to_string())
    //     }
    // }
    panic!("Bla")

}


#[cfg(test)]
mod tests {
    use base64::prelude::*;
    use log::info;
    use noise_protocol::{patterns::{HandshakePattern, Token}, HandshakeState};
    use test_log::test;

    use crate::{proto, to_packet_from_ref};

    use super::*;

    #[test]
    fn hello_message_short() {
        let bytes = vec![0, 1, 10, 13, 97, 105, 111, 101, 115, 112, 104, 111, 109, 101, 97, 112, 105, 16, 1, 24, 10];

        let message = plaintext_frame_to_message(&bytes[1..]).unwrap();
        match message {
            ProtoMessage::HelloRequest(msg) => {
                assert_eq!(msg.api_version_major, 1);
                assert_eq!(msg.api_version_minor, 10);
                assert_eq!(msg.client_info, "aioesphomeapi");
            },
            _ => panic!("Expected HelloRequest message"),
        }
    }

    #[test]
    fn encrypted_hello() {
        let noise_psk: Vec<u8> = BASE64_STANDARD.decode(b"px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA=").unwrap();
        let encrypted_frame: Vec<u8> = vec![1, 0, 0, 1, 0, 49, 0, 199, 24, 95, 23, 27, 153, 215, 105, 84, 40, 64, 10, 217, 219, 186, 107, 64, 228, 100, 222, 74, 240, 121, 115, 166, 140, 58, 228, 237, 81, 66, 112, 157, 138, 162, 119, 146, 224, 35, 51, 229, 19, 11, 193, 62, 181, 72, 34];
        
        info!("Encrypted frame: {:?}", encrypted_frame);
        // let key = GenericArray::clone_from_slice(&noise_psk);

        // Similar to https://github.com/esphome/aioesphomeapi/blob/60bcd1698dd622aeac6f4b5ec448bab0e3467c4f/aioesphomeapi/_frame_helper/noise.py#L248C17-L255
        let mut handshake_state_client: HandshakeState<X25519, ChaCha20Poly1305, Sha256> = HandshakeState::new(
            noise_nn_psk0(),
            true,
            b"NoiseAPIInit\x00\x00",
            None, // No static private key
            None,
            None,
            None
        );

        let mut client_message: Vec<u8> = vec![0; 48];
        handshake_state_client.push_psk(&noise_psk);
        handshake_state_client.write_message(b"", &mut client_message).unwrap();

        // Similar to https://github.com/esphome/aioesphomeapi/blob/60bcd1698dd622aeac6f4b5ec448bab0e3467c4f/aioesphomeapi/_frame_helper/noise.py#L248C17-L255
        let mut handshake_state: HandshakeState<X25519, ChaCha20Poly1305, Sha256> = HandshakeState::new(
            noise_nn_psk0(),
            false,
            b"NoiseAPIInit\x00\x00",
            None, // No static private key
            None,
            None,
            None
        );

        let mut out: Vec<u8> = vec![0; 0];
        handshake_state.push_psk(&noise_psk);
        handshake_state.read_message(&client_message, &mut out).unwrap();

        debug!("Decrypted message: {:?}", out);

        let hello_message = ProtoMessage::HelloResponse(
            proto::version_2025_6_3::HelloResponse {
            api_version_major: 1,
            api_version_minor: 1,
            server_info: "Test Server".to_string(),
            name: "Test Server".to_string(),
        });
        let bytes = to_packet_from_ref(&hello_message).unwrap();

        let mut out: Vec<u8> = vec![0; 48];
        handshake_state.write_message(b"", &mut out).unwrap();
        assert_eq!(handshake_state.completed(), true);
        
        debug!("Encrypted message: {:?}", out);

        let mut client_new_message: Vec<u8> = vec![0; 0];
        handshake_state_client.read_message(&out, &mut client_new_message).unwrap();
        assert_eq!(handshake_state_client.completed(), true);
        assert_eq!(handshake_state.completed(), true);
        // let message = encrypted_frame_to_message(&encrypted_frame[1..], &noise_psk).unwrap();
        // match message {
        //     ProtoMessage::HelloRequest(msg) => {
        //         assert_eq!(msg.api_version_major, 1);
        //         assert_eq!(msg.api_version_minor, 10);
        //         assert_eq!(msg.client_info, "aioesphomeapi");
        //     },
        //     _ => panic!("Expected HelloRequest message"),
        // }
    }
}