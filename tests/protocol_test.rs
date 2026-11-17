//! Tests for the sans-IO protocol state machine. They need neither a socket
//! nor an async runtime: bytes go in, events come out.

use base64::prelude::*;
use esphome_native_api::proto::{
    DeviceInfoResponse, HelloRequest, HelloResponse, ListEntitiesDoneResponse, PingRequest,
};
use esphome_native_api::protocol::{Config, Event, ProtoMessage, Protocol};
use esphome_native_api::{DisconnectReason, Error, FrameError, HandshakeError};
use noise_protocol::patterns::noise_nn_psk0;
use noise_protocol::{CipherState, HandshakeState};
use noise_rust_crypto::{ChaCha20Poly1305, Sha256, X25519};
use prost::Message;

const TEST_DEVICE_NAME: &str = "test_device";
const NOISE_PSK: &str = "xiahAckHBW7BcKEQ6mRfasIW20Md9uMh/5PjrjbAhXQ=";
// A valid 32-byte base64 key that differs from `NOISE_PSK`.
const WRONG_NOISE_PSK: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

const PLAINTEXT_PING_REQUEST: [u8; 3] = [0x00, 0x00, 0x07];
const PLAINTEXT_PING_RESPONSE: [u8; 3] = [0x00, 0x00, 0x08];
const PLAINTEXT_DISCONNECT_REQUEST: [u8; 3] = [0x00, 0x00, 0x05];
const PLAINTEXT_DISCONNECT_RESPONSE: [u8; 3] = [0x00, 0x00, 0x06];
const PLAINTEXT_LIST_ENTITIES_REQUEST: [u8; 3] = [0x00, 0x00, 0x0B];

fn plaintext_hello_request_frame() -> Vec<u8> {
    vec![
        0x00, // frame preamble: plaintext
        0x13, // plaintext payload length (message type + protobuf payload, minus type byte)
        0x01, // message type: HelloRequest
        0x0a, 0x0d, // client_info field tag + length (13 bytes)
        0x61, 0x69, 0x6f, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d, 0x65, 0x61, 0x70,
        0x69, // "aioesphomeapi"
        0x10, 0x01, // api_version_major = 1
        0x18, 0x0a, // api_version_minor = 10
    ]
}

fn plaintext_hello_response_frame() -> Vec<u8> {
    vec![
        0x00, // frame preamble: plaintext
        0x2b, // plaintext payload length (message type + protobuf payload, minus type byte)
        0x02, // message type: HelloResponse
        0x08, 0x01, // api_version_major = 1
        0x10, 0x0a, // api_version_minor = 10
        0x1a, 0x18, // server_info field tag + length (24 bytes)
        0x52, 0x75, 0x73, 0x74, 0x3a, 0x20, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d, 0x65, 0x2d, 0x6e,
        0x61, 0x74, 0x69, 0x76, 0x65, 0x2d, 0x61, 0x70, 0x69, // "Rust: esphome-native-api"
        0x22, 0x0b, // name field tag + length (11 bytes)
        0x74, 0x65, 0x73, 0x74, 0x5f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, // "test_device"
    ]
}

// Frame from protocol log: empty client noise hello
fn encrypted_client_hello_frame() -> Vec<u8> {
    vec![0x01, 0x00, 0x00]
}

// Frame from protocol log: server hello, announcing the device name
fn encrypted_server_hello_frame() -> Vec<u8> {
    vec![
        0x01, 0x00, 0x0D, // encrypted frame preamble, length 13
        0x01, // chosen protocol
        0x74, 0x65, 0x73, 0x74, 0x5f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, // "test_device"
        0x00, // null terminator
    ]
}

/// An encrypted frame (preamble + big endian length) around `payload`.
fn encrypted_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x01];
    frame.extend((payload.len() as u16).to_be_bytes());
    frame.extend(payload);
    frame
}

/// The payload of the single encrypted frame in `bytes`.
fn encrypted_frame_payload(bytes: &[u8]) -> &[u8] {
    assert_eq!(bytes[0], 0x01, "expected an encrypted frame");
    let length = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
    assert_eq!(bytes.len(), 3 + length, "expected exactly one frame");
    &bytes[3..]
}

fn plaintext_protocol() -> Protocol {
    Protocol::new(Config::new(TEST_DEVICE_NAME))
}

fn encrypted_protocol(key: &str) -> Protocol {
    Protocol::new(
        Config::new(TEST_DEVICE_NAME)
            .with_encryption_key(key)
            .expect("valid key"),
    )
}

/// Polls until the state machine has nothing left to do and returns the
/// events it produced, plus the fatal error that stopped it (if any).
fn drain(protocol: &mut Protocol) -> (Vec<Event>, Option<Error>) {
    let mut events = Vec::new();
    loop {
        match protocol.poll() {
            Ok(Some(event)) => events.push(event),
            Ok(None) => return (events, None),
            Err(error) => return (events, Some(error)),
        }
    }
}

/// Like [`drain`], for input that must not end the connection.
fn drain_ok(protocol: &mut Protocol) -> Vec<Event> {
    let (events, error) = drain(protocol);
    assert!(error.is_none(), "unexpected error: {error:?}");
    events
}

/// All bytes of the `Transmit` events, in order.
fn transmitted(events: &[Event]) -> Vec<u8> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Transmit(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .concat()
}

fn count_connected(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, Event::Connected))
        .count()
}

/// A plaintext protocol that already went through the hello exchange.
fn established_plaintext_protocol() -> Protocol {
    let mut protocol = plaintext_protocol();
    protocol.receive(&plaintext_hello_request_frame());
    drain_ok(&mut protocol);
    assert!(protocol.is_established());
    protocol
}

/// The client side of an encrypted connection, to talk to a [`Protocol`].
struct NoiseClient {
    encrypt: CipherState<ChaCha20Poly1305>,
    decrypt: CipherState<ChaCha20Poly1305>,
}

impl NoiseClient {
    /// Runs the noise handshake against `protocol` and returns the client
    /// together with the events the handshake produced.
    fn connect(protocol: &mut Protocol, key: &str) -> (Self, Vec<Event>) {
        let psk = BASE64_STANDARD.decode(key).unwrap();
        let mut handshake: HandshakeState<X25519, ChaCha20Poly1305, Sha256> = HandshakeState::new(
            noise_nn_psk0(),
            true,
            b"NoiseAPIInit\0\0",
            None,
            None,
            None,
            None,
        );
        handshake.push_psk(&psk);

        protocol.receive(&encrypted_client_hello_frame());
        let mut request = vec![0x00];
        request.extend(handshake.write_message_vec(b"").unwrap());
        protocol.receive(&encrypted_frame(&request));

        let events = drain_ok(protocol);
        let frames: Vec<&Vec<u8>> = events
            .iter()
            .filter_map(|event| match event {
                Event::Transmit(bytes) => Some(bytes),
                _ => None,
            })
            .collect();
        assert_eq!(frames.len(), 2, "expected server hello + handshake frame");

        let response = encrypted_frame_payload(frames[1]);
        assert_eq!(response[0], 0x00, "handshake must be accepted");
        handshake.read_message_vec(&response[1..]).unwrap();
        assert!(handshake.completed());

        let (encrypt, decrypt) = handshake.get_ciphers();
        (Self { encrypt, decrypt }, events)
    }

    /// The encrypted frame for a message of `message_type` with `payload`.
    fn frame(&mut self, message_type: u16, payload: &[u8]) -> Vec<u8> {
        let mut plaintext = message_type.to_be_bytes().to_vec();
        plaintext.extend((payload.len() as u16).to_be_bytes());
        plaintext.extend(payload);
        encrypted_frame(&self.encrypt.encrypt_vec(&plaintext))
    }

    /// Decrypts a frame of the device into `(message_type, payload)`.
    fn open(&mut self, frame: &[u8]) -> (u16, Vec<u8>) {
        let plaintext = self
            .decrypt
            .decrypt_vec(encrypted_frame_payload(frame))
            .expect("frame must decrypt");
        let message_type = u16::from_be_bytes([plaintext[0], plaintext[1]]);
        let length = u16::from_be_bytes([plaintext[2], plaintext[3]]) as usize;
        assert_eq!(plaintext.len(), 4 + length);
        (message_type, plaintext[4..].to_vec())
    }
}

// ---------------------------------------------------------------------------
// Plaintext
// ---------------------------------------------------------------------------

#[test]
fn test_new_protocol_is_idle() {
    let mut protocol = plaintext_protocol();
    assert!(!protocol.is_established());
    assert!(!protocol.is_closed());
    assert!(!protocol.is_encrypted());
    assert!(!protocol.disconnect_requested());
    assert!(matches!(protocol.poll(), Ok(None)));
}

#[test]
fn test_plaintext_hello_is_answered() {
    let mut protocol = plaintext_protocol();
    protocol.receive(&plaintext_hello_request_frame());

    let events = drain_ok(&mut protocol);

    assert!(matches!(events[0], Event::Connected));
    assert_eq!(events.len(), 2);
    assert_eq!(transmitted(&events), plaintext_hello_response_frame());
    assert!(protocol.is_established());
    assert!(!protocol.is_encrypted());
}

#[test]
fn test_plaintext_connects_on_first_byte() {
    let mut protocol = plaintext_protocol();
    protocol.receive(&[0x00]);

    let events = drain_ok(&mut protocol);

    assert!(matches!(events.as_slice(), [Event::Connected]));
    assert!(protocol.is_established());
}

#[test]
fn test_input_split_at_every_position_gives_the_same_output() {
    let mut input = plaintext_hello_request_frame();
    input.extend(PLAINTEXT_PING_REQUEST);
    let mut expected = plaintext_hello_response_frame();
    expected.extend(PLAINTEXT_PING_RESPONSE);

    for split in 0..=input.len() {
        let mut protocol = plaintext_protocol();
        let mut events = Vec::new();
        for chunk in [&input[..split], &input[split..]] {
            protocol.receive(chunk);
            events.extend(drain_ok(&mut protocol));
        }
        assert_eq!(transmitted(&events), expected, "split at {split}");
        assert_eq!(count_connected(&events), 1, "split at {split}");
    }
}

#[test]
fn test_input_fed_byte_by_byte() {
    let mut protocol = plaintext_protocol();
    let mut events = Vec::new();
    for byte in plaintext_hello_request_frame() {
        protocol.receive(&[byte]);
        events.extend(drain_ok(&mut protocol));
    }

    assert_eq!(transmitted(&events), plaintext_hello_response_frame());
    assert_eq!(count_connected(&events), 1);
}

#[test]
fn test_frames_are_processed_lazily_one_event_at_a_time() {
    let mut protocol = plaintext_protocol();
    let mut input = plaintext_hello_request_frame();
    input.extend(PLAINTEXT_PING_REQUEST);
    protocol.receive(&input);

    // `Connected` is handed out before the first frame is even looked at, so a
    // driver can finish its handshake phase without consuming later events.
    assert!(matches!(protocol.poll(), Ok(Some(Event::Connected))));
    assert!(
        matches!(protocol.poll(), Ok(Some(Event::Transmit(bytes))) if bytes == plaintext_hello_response_frame())
    );
    assert!(
        matches!(protocol.poll(), Ok(Some(Event::Transmit(bytes))) if bytes == PLAINTEXT_PING_RESPONSE)
    );
    assert!(matches!(protocol.poll(), Ok(None)));
}

#[test]
fn test_ping_is_answered() {
    let mut protocol = established_plaintext_protocol();
    protocol.receive(&PLAINTEXT_PING_REQUEST);

    let events = drain_ok(&mut protocol);

    assert_eq!(events.len(), 1);
    assert_eq!(transmitted(&events), PLAINTEXT_PING_RESPONSE);
}

#[test]
fn test_authentication_without_password_is_accepted() {
    let mut protocol = established_plaintext_protocol();
    // AuthenticationRequest (type 3) with an empty password.
    protocol.receive(&[0x00, 0x00, 0x03]);

    let events = drain_ok(&mut protocol);

    // AuthenticationResponse (type 4), `invalid_password` left at false.
    assert_eq!(events.len(), 1);
    assert_eq!(transmitted(&events), [0x00, 0x00, 0x04]);
}

#[test]
fn test_authentication_with_password_is_neither_answered_nor_forwarded() {
    let mut protocol = established_plaintext_protocol();
    // AuthenticationRequest (type 3) with password "pw".
    protocol.receive(&[0x00, 0x04, 0x03, 0x0a, 0x02, b'p', b'w']);

    assert!(drain_ok(&mut protocol).is_empty());
    assert!(protocol.is_established());
}

#[test]
fn test_device_info_is_answered_from_config() {
    let mut config = Config::new(TEST_DEVICE_NAME);
    config.device_info.model = "test-model".to_string();
    config.device_info.mac_address = "AA:BB:CC:DD:EE:FF".to_string();
    let mut protocol = Protocol::new(config);
    // DeviceInfoRequest (type 9)
    protocol.receive(&[0x00, 0x00, 0x09]);

    let bytes = transmitted(&drain_ok(&mut protocol));

    assert_eq!(bytes[0], 0x00);
    assert_eq!(bytes[1] as usize, bytes.len() - 3);
    assert_eq!(bytes[2], 10, "expected a DeviceInfoResponse");
    let device_info = DeviceInfoResponse::decode(&bytes[3..]).unwrap();
    assert_eq!(device_info.name, TEST_DEVICE_NAME);
    assert_eq!(device_info.friendly_name, TEST_DEVICE_NAME);
    assert_eq!(device_info.model, "test-model");
    assert_eq!(device_info.mac_address, "AA:BB:CC:DD:EE:FF");
    assert!(!device_info.esphome_version.is_empty());
    assert!(!device_info.api_encryption_supported);
}

#[test]
fn test_hello_is_answered_from_config() {
    let mut config = Config::new(TEST_DEVICE_NAME);
    config.hello_response.api_version_minor = 12;
    config.hello_response.server_info = "custom".to_string();
    let mut protocol = Protocol::new(config);
    protocol.receive(&plaintext_hello_request_frame());

    let bytes = transmitted(&drain_ok(&mut protocol));

    assert_eq!(bytes[2], 2, "expected a HelloResponse");
    let hello = HelloResponse::decode(&bytes[3..]).unwrap();
    assert_eq!(hello.api_version_major, 1);
    assert_eq!(hello.api_version_minor, 12);
    assert_eq!(hello.server_info, "custom");
    assert_eq!(hello.name, TEST_DEVICE_NAME);
}

#[test]
fn test_other_messages_are_forwarded_to_the_application() {
    let mut protocol = established_plaintext_protocol();
    protocol.receive(&PLAINTEXT_LIST_ENTITIES_REQUEST);

    let events = drain_ok(&mut protocol);

    assert!(matches!(
        events.as_slice(),
        [Event::Message(ProtoMessage::ListEntitiesRequest(_))]
    ));
}

#[test]
fn test_unknown_message_type_is_skipped() {
    let mut protocol = plaintext_protocol();
    // Message type 127 is not assigned; the frame must be skipped and the
    // following HelloRequest still answered.
    protocol.receive(&[0x00, 0x00, 0x7F]);
    protocol.receive(&plaintext_hello_request_frame());

    let events = drain_ok(&mut protocol);

    assert_eq!(transmitted(&events), plaintext_hello_response_frame());
    assert!(protocol.is_established());
}

#[test]
fn test_send_queues_the_encoded_message() {
    let mut protocol = established_plaintext_protocol();

    protocol
        .send(&ProtoMessage::ListEntitiesDoneResponse(
            ListEntitiesDoneResponse {},
        ))
        .unwrap();

    let events = drain_ok(&mut protocol);
    assert_eq!(events.len(), 1);
    assert_eq!(transmitted(&events), [0x00, 0x00, 0x13]);
}

#[test]
fn test_send_keeps_the_order_with_answers() {
    let mut protocol = established_plaintext_protocol();

    protocol.receive(&PLAINTEXT_PING_REQUEST);
    protocol
        .send(&ProtoMessage::ListEntitiesDoneResponse(
            ListEntitiesDoneResponse {},
        ))
        .unwrap();

    // The ping was received first but is only processed by `poll`, so the
    // message queued in between goes out first.
    let events = drain_ok(&mut protocol);
    assert_eq!(
        transmitted(&events),
        [[0x00, 0x00, 0x13], PLAINTEXT_PING_RESPONSE].concat()
    );
}

#[test]
fn test_send_fails_before_the_connection_is_established() {
    let mut protocol = plaintext_protocol();

    let error = protocol
        .send(&ProtoMessage::PingRequest(PingRequest {}))
        .expect_err("nothing can be sent before the handshake");

    assert!(
        matches!(error, Error::NotEstablished),
        "unexpected error: {error}"
    );
    assert!(drain_ok(&mut protocol).is_empty());
}

// ---------------------------------------------------------------------------
// Disconnecting
// ---------------------------------------------------------------------------

#[test]
fn test_disconnect_request_is_answered_and_closes_the_write_side() {
    let mut protocol = established_plaintext_protocol();
    protocol.receive(&PLAINTEXT_DISCONNECT_REQUEST);

    let events = drain_ok(&mut protocol);

    assert!(
        matches!(events.as_slice(), [Event::Transmit(bytes), Event::Close] if bytes == &PLAINTEXT_DISCONNECT_RESPONSE)
    );
    assert!(protocol.disconnect_requested());

    let error = protocol
        .send(&ProtoMessage::PingRequest(PingRequest {}))
        .expect_err("write side is closed");
    assert!(
        matches!(error, Error::Disconnected(DisconnectReason::Requested)),
        "unexpected error: {error}"
    );

    let error = protocol.on_eof();
    assert!(
        matches!(error, Error::Disconnected(DisconnectReason::Requested)),
        "unexpected error: {error}"
    );
    assert!(protocol.is_closed());
}

#[test]
fn test_request_after_disconnect_ends_the_connection() {
    let mut protocol = established_plaintext_protocol();
    protocol.receive(&PLAINTEXT_DISCONNECT_REQUEST);
    protocol.receive(&PLAINTEXT_PING_REQUEST);

    let (events, error) = drain(&mut protocol);

    assert_eq!(transmitted(&events), PLAINTEXT_DISCONNECT_RESPONSE);
    assert!(
        matches!(
            error,
            Some(Error::Disconnected(DisconnectReason::Requested))
        ),
        "unexpected error: {error:?}"
    );
    assert!(protocol.is_closed());
}

#[test]
fn test_messages_are_still_forwarded_after_disconnect_request() {
    let mut protocol = established_plaintext_protocol();
    protocol.receive(&PLAINTEXT_DISCONNECT_REQUEST);
    protocol.receive(&PLAINTEXT_LIST_ENTITIES_REQUEST);

    let events = drain_ok(&mut protocol);

    assert!(matches!(
        events.last(),
        Some(Event::Message(ProtoMessage::ListEntitiesRequest(_)))
    ));
}

#[test]
fn test_sending_a_disconnect_response_closes_the_write_side() {
    let mut protocol = established_plaintext_protocol();

    protocol
        .send(&ProtoMessage::DisconnectResponse(Default::default()))
        .unwrap();

    let events = drain_ok(&mut protocol);
    assert!(
        matches!(events.as_slice(), [Event::Transmit(bytes), Event::Close] if bytes == &PLAINTEXT_DISCONNECT_RESPONSE)
    );
    let error = protocol
        .send(&ProtoMessage::PingRequest(PingRequest {}))
        .expect_err("write side is closed");
    assert!(
        matches!(error, Error::Disconnected(DisconnectReason::WriteClosed)),
        "unexpected error: {error}"
    );
}

#[test]
fn test_close_write_drops_pending_output_and_rejects_sends() {
    let mut protocol = established_plaintext_protocol();
    protocol
        .send(&ProtoMessage::ListEntitiesDoneResponse(
            ListEntitiesDoneResponse {},
        ))
        .unwrap();

    protocol.close_write();

    assert!(drain_ok(&mut protocol).is_empty());
    let error = protocol
        .send(&ProtoMessage::PingRequest(PingRequest {}))
        .expect_err("write side is closed");
    assert!(
        matches!(error, Error::Disconnected(DisconnectReason::WriteClosed)),
        "unexpected error: {error}"
    );
}

#[test]
fn test_close_write_keeps_forwarding_until_an_answer_is_needed() {
    let mut protocol = established_plaintext_protocol();
    protocol.close_write();

    protocol.receive(&PLAINTEXT_LIST_ENTITIES_REQUEST);
    protocol.receive(&PLAINTEXT_PING_REQUEST);
    let (events, error) = drain(&mut protocol);

    assert!(matches!(
        events.as_slice(),
        [Event::Message(ProtoMessage::ListEntitiesRequest(_))]
    ));
    assert!(
        matches!(
            error,
            Some(Error::Disconnected(DisconnectReason::WriteClosed))
        ),
        "unexpected error: {error:?}"
    );
}

// ---------------------------------------------------------------------------
// End of stream
// ---------------------------------------------------------------------------

#[test]
fn test_eof_without_data_is_no_data() {
    let mut protocol = plaintext_protocol();

    let error = protocol.on_eof();

    assert!(
        matches!(error, Error::Handshake(HandshakeError::NoData)),
        "unexpected error: {error}"
    );
    assert!(protocol.is_closed());
}

#[test]
fn test_eof_on_established_connection_is_eof() {
    let mut protocol = established_plaintext_protocol();

    let error = protocol.on_eof();

    assert!(
        matches!(error, Error::Disconnected(DisconnectReason::Eof)),
        "unexpected error: {error}"
    );
}

#[test]
fn test_eof_in_the_middle_of_a_frame_is_malformed() {
    let mut protocol = established_plaintext_protocol();
    let frame = plaintext_hello_request_frame();
    protocol.receive(&frame[..frame.len() - 1]);
    assert!(drain_ok(&mut protocol).is_empty());

    let error = protocol.on_eof();

    assert!(
        matches!(error, Error::Frame(FrameError::Malformed(_))),
        "unexpected error: {error}"
    );
}

#[test]
fn test_eof_during_noise_handshake_is_aborted() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    protocol.receive(&encrypted_client_hello_frame());
    drain_ok(&mut protocol);

    let error = protocol.on_eof();

    assert!(
        matches!(error, Error::Handshake(HandshakeError::Aborted)),
        "unexpected error: {error}"
    );
}

#[test]
fn test_closed_protocol_ignores_everything() {
    let mut protocol = established_plaintext_protocol();
    let _ = protocol.on_eof();

    protocol.receive(&PLAINTEXT_PING_REQUEST);

    assert!(drain_ok(&mut protocol).is_empty());
    assert!(matches!(
        protocol.send(&ProtoMessage::PingRequest(PingRequest {})),
        Err(Error::Disconnected(_))
    ));
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

#[test]
fn test_invalid_marker_byte_is_rejected() {
    let mut protocol = plaintext_protocol();
    protocol.receive(&[0x42]);

    let (events, error) = drain(&mut protocol);

    assert!(events.is_empty());
    assert!(
        matches!(
            error,
            Some(Error::Handshake(HandshakeError::InvalidMarker(0x42)))
        ),
        "unexpected error: {error:?}"
    );
    assert!(protocol.is_closed());
}

#[test]
fn test_undecodable_message_ends_the_connection() {
    let mut protocol = plaintext_protocol();
    // HelloRequest (type 1) whose payload is not valid protobuf: 0xFF starts a
    // varint tag with no continuation byte.
    protocol.receive(&[0x00, 0x01, 0x01, 0xFF]);

    let (events, error) = drain(&mut protocol);

    assert!(matches!(events.as_slice(), [Event::Connected]));
    assert!(
        matches!(
            error,
            Some(Error::Frame(FrameError::Decode { message_type: 1 }))
        ),
        "unexpected error: {error:?}"
    );
    assert!(protocol.is_closed());
    assert!(!protocol.is_established());
}

#[test]
fn test_error_is_reported_once_and_after_earlier_events() {
    let mut protocol = plaintext_protocol();
    protocol.receive(&plaintext_hello_request_frame());
    protocol.receive(&[0x00, 0x01, 0x01, 0xFF]);
    // Never looked at: the connection is over before.
    protocol.receive(&PLAINTEXT_PING_REQUEST);

    let (events, error) = drain(&mut protocol);

    // The answer to the valid frame is not lost to the later fault.
    assert_eq!(transmitted(&events), plaintext_hello_response_frame());
    assert!(matches!(
        error,
        Some(Error::Frame(FrameError::Decode { .. }))
    ));
    assert!(matches!(protocol.poll(), Ok(None)));
    assert!(matches!(protocol.poll(), Ok(None)));
}

#[test]
fn test_frame_switching_to_encrypted_preamble_is_malformed() {
    let mut protocol = established_plaintext_protocol();
    protocol.receive(&encrypted_client_hello_frame());

    let (_, error) = drain(&mut protocol);

    assert!(
        matches!(error, Some(Error::Frame(FrameError::Malformed(_)))),
        "unexpected error: {error:?}"
    );
}

#[test]
fn test_frame_above_max_frame_length_is_rejected_before_its_body_arrives() {
    let mut config = Config::new(TEST_DEVICE_NAME);
    config.max_frame_length = 64;
    let mut protocol = Protocol::new(config);
    // Header announcing a 1000 byte frame; the body never has to be buffered.
    protocol.receive(&[0x00, 0xE8, 0x07]);

    let (_, error) = drain(&mut protocol);

    assert!(
        matches!(error, Some(Error::Frame(FrameError::Malformed(_)))),
        "unexpected error: {error:?}"
    );
    assert!(protocol.is_closed());
}

#[test]
fn test_send_above_max_frame_length_fails_but_keeps_the_connection() {
    let mut config = Config::new(TEST_DEVICE_NAME);
    config.max_frame_length = 64;
    let mut protocol = Protocol::new(config);
    protocol.receive(&plaintext_hello_request_frame());
    drain_ok(&mut protocol);

    let error = protocol
        .send(&ProtoMessage::HelloRequest(HelloRequest {
            client_info: "x".repeat(100),
            ..Default::default()
        }))
        .expect_err("message does not fit into a frame");
    assert!(
        matches!(error, Error::Frame(FrameError::Malformed(_))),
        "unexpected error: {error}"
    );

    assert!(protocol.is_established());
    protocol.receive(&PLAINTEXT_PING_REQUEST);
    assert_eq!(
        transmitted(&drain_ok(&mut protocol)),
        PLAINTEXT_PING_RESPONSE
    );
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

#[test]
fn test_encrypted_send_above_max_frame_length_keeps_the_ciphers_in_sync() {
    let mut config = Config::new(TEST_DEVICE_NAME)
        .with_encryption_key(NOISE_PSK)
        .unwrap();
    config.max_frame_length = 128;
    let mut protocol = Protocol::new(config);
    let (mut client, _) = NoiseClient::connect(&mut protocol, NOISE_PSK);

    let error = protocol
        .send(&ProtoMessage::HelloRequest(HelloRequest {
            client_info: "x".repeat(200),
            ..Default::default()
        }))
        .expect_err("message does not fit into a frame");
    assert!(
        matches!(error, Error::Frame(FrameError::Malformed(_))),
        "unexpected error: {error}"
    );
    assert!(drain_ok(&mut protocol).is_empty());

    // The rejected message must not have used up a nonce: the next message
    // still decrypts on the client.
    protocol.receive(&client.frame(7, &[]));
    let (message_type, _) = client.open(&transmitted(&drain_ok(&mut protocol)));
    assert_eq!(message_type, 8);
}

#[test]
fn test_config_rejects_invalid_base64_encryption_key() {
    let error = Config::new(TEST_DEVICE_NAME)
        .with_encryption_key("not valid base64!!!")
        .expect_err("invalid key should be rejected");
    assert!(
        matches!(error, Error::Config(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn test_config_with_encryption_key_announces_encryption() {
    let config = Config::new(TEST_DEVICE_NAME)
        .with_encryption_key(NOISE_PSK)
        .unwrap();
    assert_eq!(config.noise_psk.as_deref().map(<[u8]>::len), Some(32));
    assert!(config.device_info.api_encryption_supported);
}

#[test]
fn test_plaintext_client_is_rejected_when_encryption_is_required() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    protocol.receive(&plaintext_hello_request_frame());

    let (events, error) = drain(&mut protocol);

    // The rejection uses encrypted framing: preamble, length, failure marker.
    let mut expected = vec![0x01, 0x00, 0x1F, 0x01];
    expected.extend(b"Only key encryption is enabled");
    assert!(
        matches!(events.as_slice(), [Event::Transmit(bytes), Event::Close] if bytes == &expected),
        "unexpected events: {events:?}"
    );
    assert!(
        matches!(
            error,
            Some(Error::Handshake(
                HandshakeError::EncryptionProtocolMismatch(_)
            ))
        ),
        "unexpected error: {error:?}"
    );
    assert!(protocol.is_closed());
}

#[test]
fn test_encrypted_client_is_rejected_when_no_key_is_configured() {
    let mut protocol = plaintext_protocol();
    protocol.receive(&encrypted_client_hello_frame());

    let (events, error) = drain(&mut protocol);

    // The rejection uses plaintext framing so encrypted clients can tell the
    // device speaks plaintext.
    let mut expected = vec![0x00, 0x22, 0x01];
    expected.extend(b"No encrypted communication allowed");
    assert!(
        matches!(events.as_slice(), [Event::Transmit(bytes), Event::Close] if bytes == &expected),
        "unexpected events: {events:?}"
    );
    assert!(
        matches!(
            error,
            Some(Error::Handshake(
                HandshakeError::EncryptionProtocolMismatch(_)
            ))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn test_noise_hello_is_answered_with_server_hello() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    protocol.receive(&encrypted_client_hello_frame());

    let events = drain_ok(&mut protocol);

    assert_eq!(events.len(), 1);
    assert_eq!(transmitted(&events), encrypted_server_hello_frame());
    assert!(protocol.is_encrypted());
    assert!(!protocol.is_established());
    assert!(matches!(
        protocol.send(&ProtoMessage::PingRequest(PingRequest {})),
        Err(Error::NotEstablished)
    ));
}

#[test]
fn test_server_hello_includes_the_mac_address() {
    let mut config = Config::new("dev").with_encryption_key(NOISE_PSK).unwrap();
    config.mac = Some("AA:BB".to_string());
    let mut protocol = Protocol::new(config);
    protocol.receive(&encrypted_client_hello_frame());

    let bytes = transmitted(&drain_ok(&mut protocol));

    assert_eq!(encrypted_frame_payload(&bytes), b"\x01dev\0AA:BB\0");
}

#[test]
fn test_noise_handshake_establishes_the_connection() {
    let mut protocol = encrypted_protocol(NOISE_PSK);

    let (_client, events) = NoiseClient::connect(&mut protocol, NOISE_PSK);

    // Server hello, handshake response, then the connection is reported.
    assert!(matches!(
        events.as_slice(),
        [Event::Transmit(_), Event::Transmit(_), Event::Connected]
    ));
    assert_eq!(transmitted(&events[..1]), encrypted_server_hello_frame());
    assert!(protocol.is_established());
    assert!(protocol.is_encrypted());
}

#[test]
fn test_encrypted_messages_are_exchanged() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    let (mut client, _) = NoiseClient::connect(&mut protocol, NOISE_PSK);

    // HelloRequest (type 1) is answered with the HelloResponse (type 2).
    let hello_request = HelloRequest {
        client_info: "aioesphomeapi".to_string(),
        api_version_major: 1,
        api_version_minor: 10,
        ..Default::default()
    };
    protocol.receive(&client.frame(1, &hello_request.encode_to_vec()));
    let events = drain_ok(&mut protocol);
    assert_eq!(events.len(), 1);
    let (message_type, payload) = client.open(&transmitted(&events));
    assert_eq!(message_type, 2);
    let hello = HelloResponse::decode(payload.as_slice()).unwrap();
    assert_eq!(hello.name, TEST_DEVICE_NAME);
    assert_eq!(hello.api_version_minor, 10);

    // PingRequest (type 7) is answered with a PingResponse (type 8).
    protocol.receive(&client.frame(7, &[]));
    let (message_type, payload) = client.open(&transmitted(&drain_ok(&mut protocol)));
    assert_eq!((message_type, payload.len()), (8, 0));

    // Application messages are forwarded ...
    protocol.receive(&client.frame(11, &[]));
    assert!(matches!(
        drain_ok(&mut protocol).as_slice(),
        [Event::Message(ProtoMessage::ListEntitiesRequest(_))]
    ));

    // ... and messages of the application reach the client.
    protocol
        .send(&ProtoMessage::ListEntitiesDoneResponse(
            ListEntitiesDoneResponse {},
        ))
        .unwrap();
    let (message_type, payload) = client.open(&transmitted(&drain_ok(&mut protocol)));
    assert_eq!((message_type, payload.len()), (19, 0));
}

#[test]
fn test_encrypted_device_info_announces_encryption() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    let (mut client, _) = NoiseClient::connect(&mut protocol, NOISE_PSK);

    protocol.receive(&client.frame(9, &[]));

    let (message_type, payload) = client.open(&transmitted(&drain_ok(&mut protocol)));
    assert_eq!(message_type, 10);
    let device_info = DeviceInfoResponse::decode(payload.as_slice()).unwrap();
    assert!(device_info.api_encryption_supported);
}

#[test]
fn test_encrypted_disconnect_request_closes_the_write_side() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    let (mut client, _) = NoiseClient::connect(&mut protocol, NOISE_PSK);

    protocol.receive(&client.frame(5, &[]));

    let events = drain_ok(&mut protocol);
    assert!(matches!(
        events.as_slice(),
        [Event::Transmit(_), Event::Close]
    ));
    let (message_type, _) = client.open(&transmitted(&events));
    assert_eq!(message_type, 6);
}

#[test]
fn test_each_connection_has_its_own_handshake() {
    let mut first = encrypted_protocol(NOISE_PSK);
    let mut second = encrypted_protocol(NOISE_PSK);
    let (mut first_client, _) = NoiseClient::connect(&mut first, NOISE_PSK);
    let (_second_client, _) = NoiseClient::connect(&mut second, NOISE_PSK);

    // A frame of one session is garbage for the other one.
    second.receive(&first_client.frame(7, &[]));

    let (_, error) = drain(&mut second);
    assert!(
        matches!(error, Some(Error::Frame(FrameError::Decrypt))),
        "unexpected error: {error:?}"
    );
}

#[test]
fn test_handshake_with_wrong_key_fails_with_mac_failure() {
    let mut protocol = encrypted_protocol(WRONG_NOISE_PSK);
    let psk = BASE64_STANDARD.decode(NOISE_PSK).unwrap();
    let mut handshake: HandshakeState<X25519, ChaCha20Poly1305, Sha256> = HandshakeState::new(
        noise_nn_psk0(),
        true,
        b"NoiseAPIInit\0\0",
        None,
        None,
        None,
        None,
    );
    handshake.push_psk(&psk);
    let mut request = vec![0x00];
    request.extend(handshake.write_message_vec(b"").unwrap());

    protocol.receive(&encrypted_client_hello_frame());
    protocol.receive(&encrypted_frame(&request));
    let (events, error) = drain(&mut protocol);

    // Server hello, then the rejection: failure marker + reason, and close.
    let mut expected = vec![0x01, 0x00, 0x16, 0x01];
    expected.extend(b"Handshake MAC failure");
    assert!(
        matches!(events.as_slice(), [Event::Transmit(_), Event::Transmit(bytes), Event::Close] if bytes == &expected),
        "unexpected events: {events:?}"
    );
    assert!(
        matches!(error, Some(Error::Handshake(HandshakeError::MacFailure))),
        "unexpected error: {error:?}"
    );
    assert!(protocol.is_closed());
}

#[test]
fn test_empty_handshake_frame_is_malformed() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    protocol.receive(&encrypted_client_hello_frame());
    // An empty frame where the handshake request is expected.
    protocol.receive(&encrypted_client_hello_frame());

    let (events, error) = drain(&mut protocol);

    assert_eq!(transmitted(&events), encrypted_server_hello_frame());
    assert!(
        matches!(
            error,
            Some(Error::Handshake(HandshakeError::MalformedFrame))
        ),
        "unexpected error: {error:?}"
    );
}

#[test]
fn test_garbage_ciphertext_fails_to_decrypt() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    let (_client, _) = NoiseClient::connect(&mut protocol, NOISE_PSK);

    // A well-framed encrypted frame whose ciphertext is garbage.
    protocol.receive(&encrypted_frame(&[0u8; 16]));

    let (events, error) = drain(&mut protocol);
    assert!(events.is_empty());
    assert!(
        matches!(error, Some(Error::Frame(FrameError::Decrypt))),
        "unexpected error: {error:?}"
    );
    assert!(protocol.is_closed());
}

#[test]
fn test_plaintext_frame_on_encrypted_connection_is_malformed() {
    let mut protocol = encrypted_protocol(NOISE_PSK);
    let (_client, _) = NoiseClient::connect(&mut protocol, NOISE_PSK);

    protocol.receive(&PLAINTEXT_PING_REQUEST);

    let (_, error) = drain(&mut protocol);
    assert!(
        matches!(error, Some(Error::Frame(FrameError::Malformed(_)))),
        "unexpected error: {error:?}"
    );
}
