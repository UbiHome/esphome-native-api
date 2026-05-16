use esphome_native_api::esphomeapi::EspHomeApi;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

const TEST_DEVICE_NAME: &str = "test_device";
const NOISE_PSK: &str = "xiahAckHBW7BcKEQ6mRfasIW20Md9uMh/5PjrjbAhXQ=";

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

// Frame from protocol log: client handshake request (49 bytes payload)
fn encrypted_client_handshake_frame() -> Vec<u8> {
    vec![
        0x01, 0x00, 0x31, // encrypted frame preamble, length 49
        0x00, 0xE9, 0xCC, 0x9B, 0x95, 0x76, 0xBA, 0x19, 0xD5, 0xFF, 0x96, 0xC2, 0x47, 0x49, 0x40,
        0xB3, 0x22, 0x3F, 0x46, 0xE0, 0x65, 0x9C, 0xB1, 0x8B, 0xE6, 0xB1, 0x11, 0x6B, 0x35, 0xFB,
        0xC5, 0xBD, 0x4D, 0x23, 0x52, 0xED, 0x88, 0xD0, 0x48, 0x7F, 0xB1, 0xD5, 0x18, 0x85, 0x61,
        0xAB, 0xAE, 0x74, 0x4B,
    ]
}

// Frame from protocol log: server handshake response
fn encrypted_server_handshake_frame() -> Vec<u8> {
    vec![
        0x01, 0x00, 0x0D, // encrypted frame preamble, length 13
        0x01, // frame type
        0x74, 0x65, 0x73, 0x74, 0x5f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, // "test_device"
        0x00, // null terminator
    ]
}

// Frame from protocol log: encrypted client hello request (39 bytes payload)
fn encrypted_client_encrypted_hello_frame() -> Vec<u8> {
    vec![
        0x01, 0x00, 0x27, // encrypted frame preamble, length 39
        0xAD, 0xE8, 0x27, 0x9F, 0xDE, 0x42, 0x7F, 0x19, 0x38, 0x52, 0x76, 0xF7, 0x5B, 0xA0, 0x30,
        0x9B, 0x54, 0xCC, 0x39, 0x1A, 0x85, 0x0B, 0x13, 0x96, 0xFE, 0x9F, 0xFB, 0xBD, 0xDC, 0x93,
        0xD0, 0x5E, 0x41, 0xAC, 0x66, 0xFD, 0x1B, 0x66, 0xCF,
    ]
}

#[test]
fn test_basic_server_instantiation() {
    EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build();
}

#[tokio::test]
async fn test_hello_message_and_response_plaintext() {
    let (client_stream, server_stream) = duplex(1024);
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build();

    let request_frame = plaintext_hello_request_frame();

    let start_future = api.start(server_stream);
    let write_future = async {
        client_write
            .write_all(&request_frame)
            .await
            .expect("failed to write request frame");
        client_write
            .flush()
            .await
            .expect("failed to flush request frame");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let (_tx, _outgoing_messages_rx) = start_result.expect("server start failed");

    let mut response_frame = vec![0u8; plaintext_hello_response_frame().len()];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_read.read_exact(&mut response_frame),
    )
    .await
    .expect("timed out waiting for response")
    .expect("failed to read response frame");

    assert_eq!(response_frame, plaintext_hello_response_frame());
}

/// This test ensures that an encrypted server rejects plaintext first, but still allows a
/// subsequent encrypted connection when the same `EspHomeApi` instance is reused.
#[tokio::test]
async fn test_protocol_change_from_plaintext_to_encrypted_on_encrypted_server() {
    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .encryption_key(NOISE_PSK.to_string())
        .build();

    let request_frame = plaintext_hello_request_frame();

    let (client_stream, server_stream) = duplex(1024);
    let (mut _client_read, mut client_write) = tokio::io::split(client_stream);

    let start_future = api.start(server_stream);
    let write_future = async {
        client_write
            .write_all(&request_frame)
            .await
            .expect("failed to write plaintext request frame");
        client_write
            .flush()
            .await
            .expect("failed to flush plaintext request frame");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let error = start_result.expect_err("plaintext connection should be rejected");
    assert!(
        error.to_string().contains("Only key encryption is enabled"),
        "unexpected error: {}",
        error
    );

    let (client_stream, server_stream) = duplex(1024);
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    let start_future = api.start(server_stream);
    let write_future = async {
        // Send client hello + handshake in sequence
        client_write
            .write_all(&encrypted_client_hello_frame())
            .await
            .expect("failed to write encrypted hello frame");
        client_write
            .write_all(&encrypted_client_handshake_frame())
            .await
            .expect("failed to write encrypted handshake frame");
        client_write
            .write_all(&encrypted_client_encrypted_hello_frame())
            .await
            .expect("failed to write encrypted hello request frame");
        client_write
            .flush()
            .await
            .expect("failed to flush encrypted frames");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let (_tx, _outgoing_messages_rx) = start_result.expect("encrypted connection should succeed");

    // Read and validate server's handshake response
    let mut handshake_response = vec![0u8; encrypted_server_handshake_frame().len()];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_read.read_exact(&mut handshake_response),
    )
    .await
    .expect("timed out waiting for encrypted handshake response")
    .expect("failed to read encrypted handshake response frame");

    assert_eq!(handshake_response, encrypted_server_handshake_frame());

    // Read and validate server's encrypted hello response (sent after handshake completes)
    // The server sends the hello response after the encrypted communication is established
    let mut hello_response_header = vec![0u8; 3];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_read.read_exact(&mut hello_response_header),
    )
    .await
    .expect("timed out waiting for encrypted hello response header")
    .expect("failed to read encrypted hello response header");

    // Verify it's an encrypted frame
    assert_eq!(
        hello_response_header[0], 0x01,
        "Expected encrypted frame marker"
    );
}

/// This test ensures that a plaintext server rejects encrypted first, but still allows a
/// subsequent plaintext connection when the same `EspHomeApi` instance is reused.
#[tokio::test]
async fn test_protocol_change_from_encrypted_to_plaintext_on_plaintext_server() {
    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build();

    let (client_stream, server_stream) = duplex(1024);
    let (mut _client_read, mut client_write) = tokio::io::split(client_stream);

    let start_future = api.start(server_stream);
    let write_future = async {
        // Send client hello + handshake in sequence
        client_write
            .write_all(&encrypted_client_hello_frame())
            .await
            .expect("failed to write encrypted hello frame");
        client_write
            .write_all(&encrypted_client_handshake_frame())
            .await
            .expect("failed to write encrypted handshake frame");
        client_write
            .flush()
            .await
            .expect("failed to flush encrypted frames");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let error = start_result.expect_err("encrypted connection should be rejected");
    assert!(
        error
            .to_string()
            .contains("No encryption key set, but encrypted communication requested"),
        "unexpected error: {}",
        error
    );

    let (client_stream, server_stream) = duplex(1024);
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    let start_future = api.start(server_stream);
    let write_future = async {
        client_write
            .write_all(&plaintext_hello_request_frame())
            .await
            .expect("failed to write plaintext request frame");
        client_write
            .flush()
            .await
            .expect("failed to flush plaintext request frame");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let (_tx, _outgoing_messages_rx) = start_result.expect("plaintext connection should succeed");

    let mut response_frame = vec![0u8; plaintext_hello_response_frame().len()];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_read.read_exact(&mut response_frame),
    )
    .await
    .expect("timed out waiting for plaintext response")
    .expect("failed to read plaintext response frame");

    assert_eq!(response_frame, plaintext_hello_response_frame());
}
