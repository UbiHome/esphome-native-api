use esphome_native_api::esphomeapi::EspHomeApi;
use std::time::Duration;
use test_log::test;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[test]
fn test_basic_server_instantiation() {
    EspHomeApi::builder()
        .name("test_device".to_string())
        .build();
}

#[tokio::test]
async fn test_hello_message_and_response() {
    let (client_stream, server_stream) = duplex(1024);
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    let mut api = EspHomeApi::builder()
        .name("test_device".to_string())
        .build();

    let request_frame = vec![
        0x00, // frame preamble: plaintext
        0x13, // plaintext payload length (message type + protobuf payload, minus type byte)
        0x01, // message type: HelloRequest
        0x0a, 0x0d, // client_info field tag + length (13 bytes)
        0x61, 0x69, 0x6f, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d, 0x65, 0x61, 0x70,
        0x69, // "aioesphomeapi"
        0x10, 0x01, // api_version_major = 1
        0x18, 0x0a, // api_version_minor = 10
    ];

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

    let mut response_frame = vec![0u8; 46];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_read.read_exact(&mut response_frame),
    )
    .await
    .expect("timed out waiting for response")
    .expect("failed to read response frame");

    let expected_response_frame = vec![
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
    ];

    assert_eq!(response_frame, expected_response_frame);
}

#[tokio::test]
async fn test_start_with_mocked_socket_and_encrypted_hex_message() {
    let (client_stream, server_stream) = duplex(1024);
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    let mut api = EspHomeApi::builder()
        .name("test_device".to_string())
        .encryption_key("xiahAckHBW7BcKEQ6mRfasIW20Md9uMh/5PjrjbAhXQ=".to_string())
        .build();

    let frame = vec![
        0x01, 0x00, 0x00, 0x01, 0x00, 0x31, 0x00, 0x2e, 0x79, 0x1f, 0x12, 0x92, 0xfe, 0x51, 0x45,
        0x0b, 0xec, 0xb9, 0x74, 0x24, 0x4c, 0xe5, 0x1f, 0x67, 0xa4, 0x90, 0xe5, 0x53, 0x56, 0x2f,
        0xa1, 0x5b, 0x67, 0x68, 0x5e, 0xe5, 0x9d, 0x90, 0x37, 0xb7, 0xc8, 0xaf, 0x16, 0xd2, 0xc4,
        0x28, 0x52, 0x97, 0x73, 0x7c, 0x73, 0x97, 0x0d, 0xc7, 0x28,
    ];

    let start_future = api.start(server_stream);
    let write_future = async {
        client_write
            .write_all(&frame)
            .await
            .expect("failed to write frame");
        client_write
            .flush()
            .await
            .expect("failed to flush request frames");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let error = start_result.expect_err("server start should fail for invalid encrypted input");

    // assert!(
    //     error.to_string().contains("Handshake MACa failure"),
    //     "unexpected error: {}",
    //     error
    // );

    let mut response_frame = vec![0u8; 4];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_read.read_exact(&mut response_frame),
    )
    .await
    .expect("timed out waiting for response")
    .expect("failed to read response frame");

    let expected_response_frame = vec![
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
    ];

    assert_eq!(response_frame, expected_response_frame);
}
