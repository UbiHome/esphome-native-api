use esphome_native_api::esphomeapi::EspHomeApi;
use esphome_native_api::{DisconnectReason, Error, FrameError, HandshakeError};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

const TEST_DEVICE_NAME: &str = "test_device";
const NOISE_PSK: &str = "xiahAckHBW7BcKEQ6mRfasIW20Md9uMh/5PjrjbAhXQ=";
// A valid 32-byte base64 key that does not match the fixture frames.
const WRONG_NOISE_PSK: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

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
        .build()
        .unwrap();
}

#[tokio::test]
async fn test_hello_message_and_response_plaintext() {
    let (client_stream, server_stream) = duplex(1024);
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

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
    let _connection = start_result.expect("server start failed");

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
        .build()
        .unwrap();

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
        error.to_string().contains("encryption protocol mismatch"),
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
    let _connection = start_result.expect("encrypted connection should succeed");

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
        .build()
        .unwrap();

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
            .flush()
            .await
            .expect("failed to flush encrypted frames");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let error = start_result.expect_err("encrypted connection should be rejected");
    assert!(
        error.to_string().contains("encryption protocol mismatch"),
        "unexpected error: {}",
        error
    );

    // The rejection frame must use plaintext framing so encrypted clients can
    // tell the device speaks plaintext.
    let mut rejection_preamble = [0u8; 1];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_read.read_exact(&mut rejection_preamble),
    )
    .await
    .expect("timed out waiting for rejection frame")
    .expect("failed to read rejection frame preamble");
    assert_eq!(rejection_preamble[0], 0x00);

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
    let _connection = start_result.expect("plaintext connection should succeed");

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

#[test]
fn test_build_rejects_invalid_base64_encryption_key() {
    let error = match EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .encryption_key("not valid base64!!!".to_string())
        .build()
    {
        Ok(_) => panic!("invalid key should fail at build time"),
        Err(error) => error,
    };
    assert!(
        matches!(error, Error::Config(_)),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn test_start_fails_with_no_data_when_peer_closes_immediately() {
    let (client_stream, server_stream) = duplex(1024);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

    drop(client_stream);
    let error = api
        .start(server_stream)
        .await
        .expect_err("closed connection without data should be rejected");
    assert!(
        matches!(error, Error::Handshake(HandshakeError::NoData)),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn test_start_fails_with_invalid_marker_byte() {
    let (client_stream, server_stream) = duplex(1024);
    let (_client_read, mut client_write) = tokio::io::split(client_stream);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

    let start_future = api.start(server_stream);
    let write_future = async {
        client_write
            .write_all(&[0x42])
            .await
            .expect("failed to write marker byte");
        client_write.flush().await.expect("failed to flush");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let error = start_result.expect_err("invalid marker byte should be rejected");
    assert!(
        matches!(error, Error::Handshake(HandshakeError::InvalidMarker(0x42))),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn test_start_fails_with_mac_failure_on_wrong_key() {
    let (client_stream, server_stream) = duplex(1024);
    let (_client_read, mut client_write) = tokio::io::split(client_stream);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .encryption_key(WRONG_NOISE_PSK.to_string())
        .build()
        .unwrap();

    let start_future = api.start(server_stream);
    let write_future = async {
        client_write
            .write_all(&encrypted_client_hello_frame())
            .await
            .expect("failed to write encrypted hello frame");
        client_write
            .write_all(&encrypted_client_handshake_frame())
            .await
            .expect("failed to write encrypted handshake frame");
        client_write.flush().await.expect("failed to flush");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let error = start_result.expect_err("handshake with mismatched key should be rejected");
    assert!(
        matches!(error, Error::Handshake(HandshakeError::MacFailure)),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn test_start_fails_with_aborted_when_peer_leaves_mid_handshake() {
    let (client_stream, server_stream) = duplex(1024);
    let (_client_read, mut client_write) = tokio::io::split(client_stream);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .encryption_key(NOISE_PSK.to_string())
        .build()
        .unwrap();

    let start_future = api.start(server_stream);
    let write_future = async {
        client_write
            .write_all(&encrypted_client_hello_frame())
            .await
            .expect("failed to write encrypted hello frame");
        client_write
            .shutdown()
            .await
            .expect("failed to shutdown client");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let error = start_result.expect_err("mid-handshake disconnect should be rejected");
    assert!(
        matches!(error, Error::Handshake(HandshakeError::Aborted)),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn test_wait_reports_eof_when_peer_closes() {
    let (mut client_stream, server_stream) = duplex(1024);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

    let start_future = api.start(server_stream);
    let write_future = async {
        client_stream
            .write_all(&plaintext_hello_request_frame())
            .await
            .expect("failed to write request frame");
        client_stream.flush().await.expect("failed to flush");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let connection = start_result.expect("server start failed");

    let mut response_frame = vec![0u8; plaintext_hello_response_frame().len()];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_stream.read_exact(&mut response_frame),
    )
    .await
    .expect("timed out waiting for response")
    .expect("failed to read response frame");

    client_stream
        .shutdown()
        .await
        .expect("failed to shutdown client");

    let outcome = tokio::time::timeout(Duration::from_secs(1), connection.wait())
        .await
        .expect("timed out waiting for connection to end");
    assert!(
        matches!(outcome, Err(Error::Disconnected(DisconnectReason::Eof))),
        "unexpected outcome: {outcome:?}"
    );
}

#[tokio::test]
async fn test_wait_reports_requested_after_disconnect_request() {
    let (mut client_stream, server_stream) = duplex(1024);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

    // DisconnectRequest: plaintext preamble, empty payload, message type 5
    let disconnect_request_frame = [0x00, 0x00, 0x05];

    let start_future = api.start(server_stream);
    let write_future = async {
        client_stream
            .write_all(&disconnect_request_frame)
            .await
            .expect("failed to write disconnect request frame");
        client_stream.flush().await.expect("failed to flush");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let connection = start_result.expect("server start failed");

    // DisconnectResponse: plaintext preamble, empty payload, message type 6
    let mut response_frame = [0u8; 3];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_stream.read_exact(&mut response_frame),
    )
    .await
    .expect("timed out waiting for disconnect response")
    .expect("failed to read disconnect response frame");
    assert_eq!(response_frame, [0x00, 0x00, 0x06]);

    client_stream
        .shutdown()
        .await
        .expect("failed to shutdown client");

    let outcome = tokio::time::timeout(Duration::from_secs(1), connection.wait())
        .await
        .expect("timed out waiting for connection to end");
    assert!(
        matches!(
            outcome,
            Err(Error::Disconnected(DisconnectReason::Requested))
        ),
        "unexpected outcome: {outcome:?}"
    );
}

#[tokio::test]
async fn test_wait_reports_frame_error_on_undecodable_message() {
    let (mut client_stream, server_stream) = duplex(1024);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

    // HelloRequest (type 1) whose payload is not valid protobuf: 0xFF starts a
    // varint tag with no continuation byte.
    let bad_frame = [0x00, 0x01, 0x01, 0xFF];

    let start_future = api.start(server_stream);
    let write_future = async {
        client_stream
            .write_all(&bad_frame)
            .await
            .expect("failed to write bad frame");
        client_stream.flush().await.expect("failed to flush");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let connection = start_result.expect("server start failed");

    let outcome = tokio::time::timeout(Duration::from_secs(1), connection.wait())
        .await
        .expect("timed out waiting for connection to end");
    assert!(
        matches!(
            outcome,
            Err(Error::Frame(FrameError::Decode { message_type: 1 }))
        ),
        "unexpected outcome: {outcome:?}"
    );
}

#[tokio::test]
async fn test_unknown_message_type_is_skipped() {
    let (mut client_stream, server_stream) = duplex(1024);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

    // Message type 127 is not assigned; the frame must be skipped and the
    // following HelloRequest still answered.
    let unknown_type_frame = [0x00, 0x00, 0x7F];

    let start_future = api.start(server_stream);
    let write_future = async {
        client_stream
            .write_all(&unknown_type_frame)
            .await
            .expect("failed to write unknown type frame");
        client_stream
            .write_all(&plaintext_hello_request_frame())
            .await
            .expect("failed to write request frame");
        client_stream.flush().await.expect("failed to flush");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let _connection = start_result.expect("server start failed");

    let mut response_frame = vec![0u8; plaintext_hello_response_frame().len()];
    tokio::time::timeout(
        Duration::from_secs(1),
        client_stream.read_exact(&mut response_frame),
    )
    .await
    .expect("timed out waiting for response")
    .expect("failed to read response frame");

    assert_eq!(response_frame, plaintext_hello_response_frame());
}

// A well-framed encrypted frame whose ciphertext is garbage, so AEAD
// decryption must fail.
fn encrypted_garbage_frame() -> Vec<u8> {
    let mut frame = vec![0x01, 0x00, 0x10];
    frame.extend([0u8; 16]);
    frame
}

#[tokio::test]
async fn test_wait_reports_decrypt_error_on_garbage_ciphertext() {
    let (client_stream, server_stream) = duplex(1024);
    let (_client_read, mut client_write) = tokio::io::split(client_stream);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .encryption_key(NOISE_PSK.to_string())
        .build()
        .unwrap();

    let start_future = api.start(server_stream);
    let write_future = async {
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
            .write_all(&encrypted_garbage_frame())
            .await
            .expect("failed to write garbage frame");
        client_write.flush().await.expect("failed to flush");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let connection = start_result.expect("encrypted connection should succeed");

    let outcome = tokio::time::timeout(Duration::from_secs(1), connection.wait())
        .await
        .expect("timed out waiting for connection to end");
    assert!(
        matches!(outcome, Err(Error::Frame(FrameError::Decrypt))),
        "unexpected outcome: {outcome:?}"
    );
}

#[tokio::test]
async fn test_wait_reports_reset_when_peer_resets_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind listener");
    let addr = listener.local_addr().expect("failed to get local addr");
    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("failed to connect");
    let (server_stream, _) = listener.accept().await.expect("failed to accept");

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

    client
        .write_all(&plaintext_hello_request_frame())
        .await
        .expect("failed to write request frame");
    let connection = api.start(server_stream).await.expect("server start failed");

    let mut response_frame = vec![0u8; plaintext_hello_response_frame().len()];
    tokio::time::timeout(
        Duration::from_secs(1),
        client.read_exact(&mut response_frame),
    )
    .await
    .expect("timed out waiting for response")
    .expect("failed to read response frame");

    // Linger 0 makes the close send an RST instead of a FIN.
    client
        .set_linger(Some(Duration::from_secs(0)))
        .expect("failed to set linger");
    drop(client);

    let outcome = tokio::time::timeout(Duration::from_secs(1), connection.wait())
        .await
        .expect("timed out waiting for connection to end");
    assert!(
        matches!(
            outcome,
            Err(Error::Disconnected(DisconnectReason::Reset(_)))
        ),
        "unexpected outcome: {outcome:?}"
    );
}

/// A stream that serves one scripted read and panics on the next one, killing
/// the connection's read-loop task before it can report an outcome.
struct PanicOnSecondRead {
    first_read: Option<Vec<u8>>,
}

impl tokio::io::AsyncRead for PanicOnSecondRead {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.first_read.take() {
            Some(bytes) => {
                buf.put_slice(&bytes);
                std::task::Poll::Ready(Ok(()))
            }
            None => panic!("simulated crash in the connection task"),
        }
    }
}

impl tokio::io::AsyncWrite for PanicOnSecondRead {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn test_wait_reports_task_failed_when_connection_task_panics() {
    let stream = PanicOnSecondRead {
        first_read: Some(plaintext_hello_request_frame()),
    };

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .build()
        .unwrap();

    let connection = api.start(stream).await.expect("server start failed");

    let outcome = tokio::time::timeout(Duration::from_secs(1), connection.wait())
        .await
        .expect("timed out waiting for connection to end");
    assert!(
        matches!(outcome, Err(Error::TaskFailed)),
        "unexpected outcome: {outcome:?}"
    );
}

#[tokio::test]
async fn test_start_fails_with_malformed_frame_on_empty_handshake_frame() {
    let (client_stream, server_stream) = duplex(1024);
    let (_client_read, mut client_write) = tokio::io::split(client_stream);

    let api = EspHomeApi::builder()
        .name(TEST_DEVICE_NAME.to_string())
        .encryption_key(NOISE_PSK.to_string())
        .build()
        .unwrap();

    let start_future = api.start(server_stream);
    let write_future = async {
        client_write
            .write_all(&encrypted_client_hello_frame())
            .await
            .expect("failed to write encrypted hello frame");
        // An empty frame where the handshake request is expected.
        client_write
            .write_all(&encrypted_client_hello_frame())
            .await
            .expect("failed to write empty handshake frame");
        client_write.flush().await.expect("failed to flush");
    };

    let (start_result, _) = tokio::join!(start_future, write_future);
    let error = start_result.expect_err("empty handshake frame should be rejected");
    assert!(
        matches!(error, Error::Handshake(HandshakeError::MalformedFrame)),
        "unexpected error: {error}"
    );
}
