//! Low-level ESPHome native API implementation.
//!
//! This module provides [`EspHomeApi`], which handles the core protocol communication
//! with ESPHome devices. It manages connection establishment, encryption handshakes,
//! message framing, and protocol state.
//!
//! # Examples
//!
//! ## Plaintext Connection
//!
//! ```rust,no_run
//! use esphome_native_api::esphomeapi::EspHomeApi;
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let stream = TcpStream::connect("192.168.1.100:6053").await?;
//!     
//!     let mut api = EspHomeApi::builder()
//!         .name("my-client".to_string())
//!         .build();
//!     
//!     let (tx, mut rx) = api.start(stream).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Encrypted Connection
//!
//! ```rust,no_run
//! use esphome_native_api::esphomeapi::EspHomeApi;
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let stream = TcpStream::connect("192.168.1.100:6053").await?;
//!     
//!     let mut api = EspHomeApi::builder()
//!         .name("my-client".to_string())
//!         .encryption_key("your-base64-encoded-key".to_string())
//!         .build();
//!     
//!     let (tx, mut rx) = api.start(stream).await?;
//!     Ok(())
//! }
//! ```

use base64::prelude::*;
use log::debug;
use log::error;
use log::info;
use log::trace;
use noise_protocol::CipherState;
use noise_protocol::ErrorKind;
use noise_protocol::HandshakeState;
use noise_protocol::patterns::noise_nn_psk0;
use noise_rust_crypto::ChaCha20Poly1305;
use noise_rust_crypto::Sha256;
use noise_rust_crypto::X25519;
use typed_builder::TypedBuilder;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use crate::packet_encrypted;
use crate::packet_plaintext;
use crate::parser::ProtoMessage;
use crate::proto::{
    self, AuthenticationResponse, DeviceInfoResponse, DisconnectResponse, HelloResponse,
    PingResponse,
};

// std-only imports
#[cfg(feature = "std")]
use {
    futures::sink::SinkExt,
    tokio::io::AsyncWriteExt,
    tokio::net::TcpStream,
    tokio::net::tcp::OwnedWriteHalf,
    tokio::sync::Mutex,
    tokio::sync::broadcast,
    tokio::sync::mpsc,
    tokio::sync::oneshot,
    tokio_stream::StreamExt,
    tokio_util::codec::FramedRead,
    tokio_util::codec::FramedWrite,
    crate::frame::FrameCodec,
};

#[cfg(feature = "std")]
async fn write_error_and_disconnect(
    mut writer: FramedWrite<OwnedWriteHalf, FrameCodec>,
    message: &str,
) {
    error!("API Failure: {}. Disconnecting.", message);
    let packet = [[1].to_vec(), message.as_bytes().to_vec()].concat();
    writer.send(packet).await.unwrap();
    writer.flush().await.unwrap();
    let mut tcp_write = writer.into_inner();
    if let Err(err) = tcp_write.shutdown().await {
        error!("failed to shutdown socket: {:?}", err);
    }
}

const ERROR_ONLY_ENCRYPTED: &str = "Only key encryption is enabled";
const ERROR_HANDSHAKE_MAC_FAILURE: &str = "Handshake MAC failure";

/// Low-level ESPHome native API client.
///
/// `EspHomeApi` provides direct access to the ESPHome native API protocol,
/// handling connection setup, encryption, and message framing. This is the
/// lower-level API that [`crate::esphomeserver::EspHomeServer`] builds upon.
///
/// This struct supports both encrypted and plaintext connections and uses
/// the builder pattern for configuration via [`TypedBuilder`].
///
/// # Builder Options
///
/// - `name`: Device name (required)
/// - `encryption_key`: Base64-encoded encryption key (optional, enables encryption)
/// - `api_version_major`: API version major number (default: 1)
/// - `api_version_minor`: API version minor number (default: 10)
/// - `server_info`: Server identification string (default: "Rust: esphome-native-api")
/// - `friendly_name`: Human-readable device name (optional)
/// - `mac`: MAC address (optional)
/// - `model`: Device model (optional)
/// - `manufacturer`: Device manufacturer (optional)
/// - `suggested_area`: Suggested area for the device (optional)
/// - `bluetooth_mac_address`: Bluetooth MAC address (optional)
///
/// # Examples
///
/// ```rust
/// use esphome_native_api::esphomeapi::EspHomeApi;
///
/// let api = EspHomeApi::builder()
///     .name("bedroom-light".to_string())
///     .api_version_major(1)
///     .api_version_minor(10)
///     .friendly_name("Bedroom Light".to_string())
///     .build();
/// ```
#[derive(TypedBuilder, Clone)]
pub struct EspHomeApi {
    // Private fields

    // std-only: shared state for concurrent tokio tasks
    #[cfg(feature = "std")]
    #[builder(default=Arc::new(AtomicBool::new(false)))]
    pub(crate) first_message_received: Arc<AtomicBool>,

    #[cfg(feature = "std")]
    #[builder(default=Arc::new(AtomicBool::new(true)))]
    pub(crate) plaintext_communication: Arc<AtomicBool>,

    #[cfg(feature = "std")]
    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) encrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>>,
    #[cfg(feature = "std")]
    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) decrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>>,

    // no_std: inline state for single-task async model
    #[cfg(not(feature = "std"))]
    #[builder(default = false, setter(skip))]
    pub(crate) first_message_received: bool,

    #[cfg(not(feature = "std"))]
    #[builder(default = true, setter(skip))]
    pub(crate) plaintext_communication: bool,

    #[cfg(not(feature = "std"))]
    #[builder(default = None, setter(skip))]
    pub(crate) encrypt_cypher: Option<CipherState<ChaCha20Poly1305>>,
    #[cfg(not(feature = "std"))]
    #[builder(default = None, setter(skip))]
    pub(crate) decrypt_cypher: Option<CipherState<ChaCha20Poly1305>>,

    name: String,

    #[builder(default = None, setter(strip_option(fallback=encryption_key_opt)))]
    encryption_key: Option<String>,

    #[builder(default = 1)]
    api_version_major: u32,
    #[builder(default = 10)]
    api_version_minor: u32,
    #[builder(default="Rust: esphome-native-api".to_string())]
    server_info: String,

    #[builder(default = None, setter(strip_option(fallback=friendly_name_opt)))]
    friendly_name: Option<String>,

    #[builder(default = None, setter(strip_option(fallback=mac_opt)))]
    mac: Option<String>,

    #[builder(default = None, setter(strip_option(fallback=model_opt)))]
    model: Option<String>,

    #[builder(default = None, setter(strip_option(fallback=manufacturer_opt)))]
    manufacturer: Option<String>,
    #[builder(default = None, setter(strip_option(fallback=suggested_area_opt)))]
    suggested_area: Option<String>,
    #[builder(default = None, setter(strip_option(fallback=bluetooth_mac_address_opt)))]
    bluetooth_mac_address: Option<String>,

    #[builder(default = None, setter(strip_option(fallback=project_name_opt)))]
    project_name: Option<String>,

    #[builder(default = None, setter(strip_option(fallback=project_version_opt)))]
    project_version: Option<String>,
    #[builder(default = None, setter(strip_option(fallback=compilation_time_opt)))]
    compilation_time: Option<String>,

    #[builder(default = 0)]
    legacy_bluetooth_proxy_version: u32,
    #[builder(default = 0)]
    bluetooth_proxy_feature_flags: u32,
    #[builder(default = 0)]
    legacy_voice_assistant_version: u32,
    #[builder(default = 0)]
    voice_assistant_feature_flags: u32,
}

/// Handles the ESPHome API protocol with encryption support.
#[cfg(feature = "std")]
impl EspHomeApi {
    /// Starts the API client and establishes communication with an ESPHome device.
    ///
    /// This method performs the complete connection handshake, including:
    /// 1. Detecting whether encryption is required
    /// 2. Performing encryption handshake if needed
    /// 3. Exchanging hello messages
    /// 4. Setting up message routing
    ///
    /// # Arguments
    ///
    /// * `tcp_stream` - An established TCP connection to the ESPHome device
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - An `mpsc::Sender` for sending messages to the device
    /// - A `broadcast::Receiver` for receiving messages from the device
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection fails
    /// - The encryption handshake fails
    /// - The hello exchange fails
    /// - The device requires encryption but no key was provided
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use esphome_native_api::esphomeapi::EspHomeApi;
    /// # use tokio::net::TcpStream;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let stream = TcpStream::connect("192.168.1.100:6053").await?;
    /// let mut api = EspHomeApi::builder().name("client".to_string()).build();
    /// let (tx, mut rx) = api.start(stream).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start(
        &mut self,
        tcp_stream: TcpStream,
    ) -> Result<
        (
            mpsc::Sender<ProtoMessage>,
            broadcast::Receiver<ProtoMessage>,
        ),
        Box<dyn std::error::Error>,
    > {
        // Channel for messages
        let (answer_messages_tx, mut answer_messages_rx) = mpsc::channel::<ProtoMessage>(16);
        let (outgoing_messages_tx, outgoing_messages_rx) = broadcast::channel::<ProtoMessage>(16);

        #[allow(deprecated)]
        let device_info = DeviceInfoResponse {
            api_encryption_supported: self.encryption_key.is_some(),
            uses_password: false,
            name: self.name.clone(),
            mac_address: self.mac.clone().unwrap_or_default(),
            esphome_version: proto::VERSION.to_owned(),
            compilation_time: self.compilation_time.clone().unwrap_or_default(),
            model: self.model.clone().unwrap_or_default(),
            has_deep_sleep: false,
            project_name: self.project_name.clone().unwrap_or_default(),
            project_version: self.project_version.clone().unwrap_or_default(),
            webserver_port: 0,
            // See https://github.com/esphome/aioesphomeapi/blob/c1fee2f4eaff84d13ca71996bb272c28b82314fc/aioesphomeapi/model.py#L154
            legacy_bluetooth_proxy_version: self.legacy_bluetooth_proxy_version,
            bluetooth_proxy_feature_flags: self.bluetooth_proxy_feature_flags,
            manufacturer: self.manufacturer.clone().unwrap_or_default(),
            friendly_name: self.friendly_name.clone().unwrap_or(self.name.clone()),
            legacy_voice_assistant_version: self.legacy_voice_assistant_version,
            voice_assistant_feature_flags: self.voice_assistant_feature_flags,
            suggested_area: self.suggested_area.clone().unwrap_or_default(),
            bluetooth_mac_address: self.bluetooth_mac_address.clone().unwrap_or_default(),
            areas: vec![],
            devices: vec![],
            area: None,
            zwave_proxy_feature_flags: 0,
            zwave_home_id: 0,
        };

        let hello_response = HelloResponse {
            api_version_major: self.api_version_major,
            api_version_minor: self.api_version_minor,
            server_info: self.server_info.clone(),
            name: self.name.clone(),
        };

        let encrypt_cypher_clone = self.encrypt_cypher.clone();
        let decrypt_cypher_clone = self.decrypt_cypher.clone();

        // Stage 1: Initialization
        trace!("Init Connection: Stage 1");
        let encryption_key = self.encryption_key.clone();

        let mut buf = vec![0; 1];
        let n = tcp_stream
            .peek(&mut buf)
            .await
            .expect("failed to read data from socket");

        if n == 0 {
            return Err("No data".into());
        }

        trace!("TCP Peeked: {:02X?}", &buf[0..n]);

        let preamble = buf[0] as usize;

        let first_message_received = self
            .first_message_received
            .load(std::sync::atomic::Ordering::Relaxed);

        if !first_message_received {
            match preamble {
                0 => {
                    debug!("Cleartext messaging");

                    self.plaintext_communication
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
                1 => {
                    trace!("Encrypted messaging");

                    self.plaintext_communication
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {
                    return Err(format!("Invalid marker byte {}", preamble).into());
                }
            }
            self.first_message_received
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        let plaintext_communication = self
            .plaintext_communication
            .load(std::sync::atomic::Ordering::Relaxed);
        let encrypted = !plaintext_communication;

        let (tcp_read, tcp_write) = tcp_stream.into_split();
        let decoder = FrameCodec::new(encrypted);
        let encoder = FrameCodec::new(encrypted);
        let mut reader = FramedRead::new(tcp_read, decoder);
        let mut writer = FramedWrite::new(tcp_write, encoder);

        if plaintext_communication {
            if self.encryption_key.is_some() {
                let encoder = FrameCodec::new(true);
                let writer = FramedWrite::new(writer.into_inner(), encoder);
                write_error_and_disconnect(writer, ERROR_ONLY_ENCRYPTED).await;
                return Err(ERROR_ONLY_ENCRYPTED.into());
            }
        } else {
            if self.encryption_key.is_none() {
                write_error_and_disconnect(writer, "No encrypted communication allowed").await;
                return Err("No encryption key set, but encrypted communication requested.".into());
            }

            let frame_noise_hello = reader.next().await.unwrap().unwrap();
            debug!("Frame 1: {:02X?}", &frame_noise_hello);

            let message_server_hello =
                packet_encrypted::generate_server_hello_frame(self.name.clone(), self.mac.clone());

            writer.send(message_server_hello.clone()).await.unwrap();
            writer.flush().await.unwrap();

            let frame_handshake_request = reader.next().await.unwrap().unwrap();
            debug!("Frame 2: {:02X?}", &frame_handshake_request);

            // Similar to https://github.com/esphome/aioesphomeapi/blob/60bcd1698dd622aeac6f4b5ec448bab0e3467c4f/aioesphomeapi/_frame_helper/noise.py#L248C17-L255
            let mut handshake_state: HandshakeState<X25519, ChaCha20Poly1305, Sha256> =
                HandshakeState::new(
                    noise_nn_psk0(),
                    false,
                    // NEXT: This is somehow set from the first api message?
                    b"NoiseAPIInit\0\0",
                    None,
                    None,
                    None,
                    None,
                );

            let noise_psk = BASE64_STANDARD
                .decode(encryption_key.as_ref().unwrap())
                .unwrap();

            handshake_state.push_psk(&noise_psk);
            // Ignore message type byte
            match handshake_state.read_message_vec(&frame_handshake_request[1..]) {
                Ok(_) => {}
                Err(e) => match e.kind() {
                    ErrorKind::Decryption => {
                        write_error_and_disconnect(writer, ERROR_HANDSHAKE_MAC_FAILURE).await;
                        return Err(ERROR_HANDSHAKE_MAC_FAILURE.into());
                    }
                    _ => {
                        debug!("Failed to read message: {}", e);
                    }
                },
            }

            let out = handshake_state.write_message_vec(b"").unwrap();
            {
                let mut encrypt_cipher_changer = encrypt_cypher_clone.lock().await;
                let mut decrypt_cipher_changer = decrypt_cypher_clone.lock().await;
                let (decrypt_cipher, encrypt_cipher) = handshake_state.get_ciphers();
                *encrypt_cipher_changer = Some(encrypt_cipher);
                *decrypt_cipher_changer = Some(decrypt_cipher);
            }

            let mut message_handshake = vec![0];
            message_handshake.extend(out);

            debug!("Sending handshake");
            writer.send(message_handshake.clone()).await.unwrap();
            writer.flush().await.unwrap();
        }

        debug!("Initialization done.");

        // Asynchronously wait for an inbound socket.
        let (cancellation_write_tx, mut cancellation_write_rx) = oneshot::channel();

        // Write Loop
        let plaintext_communication = self.plaintext_communication.clone();
        tokio::spawn(async move {
            loop {
                let answer_message: ProtoMessage;

                // Wait for any new message
                tokio::select! {
                    biased; // Poll cancellation_write_rx first
                    cancel_message = &mut cancellation_write_rx => {
                        debug!("Write loop received cancellation signal ({}), exiting.", cancel_message.unwrap());
                        break;
                    }
                    message = answer_messages_rx.recv() => {
                        answer_message = message.unwrap();
                    }
                };

                debug!("Answer message: {:?}", answer_message);

                if plaintext_communication.load(std::sync::atomic::Ordering::Relaxed) {
                    writer
                        .send(packet_plaintext::message_to_packet(&answer_message).unwrap())
                        .await
                        .unwrap();
                    // answer_buf =
                    //     [answer_buf, to_unencrypted_frame(&answer_message).unwrap()].concat();
                } else {
                    // Use normal messaging
                    let mut encrypt_cipher_changer = encrypt_cypher_clone.lock().await;
                    writer
                        .send(
                            packet_encrypted::message_to_packet(
                                &answer_message,
                                &mut *encrypt_cipher_changer.as_mut().unwrap(),
                            )
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                }
                writer.flush().await.unwrap();

                if matches!(answer_message, ProtoMessage::DisconnectResponse(_)) {
                    debug!("Disconnecting");
                    let mut tcp_write = writer.into_inner();
                    match tcp_write.shutdown().await {
                        Err(err) => {
                            error!("failed to shutdown socket: {:?}", err);
                            break;
                        }
                        _ => break,
                    }
                }
            }
        });

        // Clone all necessary data before spawning the task
        let answer_messages_tx_clone = answer_messages_tx.clone();
        let decrypt_cypher_clone = self.decrypt_cypher.clone();
        // Read Loop
        tokio::spawn(async move {
            loop {
                let next = reader.next().await;
                if next.is_none() {
                    info!("Read loop stopped because stream finished");
                    // If sending fails, the write loop is probably already closed
                    let _ = cancellation_write_tx.send("read loop finished");
                    break;
                }
                let frame = next.unwrap().unwrap();
                trace!("TCP Receive: {:02X?}", &frame);

                let message;
                if encrypted {
                    let mut decrypt_cipher_changer = decrypt_cypher_clone.lock().await;
                    message = packet_encrypted::packet_to_message(
                        &frame,
                        &mut *decrypt_cipher_changer.as_mut().unwrap(),
                    )
                    .unwrap();
                } else {
                    message = packet_plaintext::packet_to_message(&frame).unwrap();
                }

                // Authenticated Messages
                match &message {
                    ProtoMessage::DisconnectRequest(disconnect_request) => {
                        debug!("DisconnectRequest: {:?}", disconnect_request);
                        let response_message = DisconnectResponse {};
                        answer_messages_tx_clone
                            .send(ProtoMessage::DisconnectResponse(response_message))
                            .await
                            .unwrap();
                        continue;
                    }
                    ProtoMessage::PingRequest(ping_request) => {
                        debug!("PingRequest: {:?}", ping_request);
                        let response_message = PingResponse {};
                        answer_messages_tx_clone
                            .send(ProtoMessage::PingResponse(response_message))
                            .await
                            .unwrap();
                    }
                    ProtoMessage::DeviceInfoRequest(device_info_request) => {
                        debug!("DeviceInfoRequest: {:?}", device_info_request);
                        answer_messages_tx_clone
                            .send(ProtoMessage::DeviceInfoResponse(device_info.clone()))
                            .await
                            .unwrap();
                    }
                    ProtoMessage::HelloRequest(hello_request) => {
                        debug!("HelloRequest: {:?}", hello_request);

                        answer_messages_tx_clone
                            .send(ProtoMessage::HelloResponse(hello_response.clone()))
                            .await
                            .unwrap();
                    }
                    ProtoMessage::AuthenticationRequest(authentication_request) => {
                        debug!("AuthenticationRequest: {:?}", authentication_request);

                        if authentication_request.password != "" {
                            info!("Password Authentication is not supported");
                        } else {
                            let response_message = AuthenticationResponse {
                                invalid_password: false,
                            };
                            answer_messages_tx_clone
                                .send(ProtoMessage::AuthenticationResponse(response_message))
                                .await
                                .unwrap();
                        }
                    }
                    message => {
                        outgoing_messages_tx.send(message.clone()).unwrap();
                    }
                }
            }
        });

        Ok((answer_messages_tx.clone(), outgoing_messages_rx))
    }
}

/// No-std protocol implementation using [`embedded_io_async`] I/O traits.
///
/// These methods provide the full ESPHome server protocol in a single-task,
/// sequential model suitable for embedded environments (e.g. embassy-rs).
/// After building the [`EspHomeApi`] with the builder, call
/// [`init_connection`](EspHomeApi::init_connection) once to complete the
/// handshake, then drive [`process_message`](EspHomeApi::process_message) in
/// a loop.
#[cfg(not(feature = "std"))]
impl EspHomeApi {
    /// Detect the connection type (plaintext / encrypted) and, if encrypted,
    /// perform the Noise handshake.
    ///
    /// Must be called exactly once before [`process_message`](Self::process_message).
    pub async fn init_connection<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), &'static str>
    where
        R: embedded_io_async::Read,
        W: embedded_io_async::Write,
    {
        // Read the preamble byte to detect plaintext vs encrypted.
        let mut preamble = [0u8; 1];
        io_read_exact(reader, &mut preamble).await?;

        if preamble[0] == 0x00 {
            // Plaintext connection — nothing else to initialise.
            self.plaintext_communication = true;
            debug!("Plaintext connection detected");
            // Put the preamble byte back by processing the first full frame now.
            // The preamble is already consumed; frame_read_after_preamble will
            // read the varint length and payload.
            let frame = frame_read_plaintext_rest(reader).await?;
            // This must be the HelloRequest.
            let msg = packet_plaintext::packet_to_message(&frame)?;
            let hello_resp = self.build_hello_response();
            let hello_frame = packet_plaintext::message_to_packet(
                &ProtoMessage::HelloResponse(hello_resp),
            )?;
            frame_write_plaintext(writer, &hello_frame).await?;
            self.first_message_received = true;
            // Store the first message so process_message can return it.
            // We mark that hello has been exchanged; further protocol messages
            // (DeviceInfo, Ping …) are handled inside process_message.
            debug!("HelloRequest processed during init: {:?}", msg);
            return Ok(());
        }

        if preamble[0] == 0x01 {
            // Encrypted connection — Noise NN+PSK0 handshake.
            self.plaintext_communication = false;
            debug!("Encrypted connection detected — starting Noise handshake");

            let encryption_key = self
                .encryption_key
                .as_deref()
                .ok_or(ERROR_ONLY_ENCRYPTED)?;
            let key_bytes: Vec<u8> = BASE64_STANDARD
                .decode(encryption_key)
                .map_err(|_| "Invalid base64 encryption key")?;

            // Read the client's Noise hello frame (preamble already consumed).
            let noise_client_hello = frame_read_encrypted_rest(reader).await?;
            debug!("Noise client hello ({} bytes)", noise_client_hello.len());

            // Build and send the server hello (device name).
            let server_hello_payload = packet_encrypted::generate_server_hello_frame(
                self.name.clone(),
                self.mac.clone(),
            );
            frame_write_encrypted(writer, &server_hello_payload).await?;

            // Perform the Noise handshake.
            let mut handshake_state: HandshakeState<X25519, ChaCha20Poly1305, Sha256> =
                HandshakeState::new(
                    noise_nn_psk0(),
                    false, // we are the responder
                    b"NoiseAPIInit\0\0",
                    None,
                    None,
                    None,
                    None,
                );
            handshake_state.push_psk(&key_bytes);

            // Read the client handshake message.
            let client_handshake_frame = frame_read_encrypted_rest(reader).await?;
            let read_overhead = handshake_state.get_next_message_overhead();
            let out_len = client_handshake_frame.len().saturating_sub(read_overhead);
            let mut handshake_payload_buf = alloc::vec![0u8; out_len];
            handshake_state
                .read_message(&client_handshake_frame, &mut handshake_payload_buf)
                .map_err(|e| match e.kind() {
                    ErrorKind::DH => "Handshake DH error",
                    ErrorKind::Decryption => ERROR_HANDSHAKE_MAC_FAILURE,
                    _ => "Handshake error",
                })?;

            // Write the server handshake response.
            let write_overhead = handshake_state.get_next_message_overhead();
            let mut server_handshake_buf = alloc::vec![0u8; write_overhead]; // empty payload
            handshake_state
                .write_message(&[], &mut server_handshake_buf)
                .map_err(|_| "Handshake write error")?;
            frame_write_encrypted(writer, &server_handshake_buf).await?;

            // Extract the session ciphers.
            let (decrypt_cipher, encrypt_cipher) = handshake_state.get_ciphers();
            self.encrypt_cypher = Some(encrypt_cipher);
            self.decrypt_cypher = Some(decrypt_cipher);

            debug!("Noise handshake complete");
            return Ok(());
        }

        Err("Unknown preamble byte")
    }

    /// Read and handle one ESPHome protocol message from the connection.
    ///
    /// Protocol-level messages (Hello, Ping, DeviceInfo, Authentication,
    /// Disconnect) are handled internally and their responses are sent
    /// automatically. Application messages are returned to the caller.
    ///
    /// Returns `Err` on I/O or decoding failure.
    pub async fn process_message<R, W>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<ProtoMessage, &'static str>
    where
        R: embedded_io_async::Read,
        W: embedded_io_async::Write,
    {
        loop {
            let message = if self.plaintext_communication {
                let frame = frame_read_plaintext(reader).await?;
                packet_plaintext::packet_to_message(&frame)?
            } else {
                let frame = frame_read_encrypted(reader).await?;
                let cipher = self.decrypt_cypher.as_mut().ok_or("No decrypt cipher")?;
                packet_encrypted::packet_to_message(&frame, cipher)?
            };

            debug!("Received message: {:?}", message);

            match message {
                ProtoMessage::HelloRequest(hello_request) => {
                    debug!("HelloRequest: {:?}", hello_request);
                    let resp = self.build_hello_response();
                    self.send_message(writer, &ProtoMessage::HelloResponse(resp))
                        .await?;
                }
                ProtoMessage::PingRequest(ping_request) => {
                    debug!("PingRequest: {:?}", ping_request);
                    self.send_message(writer, &ProtoMessage::PingResponse(PingResponse {}))
                        .await?;
                }
                ProtoMessage::DeviceInfoRequest(req) => {
                    debug!("DeviceInfoRequest: {:?}", req);
                    let info = self.build_device_info();
                    self.send_message(writer, &ProtoMessage::DeviceInfoResponse(info))
                        .await?;
                }
                ProtoMessage::AuthenticationRequest(req) => {
                    debug!("AuthenticationRequest: {:?}", req);
                    if !req.password.is_empty() {
                        info!("Password Authentication is not supported");
                    }
                    self.send_message(
                        writer,
                        &ProtoMessage::AuthenticationResponse(AuthenticationResponse {
                            invalid_password: false,
                        }),
                    )
                    .await?;
                }
                ProtoMessage::DisconnectRequest(req) => {
                    debug!("DisconnectRequest: {:?}", req);
                    self.send_message(
                        writer,
                        &ProtoMessage::DisconnectResponse(DisconnectResponse {}),
                    )
                    .await?;
                    return Err("Client disconnected");
                }
                other => return Ok(other),
            }
        }
    }

    /// Send a single message to the client.
    pub async fn send_message<W>(
        &mut self,
        writer: &mut W,
        message: &ProtoMessage,
    ) -> Result<(), &'static str>
    where
        W: embedded_io_async::Write,
    {
        if self.plaintext_communication {
            let frame = packet_plaintext::message_to_packet(message)?;
            frame_write_plaintext(writer, &frame).await
        } else {
            let cipher = self.encrypt_cypher.as_mut().ok_or("No encrypt cipher")?;
            let frame = packet_encrypted::message_to_packet(message, cipher)?;
            frame_write_encrypted(writer, &frame).await
        }
    }

    fn build_hello_response(&self) -> HelloResponse {
        HelloResponse {
            api_version_major: self.api_version_major,
            api_version_minor: self.api_version_minor,
            server_info: self.server_info.clone(),
            name: self.name.clone(),
        }
    }

    #[allow(deprecated)]
    fn build_device_info(&self) -> DeviceInfoResponse {
        DeviceInfoResponse {
            api_encryption_supported: self.encryption_key.is_some(),
            uses_password: false,
            name: self.name.clone(),
            mac_address: self.mac.clone().unwrap_or_default(),
            esphome_version: proto::VERSION.to_owned(),
            compilation_time: self.compilation_time.clone().unwrap_or_default(),
            model: self.model.clone().unwrap_or_default(),
            has_deep_sleep: false,
            project_name: self.project_name.clone().unwrap_or_default(),
            project_version: self.project_version.clone().unwrap_or_default(),
            webserver_port: 0,
            legacy_bluetooth_proxy_version: self.legacy_bluetooth_proxy_version,
            bluetooth_proxy_feature_flags: self.bluetooth_proxy_feature_flags,
            manufacturer: self.manufacturer.clone().unwrap_or_default(),
            friendly_name: self.friendly_name.clone().unwrap_or(self.name.clone()),
            legacy_voice_assistant_version: self.legacy_voice_assistant_version,
            voice_assistant_feature_flags: self.voice_assistant_feature_flags,
            suggested_area: self.suggested_area.clone().unwrap_or_default(),
            bluetooth_mac_address: self.bluetooth_mac_address.clone().unwrap_or_default(),
            areas: vec![],
            devices: vec![],
            area: None,
            zwave_proxy_feature_flags: 0,
            zwave_home_id: 0,
        }
    }
}

// ── No-std frame I/O helpers ──────────────────────────────────────────────────

/// Read exactly `n` bytes.
#[cfg(not(feature = "std"))]
async fn io_read_exact<R>(reader: &mut R, buf: &mut [u8]) -> Result<(), &'static str>
where
    R: embedded_io_async::Read,
{
    let mut offset = 0;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]).await {
            Ok(0) => return Err("Unexpected EOF"),
            Ok(n) => offset += n,
            Err(_) => return Err("I/O read error"),
        }
    }
    Ok(())
}

/// Write all bytes and flush.
#[cfg(not(feature = "std"))]
async fn io_write_all<W>(writer: &mut W, buf: &[u8]) -> Result<(), &'static str>
where
    W: embedded_io_async::Write,
{
    let mut offset = 0;
    while offset < buf.len() {
        match writer.write(&buf[offset..]).await {
            Ok(0) => return Err("Unexpected EOF on write"),
            Ok(n) => offset += n,
            Err(_) => return Err("I/O write error"),
        }
    }
    writer.flush().await.map_err(|_| "I/O flush error")
}

/// Read an encrypted frame (preamble byte already consumed).
/// Returns the raw encrypted payload.
#[cfg(not(feature = "std"))]
async fn frame_read_encrypted_rest<R>(reader: &mut R) -> Result<Vec<u8>, &'static str>
where
    R: embedded_io_async::Read,
{
    let mut len_bytes = [0u8; 2];
    io_read_exact(reader, &mut len_bytes).await?;
    let length = u16::from_be_bytes(len_bytes) as usize;
    let mut payload = alloc::vec![0u8; length];
    io_read_exact(reader, &mut payload).await?;
    Ok(payload)
}

/// Read a complete encrypted frame (including preamble byte).
#[cfg(not(feature = "std"))]
async fn frame_read_encrypted<R>(reader: &mut R) -> Result<Vec<u8>, &'static str>
where
    R: embedded_io_async::Read,
{
    let mut preamble = [0u8; 1];
    io_read_exact(reader, &mut preamble).await?;
    if preamble[0] != 0x01 {
        return Err("Expected encrypted frame (preamble 0x01)");
    }
    frame_read_encrypted_rest(reader).await
}

/// Write an encrypted frame: `[0x01][u16_be_len][payload]`.
#[cfg(not(feature = "std"))]
async fn frame_write_encrypted<W>(writer: &mut W, payload: &[u8]) -> Result<(), &'static str>
where
    W: embedded_io_async::Write,
{
    let len = (payload.len() as u16).to_be_bytes();
    io_write_all(writer, &[0x01]).await?;
    io_write_all(writer, &len).await?;
    io_write_all(writer, payload).await
}

/// Read a plaintext frame's contents after the preamble byte has already
/// been consumed.  Returns `[msg_type, payload...]`.
#[cfg(not(feature = "std"))]
async fn frame_read_plaintext_rest<R>(reader: &mut R) -> Result<Vec<u8>, &'static str>
where
    R: embedded_io_async::Read,
{
    use prost::decode_length_delimiter;
    // Read the varint length.
    let mut length_raw = [0u8; 1];
    let mut varint_bytes: Vec<u8> = Vec::new();
    loop {
        io_read_exact(reader, &mut length_raw).await?;
        varint_bytes.push(length_raw[0]);
        if length_raw[0] & 0x80 == 0 {
            break;
        }
        if varint_bytes.len() > 4 {
            return Err("Varint too long");
        }
    }
    // length does NOT include the msg_type byte, so read length+1 bytes.
    let length = decode_length_delimiter(varint_bytes.as_slice())
        .map_err(|_| "Varint decode error")? as usize;
    let mut data = alloc::vec![0u8; length + 1];
    io_read_exact(reader, &mut data).await?;
    Ok(data)
}

/// Read a complete plaintext frame (including the 0x00 preamble byte).
/// Returns `[msg_type, payload...]`.
#[cfg(not(feature = "std"))]
async fn frame_read_plaintext<R>(reader: &mut R) -> Result<Vec<u8>, &'static str>
where
    R: embedded_io_async::Read,
{
    let mut preamble = [0u8; 1];
    io_read_exact(reader, &mut preamble).await?;
    if preamble[0] != 0x00 {
        return Err("Expected plaintext frame (preamble 0x00)");
    }
    frame_read_plaintext_rest(reader).await
}

/// Write a plaintext frame: `[0x00][varint(len-1)][msg_type][payload...]`.
#[cfg(not(feature = "std"))]
async fn frame_write_plaintext<W>(writer: &mut W, data: &[u8]) -> Result<(), &'static str>
where
    W: embedded_io_async::Write,
{
    use prost::encode_length_delimiter;
    // length = bytes after the msg_type byte
    let length = data.len() - 1;
    let mut len_buf: Vec<u8> = Vec::new();
    encode_length_delimiter(length, &mut len_buf).map_err(|_| "Varint encode error")?;
    io_write_all(writer, &[0x00]).await?;
    io_write_all(writer, &len_buf).await?;
    io_write_all(writer, data).await
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_basic_server_instantiation() {
        EspHomeApi::builder()
            .name("test_device".to_string())
            .build();
    }
}
