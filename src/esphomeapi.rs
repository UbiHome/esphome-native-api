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
use futures::sink::SinkExt;
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
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tokio_util::codec::FramedWrite;
use typed_builder::TypedBuilder;

use crate::error::{DisconnectReason, Error, FrameError, HandshakeError};
use crate::frame::FrameCodec;
use crate::packet_encrypted;
use crate::packet_plaintext;
use crate::parser::ProtoMessage;
use crate::proto::{
    self, AuthenticationResponse, DeviceInfoResponse, DisconnectResponse, HelloResponse,
    PingResponse,
};

async fn write_error_and_disconnect<W>(mut writer: FramedWrite<W, FrameCodec>, message: &str)
where
    W: AsyncWrite + Unpin,
{
    error!("API Failure: {}. Disconnecting.", message);
    let packet = [[1].to_vec(), message.as_bytes().to_vec()].concat();
    if let Err(err) = writer.send(packet).await {
        debug!("failed to send error frame to peer: {:?}", err);
    }
    if let Err(err) = writer.flush().await {
        debug!("failed to flush error frame to peer: {:?}", err);
    }
    let mut tcp_write = writer.into_inner();
    if let Err(err) = tcp_write.shutdown().await {
        error!("failed to shutdown socket: {:?}", err);
    }
}

/// Classify an I/O error surfaced by the framed reader into a typed [`Error`].
///
/// A peer going away (`ConnectionReset`, `BrokenPipe`, …) is an expected
/// terminal condition, not a failure; malformed framing is a [`FrameError`];
/// anything else is a genuine I/O fault.
fn classify_read_error(err: std::io::Error) -> Error {
    use std::io::ErrorKind::*;
    match err.kind() {
        ConnectionReset | BrokenPipe | ConnectionAborted | NotConnected | UnexpectedEof => {
            Error::Disconnected(DisconnectReason::Reset(err.kind()))
        }
        InvalidData => Error::Frame(FrameError::Malformed(err.to_string())),
        _ => Error::Io(err),
    }
}

/// Whether a writer-side I/O error means the peer has gone away (so we should
/// terminate quietly rather than log a fault).
fn is_peer_gone(err: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        err.kind(),
        ConnectionReset | BrokenPipe | ConnectionAborted | NotConnected
    )
}

/// Map a writer-side I/O error during the handshake into a typed [`Error`].
fn handshake_write_err(err: std::io::Error) -> Error {
    if is_peer_gone(&err) {
        Error::Handshake(HandshakeError::Aborted)
    } else {
        Error::Io(err)
    }
}

/// Read the next frame during the handshake phase, mapping a mid-handshake
/// disconnect to [`HandshakeError::Aborted`].
async fn read_handshake_frame<R>(reader: &mut FramedRead<R, FrameCodec>) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    match reader.next().await {
        Some(Ok(frame)) => Ok(frame),
        Some(Err(e)) => Err(classify_read_error(e)),
        None => Err(Error::Handshake(HandshakeError::Aborted)),
    }
}

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
    pub async fn start<S>(
        &self,
        stream: S,
    ) -> Result<
        (
            mpsc::Sender<ProtoMessage>,
            broadcast::Receiver<ProtoMessage>,
        ),
        Box<dyn std::error::Error>,
    >
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
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
            serial_proxies: vec![],
        };

        let hello_response = HelloResponse {
            api_version_major: self.api_version_major,
            api_version_minor: self.api_version_minor,
            server_info: self.server_info.clone(),
            name: self.name.clone(),
        };

        // Per-connection cipher state — created fresh so multiple concurrent connections
        // never share encryption context.
        let encrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>> =
            Arc::new(Mutex::new(None));
        let decrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>> =
            Arc::new(Mutex::new(None));

        // Stage 1: Initialization
        trace!("Init Connection: Stage 1");
        let encryption_key = self.encryption_key.clone();

        let (stream_read, stream_write) = tokio::io::split(stream);
        let mut stream_read = BufReader::new(stream_read);

        let peeked_bytes = stream_read.fill_buf().await?;
        if peeked_bytes.is_empty() {
            return Err(HandshakeError::NoData.into());
        }

        trace!("TCP Peeked: {:02X?}", &peeked_bytes[0..1]);

        let preamble = peeked_bytes[0] as usize;

        let plaintext_communication = match preamble {
            0 => {
                debug!("Cleartext messaging");
                true
            }
            1 => {
                trace!("Encrypted messaging");
                false
            }
            _ => {
                return Err(HandshakeError::InvalidMarker(preamble as u8).into());
            }
        };
        let encrypted = !plaintext_communication;

        let decoder = FrameCodec::new(encrypted);
        let encoder = FrameCodec::new(encrypted);
        let mut reader = FramedRead::new(stream_read, decoder);
        let mut writer = FramedWrite::new(stream_write, encoder);

        if plaintext_communication {
            if self.encryption_key.is_some() {
                let encoder = FrameCodec::new(true);
                let writer = FramedWrite::new(writer.into_inner(), encoder);
                let err = HandshakeError::OnlyEncryptedAllowed;
                write_error_and_disconnect(writer, &err.to_string()).await;
                return Err(err.into());
            }
        } else {
            if self.encryption_key.is_none() {
                write_error_and_disconnect(writer, "No encrypted communication allowed").await;
                return Err(HandshakeError::EncryptionNotAllowed.into());
            }

            let frame_noise_hello = read_handshake_frame(&mut reader).await?;
            debug!("Frame 1: {:02X?}", &frame_noise_hello);

            let message_server_hello =
                packet_encrypted::generate_server_hello_frame(self.name.clone(), self.mac.clone());

            writer
                .send(message_server_hello.clone())
                .await
                .map_err(handshake_write_err)?;
            writer.flush().await.map_err(handshake_write_err)?;

            let frame_handshake_request = read_handshake_frame(&mut reader).await?;
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
                .map_err(|e| Error::Config(format!("encryption key is not valid base64: {e}")))?;

            handshake_state.push_psk(&noise_psk);
            // Ignore message type byte
            match handshake_state.read_message_vec(&frame_handshake_request[1..]) {
                Ok(_) => {}
                Err(e) => match e.kind() {
                    ErrorKind::Decryption => {
                        let err = HandshakeError::MacFailure;
                        write_error_and_disconnect(writer, &err.to_string()).await;
                        return Err(err.into());
                    }
                    _ => {
                        debug!("Failed to read message: {}", e);
                    }
                },
            }

            let out = handshake_state
                .write_message_vec(b"")
                .map_err(|e| Error::Handshake(HandshakeError::Crypto(e.to_string())))?;
            {
                let mut encrypt_cipher_changer = encrypt_cypher.lock().await;
                let mut decrypt_cipher_changer = decrypt_cypher.lock().await;
                let (decrypt_cipher, encrypt_cipher) = handshake_state.get_ciphers();
                *encrypt_cipher_changer = Some(encrypt_cipher);
                *decrypt_cipher_changer = Some(decrypt_cipher);
            }

            let mut message_handshake = vec![0];
            message_handshake.extend(out);

            debug!("Sending handshake");
            writer
                .send(message_handshake.clone())
                .await
                .map_err(handshake_write_err)?;
            writer.flush().await.map_err(handshake_write_err)?;
        }

        debug!("Initialization done.");

        // Asynchronously wait for an inbound socket.
        let (cancellation_write_tx, mut cancellation_write_rx) = oneshot::channel();

        // Write Loop
        let encrypt_cypher_for_write = encrypt_cypher;
        tokio::spawn(async move {
            loop {
                // Wait for any new message
                let answer_message = tokio::select! {
                    biased; // Poll cancellation_write_rx first
                    cancel_message = &mut cancellation_write_rx => {
                        match cancel_message {
                            Ok(reason) => debug!("Write loop received cancellation signal ({reason}), exiting."),
                            Err(_) => debug!("Write loop cancellation channel dropped, exiting."),
                        }
                        break;
                    }
                    message = answer_messages_rx.recv() => match message {
                        Some(message) => message,
                        None => {
                            debug!("Write loop: all senders dropped, exiting.");
                            break;
                        }
                    }
                };

                debug!("Answer message: {:?}", answer_message);

                let packet = if plaintext_communication {
                    match packet_plaintext::message_to_packet(&answer_message) {
                        Ok(packet) => packet,
                        Err(e) => {
                            error!("Write loop: failed to encode outgoing message: {e}");
                            break;
                        }
                    }
                } else {
                    // Use normal messaging
                    let mut encrypt_cipher_changer = encrypt_cypher_for_write.lock().await;
                    let cipher = match encrypt_cipher_changer.as_mut() {
                        Some(cipher) => cipher,
                        None => {
                            error!("Write loop: encryption cipher not initialized, exiting.");
                            break;
                        }
                    };
                    match packet_encrypted::message_to_packet(&answer_message, cipher) {
                        Ok(packet) => packet,
                        Err(e) => {
                            error!("Write loop: failed to encode outgoing message: {e}");
                            break;
                        }
                    }
                };

                if let Err(e) = writer.send(packet).await {
                    if is_peer_gone(&e) {
                        debug!("Write loop: peer gone while sending, exiting.");
                    } else {
                        error!("Write loop: failed to send message: {e}");
                    }
                    break;
                }
                if let Err(e) = writer.flush().await {
                    if is_peer_gone(&e) {
                        debug!("Write loop: peer gone while flushing, exiting.");
                    } else {
                        error!("Write loop: failed to flush message: {e}");
                    }
                    break;
                }

                if matches!(answer_message, ProtoMessage::DisconnectResponse(_)) {
                    debug!("Disconnecting");
                    let mut tcp_write = writer.into_inner();
                    if let Err(err) = tcp_write.shutdown().await {
                        error!("failed to shutdown socket: {:?}", err);
                    }
                    break;
                }
            }
        });

        // Clone all necessary data before spawning the task
        let answer_messages_tx_clone = answer_messages_tx.clone();
        // Read Loop
        tokio::spawn(async move {
            let outcome: Result<(), Error> = async move {
                let mut disconnect_requested = false;
                loop {
                    let frame = match reader.next().await {
                        None => {
                            return Err(Error::Disconnected(if disconnect_requested {
                                DisconnectReason::Requested
                            } else {
                                DisconnectReason::Eof
                            }));
                        }
                        Some(Ok(frame)) => frame,
                        Some(Err(e)) => return Err(classify_read_error(e)),
                    };
                    trace!("TCP Receive: {:02X?}", &frame);

                    let decoded = if encrypted {
                        let mut decrypt_cipher_changer = decrypt_cypher.lock().await;
                        match decrypt_cipher_changer.as_mut() {
                            Some(cipher) => packet_encrypted::packet_to_message(&frame, cipher),
                            None => Err(FrameError::Malformed(
                                "decryption cipher not initialized".to_string(),
                            )),
                        }
                    } else {
                        packet_plaintext::packet_to_message(&frame)
                    };

                    let message = match decoded {
                        Ok(message) => message,
                        // Forward-compatible: an unknown message type (for example
                        // one introduced by a newer ESPHome release) is skipped so
                        // the connection stays healthy instead of being torn down.
                        Err(FrameError::UnknownMessageType(message_type)) => {
                            debug!("Ignoring unknown message type {message_type}");
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                    };

                    // Protocol-level messages we answer ourselves produce a
                    // response; everything else is forwarded to the consumer.
                    let response: Option<ProtoMessage> = match &message {
                        ProtoMessage::DisconnectRequest(disconnect_request) => {
                            debug!("DisconnectRequest: {:?}", disconnect_request);
                            disconnect_requested = true;
                            Some(ProtoMessage::DisconnectResponse(DisconnectResponse {}))
                        }
                        ProtoMessage::PingRequest(ping_request) => {
                            debug!("PingRequest: {:?}", ping_request);
                            Some(ProtoMessage::PingResponse(PingResponse {}))
                        }
                        ProtoMessage::DeviceInfoRequest(device_info_request) => {
                            debug!("DeviceInfoRequest: {:?}", device_info_request);
                            Some(ProtoMessage::DeviceInfoResponse(device_info.clone()))
                        }
                        ProtoMessage::HelloRequest(hello_request) => {
                            debug!("HelloRequest: {:?}", hello_request);
                            Some(ProtoMessage::HelloResponse(hello_response.clone()))
                        }
                        ProtoMessage::AuthenticationRequest(authentication_request) => {
                            debug!("AuthenticationRequest: {:?}", authentication_request);
                            if !authentication_request.password.is_empty() {
                                info!("Password Authentication is not supported");
                                None
                            } else {
                                Some(ProtoMessage::AuthenticationResponse(
                                    AuthenticationResponse {
                                        invalid_password: false,
                                    },
                                ))
                            }
                        }
                        other => {
                            // No active receivers is normal (the consumer dropped
                            // its handle); drop the message rather than panicking.
                            let _ = outgoing_messages_tx.send(other.clone());
                            None
                        }
                    };

                    if let Some(response) = response
                        && answer_messages_tx_clone.send(response).await.is_err()
                    {
                        // The write loop has stopped; the connection is finished.
                        return Err(Error::Disconnected(DisconnectReason::Eof));
                    }
                }
            }
            .await;

            match &outcome {
                Ok(()) => {}
                Err(Error::Disconnected(reason)) => info!("Read loop stopped: {reason}"),
                Err(e) => error!("Read loop stopped with error: {e}"),
            }
            // If sending fails, the write loop is probably already closed.
            let _ = cancellation_write_tx.send("read loop finished");
        });

        Ok((answer_messages_tx.clone(), outgoing_messages_rx))
    }
}
