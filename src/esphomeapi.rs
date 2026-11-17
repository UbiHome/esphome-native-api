//! Low-level ESPHome native API implementation.
//!
//! This module provides [`EspHomeApi`], which handles the core protocol communication
//! with ESPHome devices. It manages connection establishment, encryption handshakes,
//! message framing, and protocol state.
//!
//! The protocol itself lives in [`crate::protocol::Protocol`], a state machine
//! without any I/O. [`EspHomeApi`] drives it over a tokio stream; use the state
//! machine directly to run the protocol on another runtime or without `std`.
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
//!         .build()?;
//!
//!     let connection = api.start(stream).await?;
//!     let tx = connection.sender();
//!     let mut rx = connection.receiver();
//!     # let _ = (tx, &mut rx);
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
//!         .build()?;
//!
//!     let connection = api.start(stream).await?;
//!     let tx = connection.sender();
//!     let mut rx = connection.receiver();
//!     # let _ = (tx, &mut rx);
//!     Ok(())
//! }
//! ```

use log::debug;
use log::error;
use log::info;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use typed_builder::TypedBuilder;

use crate::connection::Connection;
use crate::error::{DisconnectReason, Error, FrameError, HandshakeError};
use crate::parser::ProtoMessage;
use crate::proto::{self, DeviceInfoResponse, HelloResponse};
use crate::protocol::{self, Config, Event, Protocol};

/// Size of the buffer bytes are read into from the stream.
const READ_BUFFER_SIZE: usize = 4096;

/// Classify an I/O error surfaced while reading into a typed [`Error`].
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

/// Map an I/O error during the handshake into a typed [`Error`], treating a
/// peer that went away as [`HandshakeError::Aborted`].
fn handshake_io_err(err: std::io::Error) -> Error {
    if is_peer_gone(&err) || err.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Handshake(HandshakeError::Aborted)
    } else {
        Error::Io(err)
    }
}

/// The terminal outcome for a stream that reached end of file.
///
/// A stream that ends in the middle of a frame is reported as an I/O error;
/// everything else is decided by the protocol state.
fn eof_error(protocol: &mut Protocol) -> Error {
    if !protocol.is_closed() && protocol.has_buffered_data() {
        let _ = protocol.on_eof();
        return Error::Io(std::io::Error::other("bytes remaining on stream"));
    }
    protocol.on_eof()
}

/// Write `bytes` to the peer and flush them.
async fn write_frame<W>(writer: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(bytes).await?;
    writer.flush().await
}

/// Receive the next message the consumer wants to send, or wait forever once
/// nothing can be sent anymore.
async fn next_outgoing(
    receiver: &mut Option<mpsc::Receiver<ProtoMessage>>,
) -> Option<ProtoMessage> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// Drives an established connection until it ends: moves bytes between the
/// stream and the [`Protocol`] state machine and messages between the state
/// machine and the consumer's channels. Returns why the connection ended.
async fn run_connection<S>(
    mut protocol: Protocol,
    mut reader: ReadHalf<S>,
    mut writer: WriteHalf<S>,
    outgoing_rx: mpsc::Receiver<ProtoMessage>,
    incoming_tx: broadcast::Sender<ProtoMessage>,
    mut buffer: Vec<u8>,
) -> Error
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // `None` once no further message of the consumer can be sent. Dropping the
    // receiver makes the consumer's `send` fail, so it notices as well.
    let mut outgoing_rx = Some(outgoing_rx);

    loop {
        // Act on everything the state machine has to say.
        loop {
            match protocol.poll() {
                Ok(Some(Event::Transmit(bytes))) => {
                    if let Err(e) = write_frame(&mut writer, &bytes).await {
                        if is_peer_gone(&e) {
                            debug!("Peer gone while sending, closing write side.");
                        } else {
                            error!("Failed to send message: {e}");
                        }
                        protocol.close_write();
                        outgoing_rx = None;
                    }
                }
                Ok(Some(Event::Message(message))) => {
                    // No active receivers is normal (the consumer dropped its
                    // handle); the message is simply dropped.
                    let _ = incoming_tx.send(message);
                }
                Ok(Some(Event::Close)) => {
                    debug!("Disconnecting");
                    if let Err(err) = writer.shutdown().await {
                        error!("failed to shutdown socket: {:?}", err);
                    }
                    outgoing_rx = None;
                }
                Ok(Some(Event::Connected)) => {}
                Ok(None) => break,
                Err(e) => return e,
            }
        }

        // Wait for bytes from the peer or a message from the consumer.
        tokio::select! {
            read = reader.read(&mut buffer) => match read {
                Ok(0) => return eof_error(&mut protocol),
                Ok(n) => protocol.receive(&buffer[..n]),
                Err(e) => return classify_read_error(e),
            },
            message = next_outgoing(&mut outgoing_rx) => match message {
                Some(message) => {
                    if let Err(e) = protocol.send(&message) {
                        error!("Failed to encode outgoing message: {e}");
                        protocol.close_write();
                        outgoing_rx = None;
                    }
                }
                None => {
                    debug!("All senders dropped, no further messages to send.");
                    outgoing_rx = None;
                }
            },
        }
    }
}

/// Fallible output of [`EspHomeApi`]'s builder. An `Err` means the configuration
/// was invalid — currently, an encryption key that is not valid base64.
pub type EspHomeApiBuildResult = Result<EspHomeApi, Error>;

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
///     .build().unwrap();
/// ```
#[derive(TypedBuilder, Clone)]
#[builder(build_method(into = EspHomeApiBuildResult))]
pub struct EspHomeApi {
    // Private fields
    name: String,

    #[builder(default = None, setter(strip_option(fallback=encryption_key_opt)))]
    encryption_key: Option<String>,

    /// Decoded pre-shared key, populated from `encryption_key` at build time so
    /// that a misconfigured key fails during `build()` rather than at connect.
    #[builder(default, setter(skip))]
    noise_psk: Option<Vec<u8>>,

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

/// Validates and decodes the configured encryption key when the builder's
/// `build()` runs, so a misconfiguration surfaces as [`Error::Config`] at
/// construction rather than partway through the connection handshake.
impl From<EspHomeApi> for EspHomeApiBuildResult {
    fn from(mut api: EspHomeApi) -> Self {
        api.noise_psk = match api.encryption_key.as_deref() {
            Some(key) => Some(protocol::decode_encryption_key(key)?),
            None => None,
        };
        Ok(api)
    }
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
    /// Returns a [`Connection`] handle. Use [`Connection::sender`] to send
    /// messages to the device, [`Connection::receiver`] to receive messages from
    /// it, and [`Connection::wait`] to observe when — and why — the connection
    /// ends.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if:
    /// - The connection fails ([`Error::Io`])
    /// - The encryption handshake fails ([`Error::Handshake`])
    /// - The device requires encryption but no key was provided
    /// - The peer disconnects mid-handshake ([`Error::Disconnected`])
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use esphome_native_api::esphomeapi::EspHomeApi;
    /// # use tokio::net::TcpStream;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let stream = TcpStream::connect("192.168.1.100:6053").await?;
    /// let api = EspHomeApi::builder().name("client".to_string()).build()?;
    /// let connection = api.start(stream).await?;
    /// let tx = connection.sender();
    /// let mut rx = connection.receiver();
    /// # let _ = (tx, &mut rx);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start<S>(&self, stream: S) -> Result<Connection, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::start_protocol(Protocol::new(self.protocol_config()), stream).await
    }

    /// Configuration of the protocol state machine for a new connection.
    fn protocol_config(&self) -> Config {
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
            api_encryption_provisionable: false,
            api_outgoing_connection_supported: false,
        };

        let hello_response = HelloResponse {
            api_version_major: self.api_version_major,
            api_version_minor: self.api_version_minor,
            server_info: self.server_info.clone(),
            name: self.name.clone(),
        };

        let mut config = Config::new(self.name.clone());
        config.mac = self.mac.clone();
        config.noise_psk = self.noise_psk.clone();
        config.hello_response = hello_response;
        config.device_info = device_info;
        config
    }

    /// Runs the handshake of `protocol` over `stream` and, once it succeeded,
    /// hands the connection to a background task.
    async fn start_protocol<S>(mut protocol: Protocol, stream: S) -> Result<Connection, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Channel for messages
        let (answer_messages_tx, answer_messages_rx) = mpsc::channel::<ProtoMessage>(16);
        let (outgoing_messages_tx, outgoing_messages_rx) = broadcast::channel::<ProtoMessage>(16);

        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut buffer = vec![0u8; READ_BUFFER_SIZE];

        // Handshake: all the protocol logic lives in the state machine; this
        // loop only moves bytes until it reports the connection as established.
        let mut first_read = true;
        loop {
            match protocol.poll() {
                Ok(Some(Event::Connected)) => break,
                Ok(Some(Event::Transmit(bytes))) => {
                    if let Err(err) = write_frame(&mut writer, &bytes).await {
                        if protocol.is_closed() {
                            // Farewell for a rejected peer: best effort, the
                            // rejection itself is what gets reported.
                            debug!("failed to send error frame to peer: {:?}", err);
                        } else {
                            return Err(handshake_io_err(err));
                        }
                    }
                }
                Ok(Some(Event::Close)) => {
                    if let Err(err) = writer.shutdown().await {
                        error!("failed to shutdown socket: {:?}", err);
                    }
                }
                // Messages are only produced once the connection is established.
                Ok(Some(Event::Message(_))) => {}
                Ok(None) => {
                    let read = reader.read(&mut buffer).await.map_err(|err| {
                        if first_read {
                            handshake_io_err(err)
                        } else {
                            // A mid-handshake disconnect is an aborted handshake.
                            match classify_read_error(err) {
                                Error::Disconnected(_) => HandshakeError::Aborted.into(),
                                other => other,
                            }
                        }
                    })?;
                    first_read = false;
                    if read == 0 {
                        return Err(eof_error(&mut protocol));
                    }
                    protocol.receive(&buffer[..read]);
                }
                Err(e) => {
                    error!("API Failure: {}. Disconnecting.", e);
                    return Err(e);
                }
            }
        }

        // Reports the connection's terminal outcome to `Connection::wait`.
        let (done_tx, done_rx) = oneshot::channel::<Result<(), Error>>();

        tokio::spawn(async move {
            let outcome = run_connection(
                protocol,
                reader,
                writer,
                answer_messages_rx,
                outgoing_messages_tx,
                buffer,
            )
            .await;

            match &outcome {
                Error::Disconnected(reason) => info!("Connection closed: {reason}"),
                e => error!("Connection stopped with error: {e}"),
            }
            // Report the terminal outcome to the consumer (ignored if dropped).
            let _ = done_tx.send(Err(outcome));
        });

        Ok(Connection::new(
            answer_messages_tx,
            outgoing_messages_rx,
            done_rx,
        ))
    }
}
