//! Sans-IO implementation of the device side of the ESPHome native API.
//!
//! [`Protocol`] is a pure state machine: it never touches a socket, a timer or
//! an async runtime. The caller moves bytes between the transport and the
//! state machine and acts on the [`Event`]s it produces:
//!
//! 1. Feed every chunk of bytes read from the transport into
//!    [`Protocol::receive`].
//! 2. Call [`Protocol::poll`] until it returns `Ok(None)` and act on each
//!    [`Event`]: write [`Event::Transmit`] bytes to the transport, hand
//!    [`Event::Message`]s to the application, close the transport on
//!    [`Event::Close`].
//! 3. Queue outgoing messages with [`Protocol::send`]; they come back out of
//!    [`Protocol::poll`] as [`Event::Transmit`].
//! 4. When the transport reports end of stream, [`Protocol::on_eof`] tells why
//!    the connection ended.
//!
//! The state machine detects plaintext vs. encrypted clients, performs the
//! noise handshake and answers the protocol level requests (`Hello`,
//! `Authentication`, `DeviceInfo`, `Ping` and `Disconnect`) on its own. This is
//! the same logic [`crate::esphomeapi::EspHomeApi`] runs on top of tokio, but it
//! only needs `core` and `alloc`, so it can be driven from any runtime — or
//! none at all, for example on an embedded device.
//!
//! # Examples
//!
//! ```rust
//! use esphome_native_api::protocol::{Config, Event, Protocol};
//!
//! let mut protocol = Protocol::new(Config::new("my-device"));
//!
//! // A plaintext `HelloRequest`, as read from the transport.
//! protocol.receive(&[
//!     0x00, 0x13, 0x01, 0x0a, 0x0d, 0x61, 0x69, 0x6f, 0x65, 0x73, 0x70, 0x68, 0x6f, 0x6d, 0x65,
//!     0x61, 0x70, 0x69, 0x10, 0x01, 0x18, 0x0a,
//! ]);
//!
//! let mut to_transport = Vec::new();
//! while let Some(event) = protocol.poll()? {
//!     match event {
//!         // The handshake is done, messages can be sent from now on.
//!         Event::Connected => {}
//!         // Bytes to write to the transport (here: the `HelloResponse`).
//!         Event::Transmit(bytes) => to_transport.extend(bytes),
//!         // A message for the application.
//!         Event::Message(message) => println!("{message:?}"),
//!         // Close the transport once everything transmitted so far is written.
//!         Event::Close => {}
//!         _ => {}
//!     }
//! }
//! assert!(protocol.is_established());
//! assert!(!to_transport.is_empty());
//! # Ok::<(), esphome_native_api::Error>(())
//! ```

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use base64::prelude::*;
use log::{debug, info, trace};
use noise_protocol::patterns::noise_nn_psk0;
use noise_protocol::{CipherState, ErrorKind, HandshakeState};
use noise_rust_crypto::{ChaCha20Poly1305, Sha256, X25519};

use crate::error::{DisconnectReason, Error, FrameError, HandshakeError};
use crate::frame::{DEFAULT_MAX_FRAME_LENGTH, FrameCodec};
use crate::packet_encrypted;
use crate::packet_plaintext;
pub use crate::parser::ProtoMessage;
use crate::proto::{
    self, AuthenticationResponse, DeviceInfoResponse, DisconnectResponse, HelloResponse,
    PingResponse,
};

/// Configuration of a [`Protocol`] state machine.
///
/// Start from [`Config::new`] and adjust the public fields as needed.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Config {
    /// Device name, announced to encrypted clients before the handshake.
    pub name: String,
    /// MAC address announced to encrypted clients before the handshake.
    pub mac: Option<String>,
    /// Decoded (raw, 32 byte) noise pre-shared key. `Some` requires clients to
    /// connect encrypted, `None` requires them to connect in plaintext.
    ///
    /// Use [`Config::with_encryption_key`] to set it from the base64 form used
    /// in ESPHome configurations.
    pub noise_psk: Option<Vec<u8>>,
    /// Answer to a client's `HelloRequest`.
    pub hello_response: HelloResponse,
    /// Answer to a client's `DeviceInfoRequest`.
    pub device_info: DeviceInfoResponse,
    /// Largest frame (in bytes, excluding the frame header) accepted from the
    /// peer or sent to it. Bounds how much memory a peer can make the state
    /// machine buffer; lower it on memory constrained devices.
    pub max_frame_length: usize,
}

impl Config {
    /// Default value of [`Config::max_frame_length`]: 8 MiB.
    pub const DEFAULT_MAX_FRAME_LENGTH: usize = DEFAULT_MAX_FRAME_LENGTH;

    /// Creates a plaintext configuration for a device called `name`, reporting
    /// API version 1.10 and the ESPHome version this crate was generated for.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            mac: None,
            noise_psk: None,
            hello_response: HelloResponse {
                api_version_major: 1,
                api_version_minor: 10,
                server_info: "Rust: esphome-native-api".to_string(),
                name: name.clone(),
            },
            device_info: DeviceInfoResponse {
                name: name.clone(),
                friendly_name: name.clone(),
                esphome_version: proto::VERSION.to_string(),
                ..Default::default()
            },
            max_frame_length: DEFAULT_MAX_FRAME_LENGTH,
            name,
        }
    }

    /// Requires clients to connect encrypted with the given base64 encoded
    /// key (the `api.encryption.key` of an ESPHome configuration).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `key` is not valid base64.
    pub fn with_encryption_key(mut self, key: &str) -> Result<Self, Error> {
        self.noise_psk = Some(decode_encryption_key(key)?);
        self.device_info.api_encryption_supported = true;
        Ok(self)
    }
}

/// Decodes a base64 encoded noise pre-shared key.
pub(crate) fn decode_encryption_key(key: &str) -> Result<Vec<u8>, Error> {
    BASE64_STANDARD
        .decode(key)
        .map_err(|e| Error::Config(format!("encryption key is not valid base64: {e}")))
}

/// Something the driver of a [`Protocol`] has to act on, returned by
/// [`Protocol::poll`].
#[derive(Clone, Debug)]
#[non_exhaustive]
// Messages are handed out by value, like everywhere else in this crate; only a
// handful of events are ever queued at once.
#[allow(clippy::large_enum_variant)]
pub enum Event {
    /// Bytes to write to the transport, in the order they are returned.
    Transmit(Vec<u8>),
    /// The handshake finished: from now on [`Protocol::send`] accepts messages.
    Connected,
    /// A message from the peer for the application. Protocol level requests
    /// (`Hello`, `Authentication`, `DeviceInfo`, `Ping` and `Disconnect`) are
    /// answered by the state machine and never show up here.
    Message(ProtoMessage),
    /// Close (shut down the write side of) the transport once all bytes
    /// transmitted so far are written. Nothing will be transmitted afterwards.
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Waiting for the first byte, which tells plaintext from encrypted.
    AwaitMarker,
    /// Encrypted: waiting for the client's (empty) noise hello frame.
    NoiseHello,
    /// Encrypted: waiting for the client's noise handshake frame.
    NoiseHandshake,
    /// Handshake done, exchanging messages.
    Established,
    /// The connection ended; nothing is processed anymore.
    Closed,
}

/// Sans-IO state machine for the device side of one ESPHome native API
/// connection. See the [module documentation](self) for how to drive it.
pub struct Protocol {
    config: Config,
    state: State,
    codec: FrameCodec,
    /// Received bytes that are not processed yet, starting at `rx_start`.
    rx: Vec<u8>,
    rx_start: usize,
    events: VecDeque<Event>,
    /// Fatal error to report once the queued `events` are handed out.
    pending_error: Option<Error>,
    encrypt_cipher: Option<CipherState<ChaCha20Poly1305>>,
    decrypt_cipher: Option<CipherState<ChaCha20Poly1305>>,
    disconnect_requested: bool,
    write_closed: bool,
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Protocol")
            .field("state", &self.state)
            .field("encrypted", &self.is_encrypted())
            .field("disconnect_requested", &self.disconnect_requested)
            .field("write_closed", &self.write_closed)
            .finish_non_exhaustive()
    }
}

impl Protocol {
    /// Creates the state machine for one freshly accepted connection.
    pub fn new(config: Config) -> Self {
        let codec = FrameCodec::with_max_length(false, config.max_frame_length);
        Self {
            config,
            state: State::AwaitMarker,
            codec,
            rx: Vec::new(),
            rx_start: 0,
            events: VecDeque::new(),
            pending_error: None,
            encrypt_cipher: None,
            decrypt_cipher: None,
            disconnect_requested: false,
            write_closed: false,
        }
    }

    /// Whether the handshake finished and the connection is still alive, i.e.
    /// messages are exchanged.
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    /// Whether the connection ended, either through a fatal error returned by
    /// [`Protocol::poll`] or through [`Protocol::on_eof`].
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Whether the peer connected encrypted. `false` until the first byte of
    /// the peer arrived.
    pub fn is_encrypted(&self) -> bool {
        self.encrypt_cipher.is_some()
            || matches!(self.state, State::NoiseHello | State::NoiseHandshake)
    }

    /// Whether the peer asked to disconnect (sent a `DisconnectRequest`).
    pub fn disconnect_requested(&self) -> bool {
        self.disconnect_requested
    }

    /// Hands bytes read from the transport to the state machine.
    ///
    /// This only buffers the bytes; they are processed by [`Protocol::poll`].
    /// Bytes received after the connection ended are discarded.
    pub fn receive(&mut self, data: &[u8]) {
        if self.state == State::Closed {
            return;
        }
        if self.rx_start > 0 {
            // Drop what is already processed before growing the buffer.
            self.rx.drain(..self.rx_start);
            self.rx_start = 0;
        }
        self.rx.extend_from_slice(data);
    }

    /// Whether received bytes are buffered that do not form a complete frame
    /// (after [`Protocol::poll`] returned `Ok(None)`).
    pub(crate) fn has_buffered_data(&self) -> bool {
        self.rx_start < self.rx.len()
    }

    /// Advances the state machine and returns the next [`Event`] to act on.
    ///
    /// `Ok(None)` means there is nothing left to do until more bytes are
    /// [received](Protocol::receive) or a message is [sent](Protocol::send).
    ///
    /// # Errors
    ///
    /// An `Err` is fatal: the connection is over and the transport should be
    /// dropped. It is returned exactly once, after any farewell events (an
    /// error frame for the peer followed by [`Event::Close`]) were handed out;
    /// afterwards `poll` returns `Ok(None)`.
    ///
    /// Received frames are processed lazily, one per call at most, so an error
    /// caused by a later frame never hides the events of an earlier one.
    pub fn poll(&mut self) -> Result<Option<Event>, Error> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            if let Some(error) = self.pending_error.take() {
                return Err(error);
            }
            if self.state == State::Closed {
                return Ok(None);
            }
            match self.step() {
                Ok(true) => {}
                Ok(false) => return Ok(None),
                Err(error) => {
                    self.terminate();
                    self.pending_error = Some(error);
                }
            }
        }
    }

    /// Queues `message` for the peer. The encoded bytes are returned by
    /// [`Protocol::poll`] as [`Event::Transmit`].
    ///
    /// Sending a `DisconnectResponse` closes the write side: it is followed by
    /// [`Event::Close`] and no further message is accepted.
    ///
    /// # Errors
    ///
    /// - [`Error::NotEstablished`] while the handshake is still running.
    /// - [`Error::Disconnected`] once the connection or its write side is closed.
    /// - [`Error::Frame`] if the message cannot be encoded (for example because
    ///   it exceeds the maximum frame length). The connection stays usable.
    pub fn send(&mut self, message: &ProtoMessage) -> Result<(), Error> {
        match self.state {
            State::Established => {}
            State::Closed => return Err(self.disconnected(DisconnectReason::WriteClosed)),
            _ => return Err(Error::NotEstablished),
        }
        if self.write_closed {
            return Err(self.disconnected(DisconnectReason::WriteClosed));
        }
        self.queue_message(message)?;
        Ok(())
    }

    /// Tells the state machine that the transport can no longer be written to
    /// (for example after a write error).
    ///
    /// Bytes not transmitted yet are dropped and [`Protocol::send`] fails from
    /// now on. Messages from the peer are still processed, until one of them
    /// needs an answer — that ends the connection with
    /// [`Error::Disconnected`].
    pub fn close_write(&mut self) {
        self.write_closed = true;
        self.events
            .retain(|event| !matches!(event, Event::Transmit(_) | Event::Close));
    }

    /// Tells the state machine that the transport reached end of stream and
    /// returns why the connection ended:
    ///
    /// - [`HandshakeError::NoData`] if the peer never sent a byte,
    /// - [`HandshakeError::Aborted`] if it left during the handshake,
    /// - [`FrameError::Malformed`] if it left in the middle of a frame,
    /// - [`DisconnectReason::Requested`] after a `DisconnectRequest`,
    /// - [`DisconnectReason::Eof`] otherwise.
    ///
    /// Call it after [`Protocol::poll`] returned `Ok(None)`, so that everything
    /// received before the end of the stream is processed.
    pub fn on_eof(&mut self) -> Error {
        let error = match self.state {
            State::AwaitMarker => HandshakeError::NoData.into(),
            State::NoiseHello | State::NoiseHandshake => HandshakeError::Aborted.into(),
            State::Established if self.has_buffered_data() => {
                FrameError::Malformed("bytes remaining on stream".to_string()).into()
            }
            State::Established | State::Closed => self.disconnected(DisconnectReason::Eof),
        };
        self.terminate();
        error
    }

    /// `Disconnected(Requested)` if the peer asked for it, otherwise
    /// `Disconnected(fallback)`.
    fn disconnected(&self, fallback: DisconnectReason) -> Error {
        Error::Disconnected(if self.disconnect_requested {
            DisconnectReason::Requested
        } else {
            fallback
        })
    }

    fn terminate(&mut self) {
        self.state = State::Closed;
        self.rx = Vec::new();
        self.rx_start = 0;
    }

    /// Processes one unit of input (the marker byte or one frame). Returns
    /// `Ok(false)` if more data is needed to make progress.
    fn step(&mut self) -> Result<bool, Error> {
        if self.state == State::AwaitMarker {
            return self.handle_marker();
        }

        // Take the buffer so a frame can borrow from it while `self` changes.
        let rx = core::mem::take(&mut self.rx);
        let result = match self.codec.decode(&rx[self.rx_start..]) {
            Ok(Some((frame, consumed))) => {
                trace!("Frame: {:02X?}", frame);
                self.rx_start += consumed;
                self.handle_frame(frame).map(|()| true)
            }
            Ok(None) => Ok(false),
            Err(error) => Err(error.into()),
        };
        self.rx = rx;
        if self.rx_start == self.rx.len() {
            self.rx.clear();
            self.rx_start = 0;
        }
        result
    }

    /// The first byte of the stream is the preamble of the first frame and
    /// tells whether the peer talks plaintext (`0`) or encrypted (`1`). It is
    /// only peeked at: the frame it belongs to is decoded afterwards.
    fn handle_marker(&mut self) -> Result<bool, Error> {
        let Some(&marker) = self.rx.get(self.rx_start) else {
            return Ok(false);
        };
        trace!("Marker byte: {:02X?}", marker);
        let max_frame_length = self.config.max_frame_length;

        match marker {
            0 => {
                debug!("Cleartext messaging");
                if self.config.noise_psk.is_some() {
                    // The literal string goes on the wire to the connecting
                    // ESPHome client; the returned error is for the caller.
                    self.queue_error_frame(true, "Only key encryption is enabled");
                    return Err(HandshakeError::EncryptionProtocolMismatch(
                        "a client connected in plaintext, but an encryption key is configured (encryption is required)",
                    )
                    .into());
                }
                self.codec = FrameCodec::with_max_length(false, max_frame_length);
                self.state = State::Established;
                debug!("Initialization done.");
                self.events.push_back(Event::Connected);
            }
            1 => {
                trace!("Encrypted messaging");
                if self.config.noise_psk.is_none() {
                    // The plaintext framing (0x00 preamble) tells the encrypted
                    // client that this device speaks plaintext, so it can raise a
                    // precise error instead of a generic socket failure.
                    self.queue_error_frame(false, "No encrypted communication allowed");
                    return Err(HandshakeError::EncryptionProtocolMismatch(
                        "a client requested an encrypted connection, but no encryption key is configured",
                    )
                    .into());
                }
                self.codec = FrameCodec::with_max_length(true, max_frame_length);
                self.state = State::NoiseHello;
            }
            _ => return Err(HandshakeError::InvalidMarker(marker).into()),
        }
        Ok(true)
    }

    fn handle_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
        match self.state {
            State::NoiseHello => {
                debug!("Frame 1: {:02X?}", frame);
                let server_hello = packet_encrypted::generate_server_hello_frame(
                    &self.config.name,
                    self.config.mac.as_deref(),
                );
                self.queue_frame(&server_hello)?;
                self.state = State::NoiseHandshake;
                Ok(())
            }
            State::NoiseHandshake => self.handle_noise_handshake(frame),
            State::Established => self.handle_message_frame(frame),
            // `step` handles the marker and `poll` never steps a closed machine.
            State::AwaitMarker | State::Closed => Ok(()),
        }
    }

    fn handle_noise_handshake(&mut self, frame: &[u8]) -> Result<(), Error> {
        debug!("Frame 2: {:02X?}", frame);

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

        let psk = match self.config.noise_psk.as_ref() {
            Some(psk) => psk,
            // Unreachable: an encrypted client is rejected at the marker byte
            // when no key is configured. Handled defensively to avoid a panic.
            None => return Err(Error::Config("encryption key missing".to_string())),
        };
        handshake_state.push_psk(psk);

        // Ignore message type byte
        let handshake_payload = frame.get(1..).ok_or(HandshakeError::MalformedFrame)?;
        match handshake_state.read_message_vec(handshake_payload) {
            Ok(_) => {}
            Err(e) => match e.kind() {
                ErrorKind::Decryption => {
                    // The literal string goes on the wire to the connecting
                    // ESPHome client; the returned error is for the caller.
                    self.queue_error_frame(true, "Handshake MAC failure");
                    return Err(HandshakeError::MacFailure.into());
                }
                _ => {
                    debug!("Failed to read message: {}", e);
                }
            },
        }

        let out = handshake_state
            .write_message_vec(b"")
            .map_err(|e| Error::Handshake(HandshakeError::Crypto(e.to_string())))?;
        let (decrypt_cipher, encrypt_cipher) = handshake_state.get_ciphers();
        self.encrypt_cipher = Some(encrypt_cipher);
        self.decrypt_cipher = Some(decrypt_cipher);

        let mut message_handshake = Vec::with_capacity(1 + out.len());
        message_handshake.push(0);
        message_handshake.extend(out);

        debug!("Sending handshake");
        self.queue_frame(&message_handshake)?;
        self.state = State::Established;
        debug!("Initialization done.");
        self.events.push_back(Event::Connected);
        Ok(())
    }

    fn handle_message_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
        let decoded = match self.decrypt_cipher.as_mut() {
            Some(cipher) => packet_encrypted::packet_to_message(frame, cipher),
            None => packet_plaintext::packet_to_message(frame),
        };

        let message = match decoded {
            Ok(message) => message,
            // Forward-compatible: an unknown message type (for example one
            // introduced by a newer ESPHome release) is skipped so the
            // connection stays healthy instead of being torn down.
            Err(FrameError::UnknownMessageType(message_type)) => {
                debug!("Ignoring unknown message type {message_type}");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        // Protocol-level messages we answer ourselves produce a response;
        // everything else is forwarded to the consumer.
        let response: Option<ProtoMessage> = match &message {
            ProtoMessage::DisconnectRequest(disconnect_request) => {
                debug!("DisconnectRequest: {:?}", disconnect_request);
                self.disconnect_requested = true;
                Some(ProtoMessage::DisconnectResponse(DisconnectResponse {}))
            }
            ProtoMessage::PingRequest(ping_request) => {
                debug!("PingRequest: {:?}", ping_request);
                Some(ProtoMessage::PingResponse(PingResponse {}))
            }
            ProtoMessage::DeviceInfoRequest(device_info_request) => {
                debug!("DeviceInfoRequest: {:?}", device_info_request);
                Some(ProtoMessage::DeviceInfoResponse(
                    self.config.device_info.clone(),
                ))
            }
            ProtoMessage::HelloRequest(hello_request) => {
                debug!("HelloRequest: {:?}", hello_request);
                Some(ProtoMessage::HelloResponse(
                    self.config.hello_response.clone(),
                ))
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
            _ => None,
        };

        match response {
            Some(response) => {
                if self.write_closed {
                    // The answer can no longer be delivered; the connection is
                    // finished.
                    return Err(self.disconnected(DisconnectReason::WriteClosed));
                }
                self.queue_message(&response)?;
            }
            None if is_protocol_request(&message) => {}
            None => self.events.push_back(Event::Message(message)),
        }
        Ok(())
    }

    /// Encodes `message` for the peer and queues it for transmission.
    fn queue_message(&mut self, message: &ProtoMessage) -> Result<(), FrameError> {
        debug!("Answer message: {:?}", message);
        let packet = match self.encrypt_cipher.as_mut() {
            Some(cipher) => {
                packet_encrypted::message_to_packet(message, cipher, self.config.max_frame_length)?
            }
            None => packet_plaintext::message_to_packet(message)?,
        };
        self.queue_frame(&packet)?;

        if matches!(message, ProtoMessage::DisconnectResponse(_)) {
            debug!("Disconnecting");
            self.events.push_back(Event::Close);
            self.write_closed = true;
        }
        Ok(())
    }

    /// Frames `packet` with the connection's codec and queues it.
    fn queue_frame(&mut self, packet: &[u8]) -> Result<(), FrameError> {
        let mut bytes = Vec::new();
        self.codec.encode(packet, &mut bytes)?;
        self.events.push_back(Event::Transmit(bytes));
        Ok(())
    }

    /// Queues the farewell for a peer that is rejected during the handshake:
    /// an error frame carrying `message`, then the request to close.
    fn queue_error_frame(&mut self, encrypted: bool, message: &str) {
        let mut packet = Vec::with_capacity(1 + message.len());
        packet.push(1);
        packet.extend_from_slice(message.as_bytes());

        let mut bytes = Vec::new();
        // Cannot fail in practice: the messages are short, static strings.
        if FrameCodec::with_max_length(encrypted, DEFAULT_MAX_FRAME_LENGTH)
            .encode(&packet, &mut bytes)
            .is_ok()
        {
            self.events.push_back(Event::Transmit(bytes));
        }
        self.events.push_back(Event::Close);
        self.write_closed = true;
    }
}

/// Requests the state machine handles itself instead of forwarding them.
fn is_protocol_request(message: &ProtoMessage) -> bool {
    matches!(
        message,
        ProtoMessage::DisconnectRequest(_)
            | ProtoMessage::PingRequest(_)
            | ProtoMessage::DeviceInfoRequest(_)
            | ProtoMessage::HelloRequest(_)
            | ProtoMessage::AuthenticationRequest(_)
    )
}
