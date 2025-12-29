use crate::frame::FrameCodec;
use crate::packet_encrypted;
use crate::packet_plaintext;
use crate::parser::ProtoMessage;
use crate::proto::version_2025_12_1::DeviceInfoResponse;
use crate::proto::version_2025_12_1::DisconnectResponse;
use crate::proto::version_2025_12_1::HelloResponse;
use crate::proto::version_2025_12_1::PingResponse;
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
use std::sync::atomic::AtomicBool;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tokio_util::codec::FramedRead;
use tokio_util::codec::FramedWrite;
use typed_builder::TypedBuilder;

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

#[derive(TypedBuilder, Clone)]
pub struct EspHomeApi {
    // Private fields
    #[builder(default=Arc::new(AtomicBool::new(false)))]
    pub(crate) first_message_received: Arc<AtomicBool>,

    #[builder(default=Arc::new(AtomicBool::new(true)))]
    pub(crate) plaintext_communication: Arc<AtomicBool>,

    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) encrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>>,
    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) decrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>>,

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

    #[builder(default = "2025.4.0".to_string())]
    esphome_version: String,
}

/// Handles the EspHome Api, with encryption etc.
impl EspHomeApi {
    /// Starts the server and returns a broadcast channel for messages, and a
    /// broadcast receiver for all messages not handled by the abstraction
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
            esphome_version: self.esphome_version.clone(),
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
            trace!("Frame 1: {:02X?}", &frame_noise_hello);

            let message_server_hello =
                packet_encrypted::generate_server_hello_frame(self.name.clone(), self.mac.clone());

            writer.send(message_server_hello.clone()).await.unwrap();
            writer.flush().await.unwrap();

            let frame_handshake_request = reader.next().await.unwrap().unwrap();
            info!("Frame 2: {:02X?}", &frame_handshake_request);

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
                    ProtoMessage::AuthenticationRequest(_) => {
                        info!("Password Authentication is not supported");
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
