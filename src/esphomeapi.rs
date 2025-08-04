use crate::frame::construct_frame;
use crate::frame::to_encrypted_frame;
use crate::frame::to_unencrypted_frame;
use crate::packet_encrypted;
use crate::parser;
use crate::parser::ProtoMessage;
use crate::proto::version_2025_6_3::ConnectResponse;
use crate::proto::version_2025_6_3::DeviceInfoResponse;
use crate::proto::version_2025_6_3::DisconnectResponse;
use crate::proto::version_2025_6_3::HelloResponse;
use crate::proto::version_2025_6_3::PingResponse;
use base64::prelude::*;
use byteorder::BigEndian;
use byteorder::ByteOrder;
use constant_time_eq::constant_time_eq;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use noise_protocol::CipherState;
use noise_protocol::ErrorKind;
use noise_protocol::HandshakeState;
use noise_protocol::patterns::noise_nn_psk0;
use noise_rust_crypto::ChaCha20Poly1305;
use noise_rust_crypto::Sha256;
use noise_rust_crypto::X25519;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use typed_builder::TypedBuilder;

#[derive(Debug)]
pub(crate) enum EncryptionState {
    Uninitialized,
    ClientHandshake,
    ServerHello,
    ServerHandshake,
    Initialized,
    Failure,
}

#[derive(TypedBuilder)]
pub struct EspHomeApi {
    // Private fields
    #[builder(default=Arc::new(AtomicBool::new(false)))]
    pub(crate) password_authenticated: Arc<AtomicBool>,
    #[builder(default=Arc::new(AtomicBool::new(false)))]
    pub(crate) key_authenticated: Arc<AtomicBool>,

    #[builder(default=Arc::new(AtomicBool::new(false)))]
    pub(crate) encrypted_api: Arc<AtomicBool>,

    #[builder(default=Arc::new(Mutex::new(EncryptionState::Uninitialized)))]
    pub(crate) encryption_state: Arc<Mutex<EncryptionState>>,

    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) handshake_state:
        Arc<Mutex<Option<HandshakeState<X25519, ChaCha20Poly1305, Sha256>>>>,
    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) encrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>>,
    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) decrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>>,

    name: String,

    #[builder(default = None, setter(strip_option(fallback=password_opt)))]
    #[deprecated(note = "https://esphome.io/components/api.html#configuration-variables")]
    password: Option<String>,
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
            broadcast::Sender<ProtoMessage>,
            broadcast::Receiver<ProtoMessage>,
        ),
        Box<dyn std::error::Error>,
    > {
        if self.password.is_none() && self.encryption_key.is_none() {
            self.password_authenticated
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        // Channel for direct answers (prioritized when sending)
        let (answer_messages_tx, mut answer_messages_rx) = broadcast::channel::<ProtoMessage>(16);
        // Channel for normal messages (e.g. state updates)
        let (messages_tx, mut messages_rx) = broadcast::channel::<ProtoMessage>(16);
        let (outgoing_messages_tx, mut outgoing_messages_rx) =
            broadcast::channel::<ProtoMessage>(16);

        // Asynchronously wait for an inbound socket.
        let (mut read, mut write) = tcp_stream.into_split();

        let device_info = DeviceInfoResponse {
            api_encryption_supported: self.encryption_key.is_some(),
            uses_password: self.password.is_some(),
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
        };

        if self.encryption_key.is_some() {
            debug!("Encryption enabled");
            self.encrypted_api
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }

        let hello_response = HelloResponse {
            api_version_major: self.api_version_major,
            api_version_minor: self.api_version_minor,
            server_info: self.server_info.clone(),
            name: self.name.clone(),
        };
        let password_clone = self.password.clone();
        let encrypted_api = self.encrypted_api.clone();
        let encrypt_cypher_clone = self.encrypt_cypher.clone();
        let decrypt_cypher_clone = self.decrypt_cypher.clone();
        let encryption_state = self.encryption_state.clone();
        let handshake_state_clone = self.handshake_state.clone();
        let answer_messages_tx_clone = answer_messages_tx.clone();
        let messages_tx_clone = messages_tx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = answer_messages_tx_clone.closed() => {
                    info!("CLOSED");
                }
                _ = messages_tx_clone.closed() => {
                    info!("CLOSED");
                }
            };
        });

        // Write Loop
        tokio::spawn(async move {
            let mut disconnect = false;
            loop {
                let mut answer_buf: Vec<u8> = vec![];
                let answer_message: ProtoMessage;
                // Wait for any new message
                tokio::select! {
                    biased; // Poll answer_messages_rx first
                    message = answer_messages_rx.recv() => {
                        answer_message = message.unwrap();
                    }
                    message = messages_rx.recv() => {
                        answer_message = message.unwrap();
                    }
                };

                let encryption = encrypted_api.load(std::sync::atomic::Ordering::Relaxed);
                if encryption {
                    {
                        let mut encryption_state_changer = encryption_state.lock().await;
                        match *encryption_state_changer {
                            EncryptionState::ClientHandshake => {
                                let mut message_server_hello: Vec<u8> = Vec::new();

                                let encryption_protocol: Vec<u8> = vec![1];
                                let node_name = b"test_node";
                                let node_mac_address = b"00:00:00:00:00:01";
                                message_server_hello.extend(encryption_protocol);
                                message_server_hello.extend(node_name);
                                message_server_hello.extend(b"\0");
                                message_server_hello.extend(node_mac_address);
                                message_server_hello.extend(b"\0");

                                let len_u16 = message_server_hello.len() as u16;
                                let len_bytes = len_u16.to_be_bytes();
                                let length: Vec<u8> = vec![len_bytes[0], len_bytes[1]];

                                let mut hello_frame = vec![1];
                                hello_frame.extend(length);
                                hello_frame.extend(message_server_hello);

                                debug!("Sending server hello: {:02X?}", &hello_frame);
                                write
                                    .write_all(&hello_frame)
                                    .await
                                    .expect("failed to write encrypted response");
                                write.flush().await.expect("failed to flush server hello");

                                *encryption_state_changer = EncryptionState::ServerHello;
                            }
                            _ => {}
                        }

                        match *encryption_state_changer {
                            EncryptionState::ServerHello => {
                                let out: Vec<u8>;
                                let mut handshake_state_change = handshake_state_clone.lock().await;

                                if handshake_state_change.is_none() {
                                    *encryption_state_changer = EncryptionState::Failure;
                                } else {
                                    let handshake_state =
                                        (*handshake_state_change).as_mut().unwrap();

                                    out = handshake_state.write_message_vec(b"").unwrap();
                                    {
                                        let mut encrypt_cipher_changer =
                                            encrypt_cypher_clone.lock().await;
                                        let mut decrypt_cipher_changer =
                                            decrypt_cypher_clone.lock().await;
                                        let (decrypt_cipher, encrypt_cipher) =
                                            handshake_state.get_ciphers();
                                        *encrypt_cipher_changer = Some(encrypt_cipher);
                                        *decrypt_cipher_changer = Some(decrypt_cipher);
                                    }

                                    let mut message_handshake = vec![0];
                                    message_handshake.extend(out);

                                    let len_u16 = message_handshake.len() as u16;
                                    let len_bytes = len_u16.to_be_bytes();
                                    let length: Vec<u8> = vec![len_bytes[0], len_bytes[1]];

                                    let mut encrypted_frame = vec![1];
                                    encrypted_frame.extend(length);
                                    encrypted_frame.extend(message_handshake);

                                    debug!("Sending handshake: {:02X?}", &encrypted_frame);
                                    write
                                        .write_all(&encrypted_frame)
                                        .await
                                        .expect("failed to write encrypted response");

                                    *encryption_state_changer = EncryptionState::ServerHandshake;
                                }
                            }
                            _ => {}
                        }
                        match *encryption_state_changer {
                            EncryptionState::Initialized | EncryptionState::ServerHandshake => {
                                // Use normal messaging
                                {
                                    let mut encrypt_cipher_changer =
                                        encrypt_cypher_clone.lock().await;
                                    let encrypted_frame = to_encrypted_frame(
                                        &answer_message,
                                        &mut *encrypt_cipher_changer.as_mut().unwrap(),
                                    )
                                    .unwrap();

                                    answer_buf = [answer_buf, encrypted_frame].concat();
                                }

                                *encryption_state_changer = EncryptionState::Initialized;
                            }
                            _ => {
                                let packet = [
                                    [1].to_vec(),
                                    "Only key encryption is enabled".as_bytes().to_vec(),
                                ]
                                .concat();
                                answer_buf = construct_frame(&packet, true).unwrap();
                                disconnect = true;
                            }
                        }
                        match *encryption_state_changer {
                            EncryptionState::Failure => {
                                error!("Encrypted API Failure. Disconnecting.");
                                let packet =
                                    [[1].to_vec(), "Handshake MAC failure".as_bytes().to_vec()]
                                        .concat();
                                answer_buf = construct_frame(&packet, true).unwrap();
                                disconnect = true;
                                // answer_buf = [answer_buf, failure_buffer].concat();
                            }
                            _ => {}
                        }
                    }
                } else {
                    answer_buf =
                        [answer_buf, to_unencrypted_frame(&answer_message).unwrap()].concat();
                }

                debug!("Answer message: {:?}", answer_message);
                match answer_message {
                    ProtoMessage::DisconnectResponse(_) => {
                        disconnect = true;
                    }
                    _ => {}
                }

                trace!("TCP Send: {:02X?}", &answer_buf);

                match write.write_all(&answer_buf).await {
                    Err(err) => {
                        error!("Failed to write data to socket: {:?}", err)
                    }
                    _ => {}
                }

                write.flush().await.expect("failed to flush data to socket");

                if disconnect {
                    debug!("Disconnecting");
                    write.shutdown().await.expect("failed to shutdown socket");
                    break;
                }
            }
        });

        // Clone all necessary data before spawning the task
        let answer_messages_tx_clone = answer_messages_tx.clone();
        let handshake_state_clone = self.handshake_state.clone();
        let encryption_state = self.encryption_state.clone();
        let encryption_key = self.encryption_key.clone();
        let encrypted_api = self.encrypted_api.clone();
        let decrypt_cypher_clone = self.decrypt_cypher.clone();
        let password_authenticated = self.password_authenticated.clone();
        let key_authenticated = self.key_authenticated.clone();

        // Read Loop
        tokio::spawn(async move {
            let mut buf = vec![0; 1024];

            loop {
                let n = read
                    .read(&mut buf)
                    .await
                    .expect("failed to read data from socket");

                if n == 0 {
                    return;
                }

                trace!("TCP Receive: {:02X?}", &buf[0..n]);

                let mut cursor = 0;

                while cursor < n {
                    // Ignore first byte
                    // Get Length of packet

                    let message;
                    let preamble = buf[cursor] as usize;
                    trace!("Cursor: {:?}", &cursor);
                    // trace!("n: {:?}", &n);

                    match preamble {
                        0 => {
                            // Cleartext

                            // TODO: use dynamic length bits
                            let len = buf[cursor + 1] as usize;
                            message = cleartext_frame_to_message(
                                &buf[cursor + 2..cursor + 3 + len].to_vec(),
                            )
                            .unwrap();

                            match &message {
                                ProtoMessage::HelloRequest(hello_request) => {
                                    debug!("HelloRequest: {:?}", hello_request);

                                    answer_messages_tx_clone
                                        .send(ProtoMessage::HelloResponse(hello_response.clone()))
                                        .unwrap();
                                }
                                _ => {}
                            }

                            cursor += 3 + len;
                        }
                        1 => {
                            // Encrypted

                            let mut encryption_state_changer = encryption_state.lock().await;
                            match *encryption_state_changer {
                                EncryptionState::Uninitialized => {
                                    encrypted_api.store(true, std::sync::atomic::Ordering::Relaxed);

                                    // Similar to https://github.com/esphome/aioesphomeapi/blob/60bcd1698dd622aeac6f4b5ec448bab0e3467c4f/aioesphomeapi/_frame_helper/noise.py#L248C17-L255
                                    let mut handshake_state: HandshakeState<
                                        X25519,
                                        ChaCha20Poly1305,
                                        Sha256,
                                    > = HandshakeState::new(
                                        noise_nn_psk0(),
                                        false,
                                        // NEXT: This is somehow set from the first api message?
                                        b"NoiseAPIInit\0\0",
                                        None,
                                        None,
                                        None,
                                        None,
                                    );

                                    encrypted_api.store(true, std::sync::atomic::Ordering::Relaxed);
                                    let noise_psk = BASE64_STANDARD
                                        .decode(encryption_key.as_ref().unwrap())
                                        .unwrap();

                                    handshake_state.push_psk(&noise_psk);
                                    match handshake_state.read_message_vec(&buf[3 + 3 + 1..n]) {
                                        Ok(_) => {
                                            {
                                                let mut mutex_changer =
                                                    handshake_state_clone.lock().await;
                                                *mutex_changer = Option::Some(handshake_state);
                                            }

                                            answer_messages_tx_clone
                                                .send(ProtoMessage::HelloResponse(
                                                    hello_response.clone(),
                                                ))
                                                .unwrap();
                                            *encryption_state_changer =
                                                EncryptionState::ClientHandshake;
                                        }
                                        Err(e) => {
                                            match e.kind() {
                                                // Only warn here. The error will be handled in the send loop
                                                ErrorKind::Decryption => {
                                                    warn!("Decryption failed: {}", e);
                                                }
                                                _ => {
                                                    debug!("Failed to read message: {}", e);
                                                }
                                            }
                                            answer_messages_tx_clone
                                                .send(ProtoMessage::HelloResponse(
                                                    hello_response.clone(),
                                                ))
                                                .unwrap();
                                            *encryption_state_changer =
                                                EncryptionState::ClientHandshake;
                                        }
                                    }

                                    cursor += n;
                                    continue;
                                }
                                EncryptionState::Initialized => {
                                    let len =
                                        BigEndian::read_u16(&buf[cursor + 1..cursor + 3]) as usize;
                                    // trace!("Length: {:?}", &len);
                                    let decrypted_message = &buf[cursor + 3..cursor + len + 3];
                                    // trace!("To decrypt message: {:02X?}", &decrypted_message);
                                    {
                                        let mut decrypt_cipher_changer =
                                            decrypt_cypher_clone.lock().await;
                                        message = packet_encrypted::packet_to_message(
                                            decrypted_message,
                                            &mut *decrypt_cipher_changer.as_mut().unwrap(),
                                        )
                                        .unwrap();
                                    }
                                    key_authenticated
                                        .store(true, std::sync::atomic::Ordering::Relaxed);

                                    cursor += 3 + len;
                                }
                                _ => {
                                    debug!(
                                        "Wrong encryption state: {:?}",
                                        *encryption_state_changer
                                    );
                                    return;
                                }
                            }
                        }
                        _ => {
                            debug!("Marker byte invalid: {}", preamble);
                            return;
                        }
                    }

                    // Initialization Messages (unauthenticated)
                    match &message {
                        ProtoMessage::ConnectRequest(connect_request) => {
                            debug!("ConnectRequest: {:?}", connect_request);
                            let mut valid = false;
                            if encryption_key.is_some() {
                                valid = true;
                            } else {
                                if let Some(password) = password_clone.clone() {
                                    valid = constant_time_eq(
                                        connect_request.password.as_bytes(),
                                        password.as_bytes(),
                                    );
                                }
                            }

                            password_authenticated
                                .store(valid, std::sync::atomic::Ordering::Relaxed);
                            let response_message = ConnectResponse {
                                invalid_password: !valid,
                            };
                            debug!("ConnectResponse: {:?}", response_message);
                            answer_messages_tx_clone
                                .send(ProtoMessage::ConnectResponse(response_message))
                                .unwrap();
                            continue;
                        }

                        ProtoMessage::DisconnectRequest(disconnect_request) => {
                            debug!("DisconnectRequest: {:?}", disconnect_request);
                            let response_message = DisconnectResponse {};
                            answer_messages_tx_clone
                                .send(ProtoMessage::DisconnectResponse(response_message))
                                .unwrap();
                            continue;
                        }
                        _ => {}
                    }
                    let auth_test = key_authenticated.load(std::sync::atomic::Ordering::Relaxed)
                        || password_authenticated.load(std::sync::atomic::Ordering::Relaxed);
                    info!("Authenticated: {}", auth_test);

                    if !auth_test {
                        answer_messages_tx_clone
                            .send(ProtoMessage::DisconnectResponse(DisconnectResponse {}))
                            .unwrap();
                        continue;
                    }

                    // Authenticated Messages
                    match &message {
                        ProtoMessage::PingRequest(ping_request) => {
                            debug!("PingRequest: {:?}", ping_request);
                            let response_message = PingResponse {};
                            answer_messages_tx_clone
                                .send(ProtoMessage::PingResponse(response_message))
                                .unwrap();
                        }
                        ProtoMessage::DeviceInfoRequest(device_info_request) => {
                            debug!("DeviceInfoRequest: {:?}", device_info_request);
                            answer_messages_tx_clone
                                .send(ProtoMessage::DeviceInfoResponse(device_info.clone()))
                                .unwrap();
                        }

                        message => {
                            outgoing_messages_tx.send(message.clone()).unwrap();
                        }
                    }
                }
            }
        });

        Ok((messages_tx.clone(), outgoing_messages_rx))
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

pub fn cleartext_frame_to_message(
    buffer: &[u8],
) -> Result<ProtoMessage, Box<dyn std::error::Error>> {
    let message_type = buffer[0] as usize;
    let packet_content = &buffer[1..];
    debug!("Message type: {}", message_type);
    debug!("Message: {:?}", packet_content);
    Ok(parser::parse_proto_message(message_type, &packet_content).unwrap())
}
