use crate::parser;
use crate::parser::ProtoMessage;
use crate::proto::version_2025_6_3::ConnectResponse;
use crate::proto::version_2025_6_3::DeviceInfoResponse;
use crate::proto::version_2025_6_3::DisconnectResponse;
use crate::proto::version_2025_6_3::HelloResponse;
use crate::proto::version_2025_6_3::ListEntitiesDoneResponse;
use crate::proto::version_2025_6_3::PingResponse;
use crate::proto::version_2025_6_3::SubscribeHomeAssistantStateResponse;
use crate::proto::version_2025_6_3::SubscribeLogsResponse;
use crate::to_encrypted_frame;
use crate::to_unencrypted_frame;
use base64::prelude::*;
use constant_time_eq::constant_time_eq;
use log::debug;
use log::info;
use log::trace;
use noise_protocol::CipherState;
use noise_protocol::HandshakeState;
use noise_protocol::patterns::noise_nn_psk0;
use noise_rust_crypto::ChaCha20Poly1305;
use noise_rust_crypto::Sha256;
use noise_rust_crypto::X25519;
use prost::encode_length_delimiter;
use std::collections::HashMap;
use std::str;
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
}

#[derive(TypedBuilder)]
// #[builder(mutators(
//     // Mutator has access to `x` additionally.
//     #[mutator(requires = [noise_psk, encryption_key])]
//     fn decode_encryption_key(&mut self) {
//         trace!("Decoding encryption key: {:?}", self.encryption_key);
//         if self.encryption_key.is_none() {
//             return;
//         }

//     }
// ))]
pub struct EspHomeApi {
    // Private fields
    #[builder(default=HashMap::new(), setter(skip))]
    pub(crate) components_by_key: HashMap<u32, ProtoMessage>,
    #[builder(default=HashMap::new(), setter(skip))]
    pub(crate) components_key_id: HashMap<String, u32>,
    #[builder(default = 0, setter(skip))]
    pub(crate) current_key: u32,

    #[builder(via_mutators, default=Arc::new(AtomicBool::new(false)))]
    pub(crate) encrypted_api: Arc<AtomicBool>,

    #[builder(default=Arc::new(Mutex::new(EncryptionState::Uninitialized)))]
    pub(crate) encryption_state: Arc<Mutex<EncryptionState>>,

    #[builder(via_mutators)]
    pub(crate) noise_psk: Vec<u8>,

    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) handshake_state:
        Arc<Mutex<Option<HandshakeState<X25519, ChaCha20Poly1305, Sha256>>>>,
    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) encrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>>,
    #[builder(default=Arc::new(Mutex::new(None)), setter(skip))]
    pub(crate) decrypt_cypher: Arc<Mutex<Option<CipherState<ChaCha20Poly1305>>>>,

    name: String,

    #[builder(default = None, setter(strip_option))]
    #[deprecated(note = "https://esphome.io/components/api.html#configuration-variables")]
    password: Option<String>,
    #[builder(default = None, setter(strip_option))]
    encryption_key: Option<String>,

    #[builder(default = 1)]
    api_version_major: u32,
    #[builder(default = 10)]
    api_version_minor: u32,
    #[builder(default="Rust: esphome-native-api".to_string())]
    server_info: String,

    #[builder(default = None, setter(strip_option))]
    friendly_name: Option<String>,

    #[builder(default = None, setter(strip_option))]
    mac: Option<String>,

    #[builder(default = None, setter(strip_option))]
    model: Option<String>,

    #[builder(default = None, setter(strip_option))]
    manufacturer: Option<String>,
    #[builder(default = None, setter(strip_option))]
    suggested_area: Option<String>,
    #[builder(default = None, setter(strip_option))]
    bluetooth_mac_address: Option<String>,
}

impl EspHomeApi {
    pub async fn start(
        &mut self,
        tcp_stream: TcpStream,
    ) -> Result<(broadcast::Sender<ProtoMessage>), Box<dyn std::error::Error>> {
        // Channel for direct answers (prioritized when sending)
        let (answer_messages_tx, mut answer_messages_rx) = broadcast::channel::<ProtoMessage>(16);
        // Channel for normal messages (e.g. state updates)
        let (messages_tx, mut messages_rx) = broadcast::channel::<ProtoMessage>(16);

        // Asynchronously wait for an inbound socket.
        let (mut read, mut write) = tcp_stream.into_split();

        let device_info = DeviceInfoResponse {
            api_encryption_supported: false,
            uses_password: false,
            name: self.name.clone(),
            mac_address: self.mac.clone().unwrap_or_default(),
            esphome_version: "2025.4.0".to_owned(),
            compilation_time: "".to_owned(),
            model: self.model.clone().unwrap_or_default(),
            has_deep_sleep: false,
            project_name: "".to_owned(),
            project_version: "".to_owned(),
            webserver_port: 8080,
            // See https://github.com/esphome/aioesphomeapi/blob/c1fee2f4eaff84d13ca71996bb272c28b82314fc/aioesphomeapi/model.py#L154
            legacy_bluetooth_proxy_version: 1,
            bluetooth_proxy_feature_flags: 1,
            manufacturer: self.manufacturer.clone().unwrap_or_default(),
            friendly_name: self.friendly_name.clone().unwrap_or(self.name.clone()),
            legacy_voice_assistant_version: 0,
            voice_assistant_feature_flags: 0,
            suggested_area: self.suggested_area.clone().unwrap_or_default(),
            bluetooth_mac_address: self.bluetooth_mac_address.clone().unwrap_or_default(),
        };

        let hello_response = HelloResponse {
            api_version_major: self.api_version_major,
            api_version_minor: self.api_version_minor,
            server_info: self.server_info.clone(),
            name: self.name.clone(),
        };
        let password_clone = self.password.clone();
        let api_components_clone = self.components_by_key.clone();
        let encrypted_api = self.encrypted_api.clone();
        let encrypt_cypher_clone = self.encrypt_cypher.clone();
        let decrypt_cypher_clone = self.decrypt_cypher.clone();
        let encryption_state = self.encryption_state.clone();
        let handshake_state_clone = self.handshake_state.clone();
        // Write Loop
        tokio::spawn(async move {
            let mut disconnect = false;
            loop {
                let mut answer_buf: Vec<u8> = vec![];
                let answer_message: ProtoMessage;
                // Wait for any new message
                tokio::select! {
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

                                debug!("Sending server hello: {:?}", &hello_frame);
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
                                {
                                    let mut handshake_state_change =
                                        handshake_state_clone.lock().await;

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
                                }

                                let mut message_handshake = vec![0];
                                message_handshake.extend(out);

                                let len_u16 = message_handshake.len() as u16;
                                let len_bytes = len_u16.to_be_bytes();
                                let length: Vec<u8> = vec![len_bytes[0], len_bytes[1]];

                                let mut encrypted_frame = vec![1];
                                encrypted_frame.extend(length);
                                encrypted_frame.extend(message_handshake);

                                debug!("Sending handshake: {:?}", &encrypted_frame);
                                write
                                    .write_all(&encrypted_frame)
                                    .await
                                    .expect("failed to write encrypted response");

                                *encryption_state_changer = EncryptionState::ServerHandshake;
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
                                        &mut (*encrypt_cipher_changer).as_mut().unwrap(),
                                    )
                                    .unwrap();
                                    debug!("Sending encrypted Message: {:?}", &encrypted_frame);
                                    answer_buf = [answer_buf, encrypted_frame].concat();
                                }

                                *encryption_state_changer = EncryptionState::Initialized;
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

                // loop {
                //     let answer_message = answer_messages_rx.try_recv();
                //     match answer_message {
                //         Ok(answer_message) => {
                //             debug!("Answer message: {:?}", answer_message);
                //             if encrypted_api.load(std::sync::atomic::Ordering::Relaxed) {
                //                 answer_buf =
                //                     [answer_buf, to_unencrypted_frame(&answer_message).unwrap()]
                //                         .concat();
                //             } else {
                //             }

                //             match answer_message {
                //                 ProtoMessage::DisconnectResponse(_) => {
                //                     disconnect = true;
                //                 }
                //                 ProtoMessage::ConnectResponse(response) => {
                //                     if response.invalid_password {
                //                         disconnect = true;
                //                     }
                //                 }
                //                 _ => {}
                //             }
                //         }
                //         Err(_) => break,
                //     }
                // }

                trace!("TCP Send: {:02X?}", &answer_buf);
                trace!("TCP Send: {:?}", &answer_buf);
                write
                    .write_all(&answer_buf)
                    .await
                    .expect("failed to write data to socket");
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
        let api_components_clone = api_components_clone.clone();
        let encrypted_api = self.encrypted_api.clone();
        let handshake_state_clone = self.handshake_state.clone();
        let encryption_state = self.encryption_state.clone();
        let encryption_key = self.encryption_key.clone();
        let encrypted_api = self.encrypted_api.clone();
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
                    match preamble {
                        0 => {
                            // Cleartext
                            let len = buf[cursor + 1] as usize;
                            message = cleartext_frame_to_message(
                                &buf[cursor + 2..cursor + 3 + len].to_vec(),
                            )
                            .unwrap();
                            cursor += 3 + len;
                        }
                        1 => {
                            // Encrypted

                            // Similar to https://github.com/esphome/aioesphomeapi/blob/60bcd1698dd622aeac6f4b5ec448bab0e3467c4f/aioesphomeapi/_frame_helper/noise.py#L248C17-L255
                            let mut handshake_state: HandshakeState<
                                X25519,
                                ChaCha20Poly1305,
                                Sha256,
                            > = HandshakeState::new(
                                noise_nn_psk0(),
                                false,
                                b"NoiseAPIInit\0\0",
                                None, // No static private key
                                None,
                                None,
                                None,
                            );

                            encrypted_api.store(true, std::sync::atomic::Ordering::Relaxed);
                            let noise_psk = BASE64_STANDARD
                                .decode(encryption_key.as_ref().unwrap())
                                .unwrap();

                            handshake_state.push_psk(&noise_psk);
                            handshake_state
                                .read_message_vec(&buf[3 + 3 + 1..n])
                                .expect("Failed to read message");

                            {
                                let mut mutex_changer = handshake_state_clone.lock().await;
                                *mutex_changer = Option::Some(handshake_state);
                                // mutex_changer.drop
                                let mut encryption_state_changer = encryption_state.lock().await;
                                *encryption_state_changer = EncryptionState::ClientHandshake;
                            }

                            encrypted_api.store(true, std::sync::atomic::Ordering::Relaxed);
                            let hello_message = HelloResponse {
                                api_version_major: 1,
                                api_version_minor: 42,
                                server_info: "Test Server".to_string(),
                                name: "Test Server".to_string(),
                            };
                            answer_messages_tx_clone
                                .send(ProtoMessage::HelloResponse(hello_message.clone()))
                                .unwrap();

                            return;
                        }
                        _ => {
                            debug!("Marker byte invalid: {}", preamble);
                            return;
                        }
                    }

                    match message {
                        ProtoMessage::HelloRequest(hello_request) => {
                            debug!("HelloRequest: {:?}", hello_request);

                            answer_messages_tx_clone
                                .send(ProtoMessage::HelloResponse(hello_response.clone()))
                                .unwrap();
                        }
                        ProtoMessage::DeviceInfoRequest(device_info_request) => {
                            debug!("DeviceInfoRequest: {:?}", device_info_request);
                            answer_messages_tx_clone
                                .send(ProtoMessage::DeviceInfoResponse(device_info.clone()))
                                .unwrap();
                        }
                        ProtoMessage::ConnectRequest(connect_request) => {
                            debug!("ConnectRequest: {:?}", connect_request);
                            let mut invalid = true;
                            if let Some(password) = password_clone.clone() {
                                invalid = constant_time_eq(
                                    connect_request.password.as_bytes(),
                                    password.as_bytes(),
                                );
                            } else {
                                invalid = false;
                            }

                            let response_message = ConnectResponse {
                                invalid_password: invalid,
                            };
                            answer_messages_tx_clone
                                .send(ProtoMessage::ConnectResponse(response_message))
                                .unwrap();
                        }

                        ProtoMessage::DisconnectRequest(disconnect_request) => {
                            debug!("DisconnectRequest: {:?}", disconnect_request);
                            let response_message = DisconnectResponse {};
                            answer_messages_tx_clone
                                .send(ProtoMessage::DisconnectResponse(response_message))
                                .unwrap();
                        }
                        ProtoMessage::ListEntitiesRequest(list_entities_request) => {
                            debug!("ListEntitiesRequest: {:?}", list_entities_request);

                            for (key, sensor) in &api_components_clone {
                                answer_messages_tx_clone.send(sensor.clone()).unwrap();
                            }
                            answer_messages_tx_clone
                                .send(ProtoMessage::ListEntitiesDoneResponse(
                                    ListEntitiesDoneResponse {},
                                ))
                                .unwrap();
                        }
                        ProtoMessage::PingRequest(ping_request) => {
                            debug!("PingRequest: {:?}", ping_request);
                            let response_message = PingResponse {};
                            answer_messages_tx_clone
                                .send(ProtoMessage::PingResponse(response_message))
                                .unwrap();
                        }
                        ProtoMessage::SubscribeLogsRequest(request) => {
                            debug!("SubscribeLogsRequest: {:?}", request);
                            let response_message = SubscribeLogsResponse {
                                level: 0,
                                message: "Test log".to_string().as_bytes().to_vec(),
                                send_failed: false,
                            };
                            answer_messages_tx_clone
                                .send(ProtoMessage::SubscribeLogsResponse(response_message))
                                .unwrap();
                        }
                        ProtoMessage::SubscribeBluetoothLeAdvertisementsRequest(request) => {
                            debug!("SubscribeBluetoothLeAdvertisementsRequest: {:?}", request);
                        }
                        ProtoMessage::UnsubscribeBluetoothLeAdvertisementsRequest(request) => {
                            debug!("UnsubscribeBluetoothLeAdvertisementsRequest: {:?}", request);
                        }
                        ProtoMessage::SubscribeStatesRequest(subscribe_states_request) => {
                            debug!("SubscribeStatesRequest: {:?}", subscribe_states_request);
                        }
                        ProtoMessage::SubscribeHomeassistantServicesRequest(request) => {
                            debug!("SubscribeHomeassistantServicesRequest: {:?}", request);
                        }
                        ProtoMessage::SubscribeHomeAssistantStatesRequest(
                            subscribe_homeassistant_services_request,
                        ) => {
                            debug!(
                                "SubscribeHomeAssistantStatesRequest: {:?}",
                                subscribe_homeassistant_services_request
                            );
                            let response_message = SubscribeHomeAssistantStateResponse {
                                entity_id: "test".to_string(),
                                attribute: "test".to_string(),
                                once: true,
                            };
                        }
                        ProtoMessage::ButtonCommandRequest(button_command_request) => {
                            debug!("ButtonCommandRequest: {:?}", button_command_request);
                            let button = api_components_clone
                                .get(&button_command_request.key)
                                .unwrap();
                            match button {
                                ProtoMessage::ListEntitiesButtonResponse(button) => {
                                    debug!("ButtonCommandRequest: {:?}", button);
                                    // let msg = ChangedMessage::ButtonPress {
                                    //     key: button.unique_id.clone(),
                                    // };

                                    // cloned_sender.send(msg).unwrap();
                                }
                                _ => {}
                            }
                        }
                        ProtoMessage::SwitchCommandRequest(switch_command_request) => {
                            debug!("SwitchCommandRequest: {:?}", switch_command_request);
                            let switch_entity = api_components_clone
                                .get(&switch_command_request.key)
                                .unwrap();
                            match switch_entity {
                                ProtoMessage::ListEntitiesSwitchResponse(switch_entity) => {
                                    debug!("switch_entityCommandRequest: {:?}", switch_entity);
                                    // let msg = ChangedMessage::SwitchStateCommand {
                                    //     key: switch_entity.unique_id.clone(),
                                    //     state: switch_command_request.state,
                                    // };

                                    // cloned_sender.send(msg).unwrap();
                                }
                                _ => {}
                            }
                        }
                        _ => {
                            debug!("Ignore message type: {:?}", message);
                            return;
                        }
                    }
                }
            }
        });

        Ok((messages_tx.clone()))
    }

    pub fn add_entity(&mut self, entity_id: &str, entity: ProtoMessage) {
        self.components_key_id
            .insert(entity_id.to_string(), self.current_key);
        self.components_by_key.insert(self.current_key, entity);

        self.current_key += 1;
    }

    // fn receive(&self) ->  {
    //     // Receive message from server
    //     String::new()
    // }
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
    let message_type = buffer[0];
    let packet_content = &buffer[1..];
    debug!("Message type: {}", message_type);
    debug!("Message: {:?}", packet_content);
    Ok(parser::parse_proto_message(message_type, &packet_content).unwrap())
}
