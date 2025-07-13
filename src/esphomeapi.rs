use crate::frame::plaintext_frame_to_message;
use crate::parser;
use crate::parser::ProtoMessage;
use crate::proto;
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
use log::debug;
use log::info;
use log::trace;
use noise_protocol::patterns::noise_nn_psk0;
use noise_protocol::HandshakeState;
use noise_rust_crypto::ChaCha20Poly1305;
use noise_rust_crypto::Sha256;
use noise_rust_crypto::X25519;
use prost::encode_length_delimiter;
use tokio::net::TcpStream;
use std::collections::HashMap;
use std::str;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use typed_builder::TypedBuilder;
use constant_time_eq::constant_time_eq;
use base64::prelude::*;

#[derive(TypedBuilder)]
pub struct EspHomeApi {
    #[builder(default=HashMap::new(), setter(skip))]
    pub(crate) components_by_key: HashMap<u32, ProtoMessage>,
    #[builder(default=HashMap::new(), setter(skip))]
    pub(crate) components_key_id: HashMap<String, u32>,
    #[builder(default = {
        0
    }, setter(skip))]
    pub(crate) current_key: u32,

    name: String,

    #[builder(default = None, setter(strip_option))]
    #[deprecated(note="https://esphome.io/components/api.html#configuration-variables")]
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
    pub async fn start(&mut self, tcp_stream: TcpStream,) -> Result<(broadcast::Sender<ProtoMessage>), Box<dyn std::error::Error>> {
        
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


        // // Write Loop
        // tokio::spawn(async move {
        //     let mut disconnect = false;
        //     loop {
        //         let mut answer_buf: Vec<u8> = vec![];

        //         let answer_messages = answer_messages_rx.recv();
        //         let normal_messages = messages_rx.recv();
        //         let answer_message: ProtoMessage;
        //         // Wait for any new message
        //         tokio::select! {
        //             message = answer_messages => {
        //                 answer_message = message.unwrap();
        //             }
        //             message = normal_messages => {
        //                 answer_message = message.unwrap();
        //             }
        //         };

        //         debug!("Answer message: {:?}", answer_message);
        //         answer_buf =
        //             [answer_buf, to_packet_from_ref(&answer_message).unwrap()].concat();
        //         match answer_message {
        //             ProtoMessage::DisconnectResponse(_) => {
        //                 disconnect = true;
        //             }
        //             _ => {}
        //         }

        //         loop {
        //             let answer_message = answer_messages_rx.try_recv();
        //             match answer_message {
        //                 Ok(answer_message) => {
        //                     debug!("Answer message: {:?}", answer_message);
        //                     answer_buf =
        //                         [answer_buf, to_packet_from_ref(&answer_message).unwrap()]
        //                             .concat();

        //                     match answer_message {
        //                         ProtoMessage::DisconnectResponse(_) => {
        //                             disconnect = true;
        //                         }
        //                         ProtoMessage::ConnectResponse(response) => {
        //                             if response.invalid_password {
        //                                 disconnect = true;
        //                             }
        //                         }
        //                         _ => {}
        //                     }
        //                 }
        //                 Err(_) => break,
        //             }
        //         }

        //         trace!("Send response: {:?}", answer_buf);
        //         write
        //             .write_all(&answer_buf)
        //             .await
        //             .expect("failed to write data to socket");
        //         write.flush().await.expect("failed to flush data to socket");

        //         if disconnect {
        //             debug!("Disconnecting");
        //             write.shutdown().await.expect("failed to shutdown socket");
        //             break;
        //         }
        //     }
        // });
        
        // Clone all necessary data before spawning the task
        let answer_messages_tx_clone = answer_messages_tx.clone();
        let api_components_clone = api_components_clone.clone();
        
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

                trace!("TCP: {:02X?}", &buf[0..n]);

                let mut cursor = 0;

                while cursor < n {
                    // Ignore first byte
                    // Get Length of packet

                    let message;
                    let preamble = buf[cursor] as usize;
                    match preamble {
                        0 => {
                            let len = buf[cursor + 1] as usize;
                            message = plaintext_frame_to_message(&buf[cursor + 2..cursor + 3 + len]).unwrap();
                            cursor += 3 + len;
                        }
                        1 => {
                            debug!("Message: {:?}", &buf[0..n]);
                            debug!("Encrypted message received, but not supported yet");

                            let noise_psk: Vec<u8> = BASE64_STANDARD.decode(b"px7tsbK3C7bpXHr2OevEV2ZMg/FrNBw2+O2pNPbedtA=").unwrap();
                            
                            info!("Encrypted frame: {:?}", &buf[0..n]);

                            // Similar to https://github.com/esphome/aioesphomeapi/blob/60bcd1698dd622aeac6f4b5ec448bab0e3467c4f/aioesphomeapi/_frame_helper/noise.py#L248C17-L255
                            let mut handshake_state: HandshakeState<X25519, ChaCha20Poly1305, Sha256> = HandshakeState::new(
                                noise_nn_psk0(),
                                false,
                                b"NoiseAPIInit\0\0",
                                None, // No static private key
                                None,
                                None,
                                None
                            );

                            handshake_state.push_psk(&noise_psk);
                            let handshake_message = handshake_state.read_message_vec(&buf[3+ 3+ 1..n]);

                            debug!("Decrypted message: {:?}", handshake_message);

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
                            
                            let mut encrypted = vec![1];
                            encrypted.extend(length);
                            encrypted.extend(message_server_hello);

                            debug!("Answer: {:?}", &encrypted);

                            write
                                .write_all(&encrypted)
                                .await
                                .expect("failed to write encrypted response");


                            write.flush().await.expect("failed to flush encrypted response");


                            let out = handshake_state.write_message_vec(b"").unwrap();
                            trace!("Encrypted Message: {:02X?}", &out);

                            let mut message_handshake = vec![0]; 
                            message_handshake.extend(out);

                            let len_u16 = message_handshake.len() as u16;
                            let len_bytes = len_u16.to_be_bytes();
                            let length: Vec<u8> = vec![len_bytes[0], len_bytes[1]];
                            
                            let mut encrypted_frame = vec![1];
                            encrypted_frame.extend(length);
                            encrypted_frame.extend(message_handshake);

                            write
                                .write_all(&encrypted_frame)
                                .await
                                .expect("failed to write encrypted response");


                                
                            // Use normal messaging
                            let hello_message = ProtoMessage::HelloResponse(
                                proto::version_2025_6_3::HelloResponse {
                                api_version_major: 1,
                                api_version_minor: 42,
                                server_info: "Test Server".to_string(),
                                name: "Test Server".to_string(),
                            });
                            let (
                                mut cipher_decrypt,  
                                mut cipher_encrypt) = handshake_state.get_ciphers();
                                
                                // let encrypted_message_hello = cipher_encrypt.encrypt_vec(&bytes);
                            let bytes = to_encrypted_frame(&hello_message, &mut cipher_encrypt).unwrap();

                            write
                                .write_all(&bytes)
                                .await
                                .expect("failed to write encrypted response");
                            // debug!("Encrypted message: {:?}", out);
                            // Encrypted
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
                                .send(ProtoMessage::DeviceInfoResponse(
                                    device_info.clone(),
                                ))
                                .unwrap();
                        }
                        ProtoMessage::ConnectRequest(connect_request) => {
                            debug!("ConnectRequest: {:?}", connect_request);
                            let mut invalid = true;
                            if let Some(password) = password_clone.clone() {
                                invalid = constant_time_eq(connect_request.password.as_bytes(), password.as_bytes());
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
                            debug!(
                                "UnsubscribeBluetoothLeAdvertisementsRequest: {:?}",
                                request
                            );
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
        self.components_key_id.insert(entity_id.to_string(), self.current_key);
        self.components_by_key
            .insert(self.current_key, entity);

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