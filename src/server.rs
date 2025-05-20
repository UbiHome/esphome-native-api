use crate::parser;
use crate::parser::ProtoMessage;
use crate::proto;
use crate::proto::version_2025_4_2::BluetoothServiceData;
use crate::proto::version_2025_4_2::ConnectResponse;
use crate::proto::version_2025_4_2::DeviceInfoResponse;
use crate::proto::version_2025_4_2::DisconnectResponse;
use crate::proto::version_2025_4_2::EntityCategory;
use crate::proto::version_2025_4_2::HelloResponse;
use crate::proto::version_2025_4_2::ListEntitiesDoneResponse;
use crate::proto::version_2025_4_2::PingResponse;
use crate::proto::version_2025_4_2::SensorLastResetType;
use crate::proto::version_2025_4_2::SensorStateClass;
use crate::proto::version_2025_4_2::SubscribeHomeAssistantStateResponse;
use crate::proto::version_2025_4_2::SubscribeLogsResponse;
use crate::to_packet_from_ref;
use log::debug;
use log::error;
use log::info;
use log::trace;
use log::warn;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::ParseIntError;
use std::sync::mpsc;
use std::{future::Future, pin::Pin, str};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::Sender;

pub struct Server {
    pub(crate) address: String,
    pub(crate) components_by_key: HashMap<u32, ProtoMessage>,
    pub(crate) components_key_id: HashMap<String, u32>,
    pub(crate) device_info: DeviceInfoResponse,
}

impl Server {
    pub fn new(address: String) -> Self {
        let (tx, rx): (std::sync::mpsc::Sender<ProtoMessage>, std::sync::mpsc::Receiver<ProtoMessage>) = mpsc::channel();

        Server {
            address,
            device_info: DeviceInfoResponse {
                uses_password: false,
                name: "name".to_owned(),
                mac_address: "mac".to_owned(),
                esphome_version: "2025.4.0".to_owned(),
                compilation_time: "".to_owned(),
                model: "model".to_owned(),
                has_deep_sleep: false,
                project_name: "".to_owned(),
                project_version: "".to_owned(),
                webserver_port: 8080,
                // See https://github.com/esphome/aioesphomeapi/blob/c1fee2f4eaff84d13ca71996bb272c28b82314fc/aioesphomeapi/model.py#L154
                legacy_bluetooth_proxy_version: 1,
                bluetooth_proxy_feature_flags: 1,
                manufacturer: "Test".to_string(),
                // format!(
                //     "{} {} {}",
                //     whoami::platform(),
                //     whoami::distro(),
                //     whoami::arch()
                // ),
                friendly_name: "friendly_name".to_string(),
                legacy_voice_assistant_version: 0,
                voice_assistant_feature_flags: 0,
                suggested_area: "".to_owned(),
                bluetooth_mac_address: "04:CF:4B:1F:F9:36".to_owned(),
                // 04:CF:4B:1F:F9:36
            },
            components_by_key: HashMap::new(),
            components_key_id: HashMap::new(),
        }
    }

    pub async fn start(&self)  -> Result<(), Box<dyn std::error::Error>>{
        let addr: SocketAddr = self.address.parse().unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();

        socket.bind(addr).unwrap();
        let listener = socket.listen(128).unwrap();

        // let listener = TcpListener::bind(&addr).await?;
        debug!("Listening on: {}", addr);

        loop {
            // Asynchronously wait for an inbound socket.
            let (socket, _) = listener.accept().await?;
            debug!("Accepted request from {}", socket.peer_addr().unwrap());
            let (mut read, mut write) = tokio::io::split(socket);

            // Channel for direct answers (prioritized when sending)
            let (answer_messages_tx, answer_messages_rx) = broadcast::channel::<ProtoMessage>(16);
            // Channel for normal messages (e.g. state updates)
            let (messages_tx, messages_rx) = broadcast::channel::<ProtoMessage>(16);

            let api_components_key_id_clone = self.components_key_id.clone();
            let device_info_clone = self.device_info.clone();
            let api_components_clone = self.components_by_key.clone();
            // Read Loop
            let answer_messages_tx_clone = answer_messages_tx.clone();

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

                        let len = buf[cursor + 1] as usize;
                        let message_type = buf[cursor + 2];
                        let packet_content = &buf[cursor + 3..cursor + 3 + len];

                        debug!("Message type: {}", message_type);
                        debug!("Message: {:?}", packet_content);

                        // TODO: Parse Frames
                        let message =
                            parser::parse_proto_message(message_type, packet_content).unwrap();

                        match message {
                            ProtoMessage::HelloRequest(hello_request) => {
                                debug!("HelloRequest: {:?}", hello_request);
                                let response_message = HelloResponse {
                                    api_version_major: 1,
                                    api_version_minor: 10,
                                    server_info: "Rust: esphome-native-api".to_string(),
                                    name: device_info_clone.name.clone(),
                                };
                                answer_messages_tx_clone
                                    .send(ProtoMessage::HelloResponse(response_message))
                                    .unwrap();
                            }
                            ProtoMessage::DeviceInfoRequest(device_info_request) => {
                                debug!("DeviceInfoRequest: {:?}", device_info_request);
                                answer_messages_tx_clone
                                    .send(ProtoMessage::DeviceInfoResponse(
                                        device_info_clone.clone(),
                                    ))
                                    .unwrap();
                            }
                            ProtoMessage::ConnectRequest(connect_request) => {
                                debug!("ConnectRequest: {:?}", connect_request);
                                let response_message = ConnectResponse {
                                    invalid_password: false,
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
                                    message: "Test log".to_string(),
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

                        cursor += 3 + len;
                    }
                }
            });

            // Write Loop
            let mut answer_messages_rx_clone = answer_messages_rx.resubscribe();
            let mut messages_rx_clone = messages_rx.resubscribe();
            tokio::spawn(async move {
                let mut disconnect = false;
                loop {
                    let mut answer_buf: Vec<u8> = vec![];

                    let answer_messages = answer_messages_rx_clone.recv();
                    let normal_messages = messages_rx_clone.recv();
                    let answer_message: ProtoMessage;
                    // Wait for any new message
                    tokio::select! {
                        message = answer_messages => {
                            answer_message = message.unwrap();
                        }
                        message = normal_messages => {
                            answer_message = message.unwrap();
                        }
                    };

                    debug!("Answer message: {:?}", answer_message);
                    answer_buf =
                        [answer_buf, to_packet_from_ref(&answer_message).unwrap()].concat();
                    match answer_message {
                        ProtoMessage::DisconnectResponse(_) => {
                            disconnect = true;
                        }
                        _ => {}
                    }

                    loop {
                        // let message = messages_rx_clone.recv().await.unwrap();
                        let answer_message = answer_messages_rx_clone.try_recv();
                        match answer_message {
                            Ok(answer_message) => {
                                debug!("Answer message: {:?}", answer_message);
                                answer_buf =
                                    [answer_buf, to_packet_from_ref(&answer_message).unwrap()]
                                        .concat();

                                match answer_message {
                                    ProtoMessage::DisconnectResponse(_) => {
                                        disconnect = true;
                                    }
                                    _ => {}
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    trace!("Send response: {:?}", answer_buf);
                    write
                        .write_all(&answer_buf)
                        .await
                        .expect("failed to write data to socket");

                    if disconnect {
                        // Close the socket
                        debug!("Disconnecting");
                        write.shutdown().await.expect("failed to shutdown socket");
                        break;
                    }
                }
            });
        }
    }

    fn send(&self, message: &str) {
        // Send message to server
    }

    fn receive(&self) -> String {
        // Receive message from server
        String::new()
    }
}
