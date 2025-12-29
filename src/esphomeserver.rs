#![allow(dead_code)]

use crate::esphomeapi::EspHomeApi;
use crate::parser::ProtoMessage;

use crate::proto::version_2025_12_1::ListEntitiesDoneResponse;
use log::debug;
use log::error;
use noise_protocol::CipherState;
use noise_protocol::HandshakeState;
use noise_rust_crypto::ChaCha20Poly1305;
use noise_rust_crypto::Sha256;
use noise_rust_crypto::X25519;
use std::collections::HashMap;
use std::str;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use typed_builder::TypedBuilder;

#[derive(TypedBuilder)]
pub struct EspHomeServer {
    // Private fields
    #[builder(default=HashMap::new(), setter(skip))]
    pub(crate) components_by_key: HashMap<u32, Entity>,
    #[builder(default=HashMap::new(), setter(skip))]
    pub(crate) components_key_id: HashMap<String, u32>,
    #[builder(default = 0, setter(skip))]
    pub(crate) current_key: u32,

    #[builder(via_mutators, default=Arc::new(AtomicBool::new(false)))]
    pub(crate) encrypted_api: Arc<AtomicBool>,

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

/// Easier version of the API abstraction.
///
/// Manages entity keys internally.
impl EspHomeServer {
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
        let mut server = EspHomeApi::builder()
            .api_version_major(self.api_version_major)
            .api_version_minor(self.api_version_minor)
            // .password(self.password.or_else())
            .server_info(self.server_info.clone())
            .name(self.name.clone())
            // .friendly_name(self.friendly_name)
            // .bluetooth_mac_address(self.bluetooth_mac_address)
            // .mac(self.mac)
            // .manufacturer(self.manufacturer)
            // .model(self.model)
            // .suggested_area(self.suggested_area)
            .build();
        let (messages_tx, mut messages_rx) = server.start(tcp_stream).await?;
        let (outgoing_messages_tx, outgoing_messages_rx) = broadcast::channel::<ProtoMessage>(16);
        let api_components_clone = self.components_by_key.clone();
        // let messages_tx_clone = messages_tx.clone();

        tokio::spawn(async move {
            loop {
                messages_rx.recv().await.map_or_else(
                    |e| {
                        error!("Error receiving message: {:?}", e);
                        // Handle the error, maybe log it or break the loop
                    },
                    |message| {
                        // Process the received message
                        debug!("Received message: {:?}", message);

                        match message {
                            ProtoMessage::ListEntitiesRequest(list_entities_request) => {
                                debug!("ListEntitiesRequest: {:?}", list_entities_request);

                                for _sensor in api_components_clone.values() {
                                    // TODO: Handle the different entity types
                                    // outgoing_messages_tx.send(sensor.clone()).unwrap();
                                }
                                outgoing_messages_tx
                                    .send(ProtoMessage::ListEntitiesDoneResponse(
                                        ListEntitiesDoneResponse {},
                                    ))
                                    .unwrap();
                            }
                            other_message => {
                                // Forward the message to the outgoing channel
                                if let Err(e) = outgoing_messages_tx.send(other_message) {
                                    error!("Error sending message to outgoing channel: {:?}", e);
                                }
                            }
                        }
                    },
                );
            }
        });

        Ok((messages_tx.clone(), outgoing_messages_rx))
    }

    pub fn add_entity(&mut self, entity_id: &str, entity: Entity) {
        self.components_key_id
            .insert(entity_id.to_string(), self.current_key);
        self.components_by_key.insert(self.current_key, entity);

        self.current_key += 1;
    }
}

#[derive(Clone, Debug)]
pub enum Entity {
    BinarySensor(BinarySensor),
}

#[derive(Clone, Debug)]
pub struct BinarySensor {
    pub object_id: String,
}
