//! High-level ESPHome server implementation with entity management.
//!
//! This module provides the [`EspHomeServer`] abstraction, which simplifies working with
//! ESPHome devices by managing entities. It builds on top of the
//! lower-level [`crate::esphomeapi::EspHomeApi`] and handles entity registration and
//! message routing automatically.
//!
//! # Examples
//!
//! ```rust,no_run
//! use esphome_native_api::esphomeserver::{EspHomeServer, Entity, BinarySensor};
//! use tokio::net::TcpStream;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let stream = TcpStream::connect("192.168.1.100:6053").await?;
//!     
//!     let mut server = EspHomeServer::builder()
//!         .name("my-server".to_string())
//!         .build();
//!     
//!     // Add entities
//!     let sensor = Entity::BinarySensor(BinarySensor {
//!         object_id: "door_sensor".to_string(),
//!     });
//!     server.add_entity("door_sensor", sensor);
//!     
//!     let (tx, mut rx) = server.start(stream).await?;
//!     
//!     Ok(())
//! }
//! ```

#![allow(dead_code)]

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

use crate::esphomeapi::EspHomeApi;
use crate::parser::ProtoMessage;
use crate::proto::ListEntitiesDoneResponse;

/// High-level ESPHome server implementation.
///
/// `EspHomeServer` provides an easier-to-use abstraction over the ESPHome native API
/// by managing entity keys internally. It handles entity registration, message routing,
/// and maintains state for all registered entities.
///
/// This struct uses the builder pattern via the [`TypedBuilder`] derive macro,
/// allowing for flexible configuration.
///
/// # Examples
///
/// ```rust,no_run
/// use esphome_native_api::esphomeserver::EspHomeServer;
///
/// let server = EspHomeServer::builder()
///     .name("my-device".to_string())
///     .api_version_major(1)
///     .api_version_minor(10)
///     .encryption_key("your-base64-key".to_string())
///     .build();
/// ```
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
    /// Starts the ESPHome server and begins communication over the provided TCP stream.
    ///
    /// This method initializes the underlying [`EspHomeApi`], establishes the connection,
    /// and spawns a background task to handle message routing between the API and
    /// registered entities.
    ///
    /// # Arguments
    ///
    /// * `tcp_stream` - An established TCP connection to an ESPHome device
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - A sender for outgoing messages to the ESPHome device
    /// - A receiver for incoming messages from the ESPHome device
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be established or if the initial
    /// handshake fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use esphome_native_api::esphomeserver::EspHomeServer;
    /// # use tokio::net::TcpStream;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let stream = TcpStream::connect("192.168.1.100:6053").await?;
    /// let mut server = EspHomeServer::builder().name("client".to_string()).build();
    /// let (tx, mut rx) = server.start(stream).await?;
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

    /// Adds an entity to the server's internal registry.
    ///
    /// Each entity is assigned a unique key that is managed internally. The entity
    /// can be referenced by its string identifier in subsequent operations.
    ///
    /// # Arguments
    ///
    /// * `entity_id` - A unique string identifier for the entity
    /// * `entity` - The entity to register
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use esphome_native_api::esphomeserver::{EspHomeServer, Entity, BinarySensor};
    /// let mut server = EspHomeServer::builder().name("server".to_string()).build();
    /// let sensor = Entity::BinarySensor(BinarySensor {
    ///     object_id: "motion_sensor".to_string(),
    /// });
    /// server.add_entity("motion", sensor);
    /// ```
    pub fn add_entity(&mut self, entity_id: &str, entity: Entity) {
        self.components_key_id
            .insert(entity_id.to_string(), self.current_key);
        self.components_by_key.insert(self.current_key, entity);

        self.current_key += 1;
    }
}

/// Represents different types of entities supported by ESPHome.
///
/// This enum contains all entity types that can be registered with the server.
/// Currently, only binary sensors are implemented, but this will expand to include
/// other entity types like switches, lights, sensors, etc.
#[derive(Clone, Debug)]
pub enum Entity {
    /// A binary sensor entity (on/off state)
    BinarySensor(BinarySensor),
}

/// Represents a binary sensor entity.
///
/// Binary sensors report a simple on/off or true/false state, such as
/// door/window sensors, motion detectors, or binary switches.
#[derive(Clone, Debug)]
pub struct BinarySensor {
    /// The unique object identifier for this binary sensor
    pub object_id: String,
}
