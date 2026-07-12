//! Handle to a live ESPHome API connection.

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::error::Error;
use crate::parser::ProtoMessage;

/// A live connection to an ESPHome peer.
///
/// Returned by [`crate::esphomeapi::EspHomeApi::start`] and
/// [`crate::esphomeserver::EspHomeServer::start`], this handle owns the channels
/// used to talk to the peer and lets a consumer observe when — and why — the
/// connection ends.
///
/// # Observing termination
///
/// Unlike a bare `(Sender, Receiver)` pair, a `Connection` reports its terminal
/// outcome via [`Connection::wait`]. A [`Error::Disconnected`] result is the
/// normal way a session ends and is usually not treated as a failure:
///
/// ```rust,no_run
/// # use esphome_native_api::{esphomeapi::EspHomeApi, Error};
/// # use tokio::net::TcpStream;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let stream = TcpStream::connect("192.168.1.100:6053").await?;
/// let api = EspHomeApi::builder().name("client".to_string()).build();
/// let connection = api.start(stream).await?;
///
/// let sender = connection.sender();
/// let mut incoming = connection.incoming();
///
/// match connection.wait().await {
///     Ok(()) | Err(Error::Disconnected(_)) => { /* peer left — expected */ }
///     Err(e) => eprintln!("connection fault: {e}"),
/// }
/// # let _ = (sender, &mut incoming);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Connection {
    sender: mpsc::Sender<ProtoMessage>,
    incoming: broadcast::Receiver<ProtoMessage>,
    done: oneshot::Receiver<Result<(), Error>>,
}

impl Connection {
    /// Construct a connection handle from its parts. Internal to the crate.
    pub(crate) fn new(
        sender: mpsc::Sender<ProtoMessage>,
        incoming: broadcast::Receiver<ProtoMessage>,
        done: oneshot::Receiver<Result<(), Error>>,
    ) -> Self {
        Self {
            sender,
            incoming,
            done,
        }
    }

    /// Returns a sender for messages to the peer. Can be called multiple times;
    /// each call yields an independent, cloneable [`mpsc::Sender`].
    pub fn sender(&self) -> mpsc::Sender<ProtoMessage> {
        self.sender.clone()
    }

    /// Subscribe to messages received from the peer. Each call yields a fresh
    /// [`broadcast::Receiver`] that observes messages sent from this point on.
    pub fn incoming(&self) -> broadcast::Receiver<ProtoMessage> {
        self.incoming.resubscribe()
    }

    /// Wait for the connection to terminate and return its outcome.
    ///
    /// Returns `Ok(())` for a clean shutdown, `Err(Error::Disconnected(_))` when
    /// the peer went away (the normal case), or another [`Error`] for a genuine
    /// fault. Consuming `self` here is deliberate: obtain a [`Connection::sender`]
    /// and [`Connection::incoming`] first if you need them for the session.
    pub async fn wait(self) -> Result<(), Error> {
        // If the read-loop task was dropped without reporting (should not happen
        // in normal operation), treat it as a clean shutdown.
        self.done.await.unwrap_or(Ok(()))
    }
}
