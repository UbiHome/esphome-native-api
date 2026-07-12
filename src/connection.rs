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
/// let api = EspHomeApi::builder().name("client".to_string()).build()?;
/// let connection = api.start(stream).await?;
///
/// let sender = connection.sender();
/// let mut receiver = connection.receiver();
///
/// match connection.wait().await {
///     Ok(()) | Err(Error::Disconnected(_)) => { /* peer left — expected */ }
///     Err(e) => eprintln!("connection fault: {e}"),
/// }
/// # let _ = (sender, &mut receiver);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Connection {
    sender: mpsc::Sender<ProtoMessage>,
    receiver: broadcast::Receiver<ProtoMessage>,
    done: oneshot::Receiver<Result<(), Error>>,
}

impl Connection {
    /// Construct a connection handle from its parts.
    pub(crate) fn new(
        sender: mpsc::Sender<ProtoMessage>,
        receiver: broadcast::Receiver<ProtoMessage>,
        done: oneshot::Receiver<Result<(), Error>>,
    ) -> Self {
        Self {
            sender,
            receiver,
            done,
        }
    }

    /// Returns a sender for messages to the peer. Can be called multiple times;
    /// each call yields an independent, cloneable [`mpsc::Sender`].
    pub fn sender(&self) -> mpsc::Sender<ProtoMessage> {
        self.sender.clone()
    }

    /// Returns a receiver for messages from the peer. Each call yields a fresh
    /// [`broadcast::Receiver`] that observes messages sent from this point on.
    pub fn receiver(&self) -> broadcast::Receiver<ProtoMessage> {
        self.receiver.resubscribe()
    }

    /// Wait for the connection to terminate and return its outcome.
    ///
    /// Returns `Ok(())` for a clean shutdown, `Err(Error::Disconnected(_))` when
    /// the peer went away (the normal case), or another [`Error`] for a genuine
    /// fault — including [`Error::TaskFailed`] if the connection's background
    /// task died (for example, panicked) without reporting an outcome.
    /// Consuming `self` here is deliberate: obtain a [`Connection::sender`]
    /// and [`Connection::receiver`] first if you need them for the session.
    pub async fn wait(self) -> Result<(), Error> {
        self.done.await.unwrap_or(Err(Error::TaskFailed))
    }
}
