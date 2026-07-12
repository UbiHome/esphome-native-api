//! Error types for the ESPHome native API.
//!
//! The API distinguishes errors by *what a consumer would do differently* about
//! them rather than by where they occurred:
//!
//! - [`Error::Disconnected`] — the session ended. This is the normal way a
//!   connection terminates; most consumers treat it as informational, not a
//!   failure.
//! - [`FrameError::UnknownMessageType`] — a valid frame carrying a message type
//!   this build does not know (e.g. a newer ESPHome release). It is safe to skip
//!   and keep the connection alive; the read loop does exactly that internally.
//! - Every other [`FrameError`] / [`HandshakeError`] / [`Error::Io`] variant is a
//!   genuine fault that tears the connection down.

use std::io;

use thiserror::Error;

/// Top-level error returned by the ESPHome native API.
#[derive(Debug, Error)]
pub enum Error {
    /// The connection ended. This is an expected lifecycle event, not
    /// necessarily a failure — inspect the [`DisconnectReason`] to decide.
    #[error("client disconnected ({0})")]
    Disconnected(DisconnectReason),

    /// A frame could not be turned into a message. The connection is no longer
    /// in a known state and is torn down.
    #[error(transparent)]
    Frame(#[from] FrameError),

    /// Connection establishment or the encryption handshake failed.
    #[error(transparent)]
    Handshake(#[from] HandshakeError),

    /// The API was misconfigured (for example, an encryption key that is not
    /// valid base64).
    #[error("invalid configuration: {0}")]
    Config(String),

    /// An unexpected I/O error that is not a normal disconnect.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Why a connection ended.
///
/// Every variant is "expected" in the sense that a peer is always allowed to go
/// away; they are kept distinct so a consumer can log or react differently (for
/// example, treating [`DisconnectReason::Requested`] as fully graceful).
#[derive(Debug, Clone, Error)]
pub enum DisconnectReason {
    /// The stream reached end of file (the peer closed its side cleanly).
    #[error("end of stream")]
    Eof,

    /// The peer reset the connection abruptly (`ConnectionReset`, `BrokenPipe`,
    /// `ConnectionAborted`, …). Routine for clients such as Home Assistant.
    #[error("connection reset: {0:?}")]
    Reset(io::ErrorKind),

    /// The peer sent a `DisconnectRequest` and we completed the graceful
    /// disconnect handshake.
    #[error("disconnect requested by peer")]
    Requested,
}

/// A frame arrived but could not be decoded into a [`crate::parser::ProtoMessage`].
#[derive(Debug, Error)]
pub enum FrameError {
    /// A well-formed frame carrying a message type this build does not know.
    ///
    /// Safe to skip: the connection stays healthy. This is the forward-compat
    /// path for message types added by newer ESPHome versions.
    #[error("unknown message type {0}")]
    UnknownMessageType(u16),

    /// A recognized message type whose protobuf body failed to decode.
    #[error("failed to decode message type {message_type}")]
    Decode {
        /// The message type byte that failed to decode.
        message_type: u16,
    },

    /// AEAD decryption of an encrypted frame failed (tampered ciphertext or a
    /// desynchronized cipher).
    #[error("frame decryption failed")]
    Decrypt,

    /// The frame itself was malformed (bad length varint, wrong preamble byte,
    /// truncated payload, oversized frame, …).
    #[error("malformed frame: {0}")]
    Malformed(String),
}

/// Failures while establishing a connection or performing the encryption
/// handshake. All of these are returned before the read/write loops start.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// No bytes were received on a freshly accepted connection (for example, a
    /// port probe that connects and immediately closes).
    #[error("no data received")]
    NoData,

    /// The first byte was neither `0` (plaintext) nor `1` (encrypted).
    #[error("invalid marker byte {0}")]
    InvalidMarker(u8),

    /// The device is configured for encryption but the peer spoke plaintext.
    #[error("Only key encryption is enabled")]
    OnlyEncryptedAllowed,

    /// The peer requested encryption but no encryption key is configured.
    #[error("No encryption key set, but encrypted communication requested.")]
    EncryptionNotAllowed,

    /// The noise handshake failed its MAC check (wrong encryption key).
    #[error("Handshake MAC failure")]
    MacFailure,

    /// The noise handshake produced a cryptographic error while building our
    /// response. Unexpected; indicates a protocol or state problem rather than a
    /// peer disconnect.
    #[error("handshake crypto failure: {0}")]
    Crypto(String),

    /// The peer went away mid-handshake, before it could complete.
    #[error("peer disconnected during handshake")]
    Aborted,
}
