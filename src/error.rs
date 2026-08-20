//! Errors produced by the native Soulseek client.
//!
//! [`Error`] is the crate-internal error type. It is deliberately free of any
//! dependency on a host application's error vocabulary so the client stays
//! self-contained and embeddable.

use thiserror::Error;

/// Errors produced by the native Soulseek client.
#[derive(Debug, Clone, Error)]
pub enum Error {
    /// The Soulseek server is not reachable.
    #[error("soulseek unavailable: {0}")]
    Unavailable(String),

    /// Credentials were rejected by the server.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// A message could not be decoded or was malformed.
    #[error("invalid message: {0}")]
    Invalid(String),

    /// An I/O failure.
    #[error("io error: {0}")]
    Io(String),

    /// An unexpected internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
