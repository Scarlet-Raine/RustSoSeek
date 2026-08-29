//! rustsoseek — a clean-room native Soulseek client.
//!
//! Implements the Soulseek peer-to-peer wire protocol directly: login, server
//! search, and peer download. No `slskd` sidecar, no HTTP API, no external
//! process.
//!
//! The implementation is clean-room: it was written from the public protocol
//! documentation only (`SLSKPROTOCOL.md`, Museek+ wiki) and contains no code
//! translated or copied from `slskd`, `Soulseek.NET`, `Nicotine+`, `aioslsk`,
//! or `museek+`.
//!
//! All wire-format types and message codecs are internal to this crate (the
//! `wire` and `proto` modules); only the high-level [`NativeClient`] and
//! [`NativeConfig`] surface is public.

pub mod error;
pub mod mocknet;
pub mod native;
pub mod proto;
pub mod share;
pub mod wire;

pub use error::Error;
pub use native::{
    BrowseResultInfo, DownloadStatus, FolderContentsResult, NativeClient, NativeConfig,
    SearchResult, SourceFolderView, UploadStatus, UserStatsInfo,
};
pub use share::ShareIndex;
