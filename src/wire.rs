//! Soulseek wire protocol primitives (clean-room implementation).
//!
//! Implemented from the public protocol documentation only
//! (`SLSKPROTOCOL.md`, Museek+ wiki). No code from `slskd`, `Soulseek.NET`,
//! `Nicotine+`, `aioslsk`, or `museek+` was read or translated.
//!
//! Framing: every message is
//!
//! ```text
//! uint32 message_length  (little-endian; length of `code + payload`)
//! uint32 code            (little-endian)
//! bytes  payload
//! ```
//!
//! All integers are little-endian; `bool` is one byte (`0` or `1`); `string`
//! is a `uint32` byte-length prefix followed by UTF-8 bytes; `bytes` is a
//! `uint32` length prefix followed by raw bytes.

use std::io;

/// Errors produced while decoding the wire format. These are internal parse
/// errors; they never surface verbatim to API clients.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("unexpected end of message")]
    UnexpectedEof,
    #[error("invalid utf-8 in string")]
    InvalidUtf8,
    #[error("invalid message length: {0}")]
    InvalidLength(u32),
}

/// Message code constants for the server connection (server messages use a
/// `uint32` code; peer-init and distributed messages use a `uint8` code).
pub mod code {
    // Server messages (uint32 code).
    pub const LOGIN: u32 = 1;
    pub const SET_LISTEN_PORT: u32 = 2;
    pub const GET_PEER_ADDRESS: u32 = 3;
    pub const CONNECT_TO_PEER: u32 = 18;
    pub const FILE_SEARCH: u32 = 26;
    pub const SHARED_FOLDERS_FILES: u32 = 35;
    pub const GET_USER_STATS: u32 = 36;
    pub const USER_SEARCH: u32 = 42;
    pub const SERVER_PING: u32 = 32;
    pub const HAVE_NO_PARENT: u32 = 71;
    pub const PARENT_MIN_SPEED: u32 = 83;
    pub const PARENT_SPEED_RATIO: u32 = 84;
    pub const EMBEDDED_MESSAGE: u32 = 93;
    pub const ACCEPT_CHILDREN: u32 = 100;
    pub const POSSIBLE_PARENTS: u32 = 102;
    pub const BRANCH_LEVEL: u32 = 126;
    pub const BRANCH_ROOT: u32 = 127;
    pub const RESET_DISTRIBUTED: u32 = 130;
    pub const EXCLUDED_SEARCH_PHRASES: u32 = 160;
    pub const CANNOT_CONNECT_TO_PEER: u32 = 1001;

    // Peer-init messages (uint8 code).
    pub const PIERCE_FIREWALL: u8 = 0;
    pub const PEER_INIT: u8 = 1;

    // Peer messages (uint32 code).
    pub const FILE_SEARCH_RESPONSE: u32 = 9;
    pub const TRANSFER_REQUEST: u32 = 40;
    pub const TRANSFER_RESPONSE: u32 = 41;
    pub const QUEUE_UPLOAD: u32 = 43;
    pub const PLACE_IN_QUEUE_RESPONSE: u32 = 44;
    pub const UPLOAD_FAILED: u32 = 46;
    pub const UPLOAD_DENIED: u32 = 50;

    // Peer messages (uint32 code) — direct peer search/browse and folder
    // contents. Code 4 is dual-use per the protocol doc: with a trailing
    // query string it is a file-search request; token-only it is a browse.
    pub const PEER_SEARCH_OR_BROWSE: u32 = 4;
    pub const PEER_BROWSE_RESPONSE: u32 = 5;
    pub const PEER_FOLDER_CONTENTS_REQUEST: u32 = 36;
    pub const PEER_FOLDER_CONTENTS_RESPONSE: u32 = 37;

    // Distributed messages (uint8 code).
    pub const DISTRIB_SEARCH: u8 = 3;
    pub const DISTRIB_BRANCH_LEVEL: u8 = 4;
    pub const DISTRIB_BRANCH_ROOT: u8 = 5;
}

/// Connection type codes (the single-byte ASCII `type` field in `PeerInit`).
pub mod conn_type {
    pub const PEER: &str = "P";
    pub const FILE: &str = "F";
    pub const DISTRIBUTED: &str = "D";
}

/// Obfuscation type codes. agpeer v1 implements type 0 (None) only; the
/// "Rotated" (type 1) cipher key schedule is out of scope and is not
/// reverse-engineered from any GPL/AGPL implementation.
pub mod obfuscation {
    /// No obfuscation: connect to the peer's plain port.
    pub const NONE: u32 = 0;
    /// Rotated cipher (out of scope for v1).
    pub const ROTATED: u32 = 1;
}

/// Transfer direction codes.
pub mod direction {
    /// We are downloading from the peer.
    pub const DOWNLOAD: u32 = 0;
    /// We are uploading to the peer.
    pub const UPLOAD: u32 = 1;
}

/// Compute the MD5 hex digest (lowercase) of `data`, matching the digest the
/// Soulseek server expects for login (`username ++ password`) and echoed back
/// for the password.
pub fn md5_hex(data: &[u8]) -> String {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A cursor over an encoded message payload.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::UnexpectedEof);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn read_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn read_bool(&mut self) -> Result<bool, WireError> {
        Ok(self.read_u8()? != 0)
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.read_u32()? as usize;
        self.take(len)
    }

    pub fn read_string(&mut self) -> Result<String, WireError> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)
    }
}

/// A little-endian binary writer over an in-memory buffer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }

    pub fn write_bytes(&mut self, b: &[u8]) {
        self.write_u32(b.len() as u32);
        self.buf.extend_from_slice(b);
    }

    pub fn write_string(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

/// A framed wire message: a code plus its raw payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub code: u32,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(code: u32, payload: Vec<u8>) -> Self {
        Self { code, payload }
    }

    /// Encode into the full framed byte stream:
    /// `[u32 length][u32 code][payload]` where `length = 4 + payload.len()`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + self.payload.len());
        out.extend_from_slice(&((4 + self.payload.len()) as u32).to_le_bytes());
        out.extend_from_slice(&self.code.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode exactly one framed message from a byte slice. Trailing bytes are
    /// ignored (callers reading from a stream must frame externally).
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(buf);
        let len = r.read_u32()?;
        let code = r.read_u32()?;
        if len < 4 {
            return Err(WireError::InvalidLength(len));
        }
        let payload_len = (len - 4) as usize;
        let payload = r.take(payload_len)?.to_vec();
        Ok(Self { code, payload })
    }

    /// The number of bytes this message occupies when framed (length prefix
    /// included). Useful for framing a raw stream.
    pub fn framed_len(&self) -> usize {
        8 + self.payload.len()
    }
}

/// Client→server login request (server code 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub major_version: u32,
    /// MD5 hex digest of `username ++ password`.
    pub hash: String,
    pub minor_version: u32,
}

impl LoginRequest {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_string(&self.username);
        w.write_string(&self.password);
        w.write_u32(self.major_version);
        w.write_string(&self.hash);
        w.write_u32(self.minor_version);
        Message::new(code::LOGIN, w.into_inner())
    }
}

/// Server→client login response (server code 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResponse {
    pub success: bool,
    pub greet: Option<String>,
    pub own_ip: Option<u32>,
    /// MD5 hex digest of the password string.
    pub hash: Option<String>,
    pub is_supporter: Option<bool>,
    pub reason: Option<String>,
    pub detail: Option<String>,
}

impl LoginResponse {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        let success = r.read_bool()?;
        if success {
            Ok(Self {
                success: true,
                greet: Some(r.read_string()?),
                own_ip: Some(r.read_u32()?),
                hash: Some(r.read_string()?),
                is_supporter: Some(r.read_bool()?),
                reason: None,
                detail: None,
            })
        } else {
            let reason = r.read_string()?;
            let detail = if reason == "INVALIDUSERNAME" {
                Some(r.read_string()?)
            } else {
                None
            };
            Ok(Self {
                success: false,
                greet: None,
                own_ip: None,
                hash: None,
                is_supporter: None,
                reason: Some(reason),
                detail,
            })
        }
    }

    pub fn encode_success(greet: &str, own_ip: u32, hash: &str, is_supporter: bool) -> Message {
        let mut w = Writer::new();
        w.write_bool(true);
        w.write_string(greet);
        w.write_u32(own_ip);
        w.write_string(hash);
        w.write_bool(is_supporter);
        Message::new(code::LOGIN, w.into_inner())
    }

    pub fn encode_failure(reason: &str, detail: Option<&str>) -> Message {
        let mut w = Writer::new();
        w.write_bool(false);
        w.write_string(reason);
        if let Some(d) = detail {
            w.write_string(d);
        }
        Message::new(code::LOGIN, w.into_inner())
    }
}

/// Client→server listen-port announcement (server code 2). Obfuscation fields
/// are optional and omitted for v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetListenPort {
    pub port: u32,
}

impl SetListenPort {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_u32(self.port);
        Message::new(code::SET_LISTEN_PORT, w.into_inner())
    }
}

/// Client→server keep-alive ping (server code 32). Empty payload.
pub fn server_ping() -> Message {
    Message::new(code::SERVER_PING, Vec::new())
}

/// Read a single little-endian `u32` from the start of `buf`.
pub fn peek_u32(buf: &[u8]) -> Result<u32, WireError> {
    if buf.len() < 4 {
        return Err(WireError::UnexpectedEof);
    }
    Ok(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Convert a wire read failure into an `io::Error` for stream-based callers.
pub fn into_io(e: WireError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Encode a single `uint8`-code message (peer-init and distributed messages)
/// into its full framed byte stream:
/// `[u32 length][u8 code][payload]` where `length = 1 + payload.len()`.
pub fn encode_u8_frame(code: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + payload.len());
    out.extend_from_slice(&((1 + payload.len()) as u32).to_le_bytes());
    out.push(code);
    out.extend_from_slice(payload);
    out
}

/// Decode one `uint8`-code framed message, returning `(code, payload)`.
pub fn decode_u8_frame(buf: &[u8]) -> Result<(u8, Vec<u8>), WireError> {
    let mut r = Reader::new(buf);
    let len = r.read_u32()?;
    let code = r.read_u8()?;
    if len < 1 {
        return Err(WireError::InvalidLength(len));
    }
    let payload_len = (len - 1) as usize;
    let payload = r.take(payload_len)?.to_vec();
    Ok((code, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_are_little_endian() {
        let mut w = Writer::new();
        w.write_u8(0x7f);
        w.write_u16(0x1234);
        w.write_u32(0xdead_beef);
        w.write_u64(0x0102_0304_0506_0708);
        let bytes = w.into_inner();
        assert_eq!(bytes[0], 0x7f);
        assert_eq!(&bytes[1..3], &[0x34, 0x12]);
        assert_eq!(&bytes[3..7], &[0xef, 0xbe, 0xad, 0xde]);
        assert_eq!(
            &bytes[7..15],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 0x7f);
        assert_eq!(r.read_u16().unwrap(), 0x1234);
        assert_eq!(r.read_u32().unwrap(), 0xdead_beef);
        assert_eq!(r.read_u64().unwrap(), 0x0102_0304_0506_0708);
        assert!(r.is_empty());
    }

    #[test]
    fn bool_roundtrip() {
        let mut w = Writer::new();
        w.write_bool(true);
        w.write_bool(false);
        let bytes = w.into_inner();
        assert_eq!(bytes, vec![1, 0]);
        let mut r = Reader::new(&bytes);
        assert!(r.read_bool().unwrap());
        assert!(!r.read_bool().unwrap());
    }

    #[test]
    fn string_and_bytes_roundtrip() {
        let mut w = Writer::new();
        w.write_string("héllo");
        w.write_bytes(&[0, 1, 2, 255]);
        let bytes = w.into_inner();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_string().unwrap(), "héllo");
        assert_eq!(r.read_bytes().unwrap(), &[0, 1, 2, 255]);
        assert!(r.is_empty());
    }

    #[test]
    fn message_framing_roundtrip() {
        let msg = Message::new(0x2a, vec![9, 8, 7]);
        let encoded = msg.encode();
        // length prefix = 4 (code) + 3 (payload) = 7
        assert_eq!(&encoded[0..4], &7u32.to_le_bytes());
        assert_eq!(&encoded[4..8], &0x2au32.to_le_bytes());
        assert_eq!(&encoded[8..], &[9, 8, 7]);

        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn login_request_encodes_documented_layout() {
        // Documented example: username="username", password="password",
        // major=177, hash hex (32 bytes), minor=1.
        let req = LoginRequest {
            username: "username".to_string(),
            password: "password".to_string(),
            major_version: 177,
            hash: "d51c9a7e9353746a6020f9602d452929".to_string(),
            minor_version: 1,
        };
        let msg = req.encode();
        assert_eq!(msg.code, code::LOGIN);
        // username (4+8) + password (4+8) + major (4) + hash (4+32) + minor (4)
        assert_eq!(msg.payload.len(), 12 + 12 + 4 + 36 + 4);

        let mut r = Reader::new(&msg.payload);
        assert_eq!(r.read_string().unwrap(), "username");
        assert_eq!(r.read_string().unwrap(), "password");
        assert_eq!(r.read_u32().unwrap(), 177);
        assert_eq!(r.read_string().unwrap(), "d51c9a7e9353746a6020f9602d452929");
        assert_eq!(r.read_u32().unwrap(), 1);
        assert!(r.is_empty());
    }

    #[test]
    fn login_response_success_roundtrip() {
        let msg = LoginResponse::encode_success("welcome", 0x7f000001, "hash", false);
        let decoded = LoginResponse::decode(&msg).unwrap();
        assert!(decoded.success);
        assert_eq!(decoded.greet.as_deref(), Some("welcome"));
        assert_eq!(decoded.own_ip, Some(0x7f000001));
        assert_eq!(decoded.hash.as_deref(), Some("hash"));
        assert_eq!(decoded.is_supporter, Some(false));
    }

    #[test]
    fn login_response_invalid_username_carries_detail() {
        let msg = LoginResponse::encode_failure("INVALIDUSERNAME", Some("Nick empty."));
        let decoded = LoginResponse::decode(&msg).unwrap();
        assert!(!decoded.success);
        assert_eq!(decoded.reason.as_deref(), Some("INVALIDUSERNAME"));
        assert_eq!(decoded.detail.as_deref(), Some("Nick empty."));
    }

    #[test]
    fn login_response_invalid_pass_has_no_detail() {
        let msg = LoginResponse::encode_failure("INVALIDPASS", None);
        let decoded = LoginResponse::decode(&msg).unwrap();
        assert!(!decoded.success);
        assert_eq!(decoded.reason.as_deref(), Some("INVALIDPASS"));
        assert!(decoded.detail.is_none());
    }

    #[test]
    fn truncated_framing_is_an_error_not_a_panic() {
        let good = Message::new(1, vec![1, 2, 3]).encode();
        for end in 0..good.len() {
            assert!(
                Message::decode(&good[..end]).is_err(),
                "len {end} should fail"
            );
        }
    }

    #[test]
    fn server_ping_is_empty() {
        let msg = server_ping();
        assert_eq!(msg.code, code::SERVER_PING);
        assert!(msg.payload.is_empty());
        let decoded = Message::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn md5_hex_matches_known_digest() {
        // MD5("") is the well-known all-zero digest d41d8cd98f00b204e9800998ecf8427e.
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn u8_frame_roundtrip() {
        let framed = encode_u8_frame(code::PEER_INIT, b"payload");
        // length = 1 (code) + 7 (payload) = 8
        assert_eq!(&framed[0..4], &8u32.to_le_bytes());
        assert_eq!(framed[4], code::PEER_INIT);
        assert_eq!(&framed[5..], b"payload");
        let (c, p) = decode_u8_frame(&framed).unwrap();
        assert_eq!(c, code::PEER_INIT);
        assert_eq!(p, b"payload");
    }
}
