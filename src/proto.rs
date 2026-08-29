//! Typed message codecs for the Soulseek protocol (clean-room implementation).
//!
//! Implemented from the public protocol documentation only. Field orders are
//! reproduced verbatim from `SLSKPROTOCOL.md`; no implementation source was
//! read. All wire-format types stay confined to this crate.

use crate::wire::{code, direction, Message, Reader, WireError, Writer};

/// A single file entry inside a search response, plus its parsed attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchFileEntry {
    pub filename: String,
    pub size: u64,
    pub extension: String,
    /// (attribute code, value) pairs; see `wire::code` attribute types in the
    /// protocol documentation (0 = bitrate, 1 = duration, 2 = vbr, ...).
    pub attributes: Vec<(u32, u32)>,
}

/// Convenience accessors for well-known attribute codes.
impl SearchFileEntry {
    pub fn bitrate(&self) -> Option<u32> {
        self.attribute(0)
    }
    pub fn duration(&self) -> Option<u32> {
        self.attribute(1)
    }
    pub fn sample_rate(&self) -> Option<u32> {
        self.attribute(4)
    }
    pub fn bit_depth(&self) -> Option<u32> {
        self.attribute(5)
    }
    fn attribute(&self, want: u32) -> Option<u32> {
        self.attributes
            .iter()
            .find(|(code, _)| *code == want)
            .map(|(_, v)| *v)
    }
}

/// A decoded peer `FileSearchResponse` (peer message code 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSearchResponse {
    pub username: String,
    pub token: u32,
    pub files: Vec<SearchFileEntry>,
    pub slot_free: bool,
    pub avg_speed: u32,
    pub queue_length: u32,
    pub private_files: Vec<SearchFileEntry>,
}

/// Parse the (already de-compressed) payload of a `FileSearchResponse`.
fn decode_file_search_response(payload: &[u8]) -> Result<FileSearchResponse, WireError> {
    let mut r = Reader::new(payload);
    let username = r.read_string()?;
    let token = r.read_u32()?;
    let files = decode_search_files(&mut r)?;
    let slot_free = r.read_bool()?;
    let avg_speed = r.read_u32()?;
    let queue_length = r.read_u32()?;
    let _unknown = r.read_u32()?;
    let private_files = decode_search_files(&mut r)?;
    Ok(FileSearchResponse {
        username,
        token,
        files,
        slot_free,
        avg_speed,
        queue_length,
        private_files,
    })
}

fn decode_search_files(r: &mut Reader<'_>) -> Result<Vec<SearchFileEntry>, WireError> {
    let count = r.read_u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decode_single_file(r)?);
    }
    Ok(out)
}

/// Decode a peer `FileSearchResponse` message. The wire payload is zlib
/// compressed; this decompresses and parses it.
pub fn decode_file_search_response_message(msg: &Message) -> Result<FileSearchResponse, WireError> {
    use std::io::Read;
    let mut decoder = flate2::read::ZlibDecoder::new(&msg.payload[..]);
    let mut plain = Vec::new();
    decoder
        .read_to_end(&mut plain)
        .map_err(|_| WireError::InvalidLength(msg.payload.len() as u32))?;
    decode_file_search_response(&plain)
}

/// Server `FileSearch` request (server code 26): token + query.
pub struct FileSearch {
    pub token: u32,
    pub query: String,
}

impl FileSearch {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_u32(self.token);
        w.write_string(&self.query);
        Message::new(code::FILE_SEARCH, w.into_inner())
    }
}

/// Server `GetPeerAddress` request (server code 3).
pub struct GetPeerAddress {
    pub username: String,
}

impl GetPeerAddress {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_string(&self.username);
        Message::new(code::GET_PEER_ADDRESS, w.into_inner())
    }
}

/// Server `GetPeerAddress` response (server code 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetPeerAddressResponse {
    pub username: String,
    pub ip: u32,
    pub port: u32,
    pub obfuscation_type: u32,
    pub obfuscated_port: u16,
}

impl GetPeerAddressResponse {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        let username = r.read_string()?;
        let ip = r.read_u32()?;
        let port = r.read_u32()?;
        let obfuscation_type = r.read_u32()?;
        let obfuscated_port = r.read_u16()?;
        Ok(Self {
            username,
            ip,
            port,
            obfuscation_type,
            obfuscated_port,
        })
    }
}

/// Server `ConnectToPeer` request (server code 18).
pub struct ConnectToPeer {
    pub token: u32,
    pub username: String,
    pub conn_type: String,
}

impl ConnectToPeer {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_u32(self.token);
        w.write_string(&self.username);
        w.write_string(&self.conn_type);
        Message::new(code::CONNECT_TO_PEER, w.into_inner())
    }
}

/// Server `ConnectToPeer` response (server code 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectToPeerResponse {
    pub username: String,
    pub conn_type: String,
    pub ip: u32,
    pub port: u32,
    pub token: u32,
    pub privileged: bool,
    pub obfuscation_type: u32,
    pub obfuscated_port: u32,
}

impl ConnectToPeerResponse {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        Ok(Self {
            username: r.read_string()?,
            conn_type: r.read_string()?,
            ip: r.read_u32()?,
            port: r.read_u32()?,
            token: r.read_u32()?,
            privileged: r.read_bool()?,
            obfuscation_type: r.read_u32()?,
            obfuscated_port: r.read_u32()?,
        })
    }
}

/// Server `HaveNoParent` message (server code 71): inform the server whether
/// we have a distributed parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaveNoParent {
    pub no_parent: bool,
}

impl HaveNoParent {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_bool(self.no_parent);
        Message::new(code::HAVE_NO_PARENT, w.into_inner())
    }
}

/// Server `AcceptChildren` message (server code 100): inform the server whether
/// we accept distributed child nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptChildren {
    pub accept: bool,
}

impl AcceptChildren {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_bool(self.accept);
        Message::new(code::ACCEPT_CHILDREN, w.into_inner())
    }
}

/// Server `BranchLevel` message (server code 126): tell the server our position
/// (nth generation) in our distributed branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchLevel {
    pub level: u32,
}

impl BranchLevel {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_u32(self.level);
        Message::new(code::BRANCH_LEVEL, w.into_inner())
    }
}

/// Server `BranchRoot` message (server code 127): tell the server the username
/// of the root of our distributed branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchRoot {
    pub root: String,
}

impl BranchRoot {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_string(&self.root);
        Message::new(code::BRANCH_ROOT, w.into_inner())
    }
}

/// A single candidate distributed parent from `PossibleParents`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PossibleParent {
    pub username: String,
    pub ip: u32,
    pub port: u32,
}

/// Server `PossibleParents` message (server code 102): a list of candidate
/// distributed parents to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PossibleParents {
    pub parents: Vec<PossibleParent>,
}

impl PossibleParents {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        let count = r.read_u32()? as usize;
        let mut parents = Vec::with_capacity(count);
        for _ in 0..count {
            parents.push(PossibleParent {
                username: r.read_string()?,
                ip: r.read_u32()?,
                port: r.read_u32()?,
            });
        }
        Ok(Self { parents })
    }
}

/// Server `ParentMinSpeed` message (server code 83): minimum upload speed
/// required to become a distributed parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentMinSpeed {
    pub speed: u32,
}

impl ParentMinSpeed {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        Ok(Self {
            speed: r.read_u32()?,
        })
    }
}

/// Server `ParentSpeedRatio` message (server code 84): speed ratio determining
/// the maximum number of distributed children we can have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentSpeedRatio {
    pub ratio: u32,
}

impl ParentSpeedRatio {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        Ok(Self {
            ratio: r.read_u32()?,
        })
    }
}

/// Server `EmbeddedMessage` (server code 93): an embedded distributed message.
/// The only distributed message type the server sends is `DistribSearch`
/// (code 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddedMessage {
    pub distributed_code: u8,
    /// Raw distributed message associated with `distributed_code` (a framed
    /// `uint8`-code message).
    pub payload: Vec<u8>,
}

impl EmbeddedMessage {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        let distributed_code = r.read_u8()?;
        let payload = r.read_bytes()?.to_vec();
        Ok(Self {
            distributed_code,
            payload,
        })
    }

    /// Parse this embedded message's payload as a `DistribSearch`.
    pub fn as_distrib_search(&self) -> Result<DistribSearch, WireError> {
        DistribSearch::decode(&self.payload)
    }
}

/// Server `ExcludedSearchPhrases` message (server code 160): phrases not
/// allowed on the search network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedSearchPhrases {
    pub phrases: Vec<String>,
}

impl ExcludedSearchPhrases {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        let count = r.read_u32()? as usize;
        let mut phrases = Vec::with_capacity(count);
        for _ in 0..count {
            phrases.push(r.read_string()?);
        }
        Ok(Self { phrases })
    }
}

/// Decode an already-decompressed `FileSearchResponse` payload.
pub fn decode_file_search_response_plain(plain: &[u8]) -> Result<FileSearchResponse, WireError> {
    decode_file_search_response(plain)
}

/// Peer-init `PeerInit` message (peer-init code 1, `uint8` code framing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInit {
    pub username: String,
    pub conn_type: String,
    /// Always `0` today.
    pub token: u32,
}

impl PeerInit {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_string(&self.username);
        w.write_string(&self.conn_type);
        w.write_u32(self.token);
        crate::wire::encode_u8_frame(code::PEER_INIT, &w.into_inner())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let (c, payload) = crate::wire::decode_u8_frame(buf)?;
        if c != code::PEER_INIT {
            return Err(WireError::InvalidLength(c as u32));
        }
        let mut r = Reader::new(&payload);
        Ok(Self {
            username: r.read_string()?,
            conn_type: r.read_string()?,
            token: r.read_u32()?,
        })
    }
}

/// Peer-init `PierceFireWall` message (peer-init code 0, `uint8` code framing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PierceFireWall {
    pub token: u32,
}

impl PierceFireWall {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(self.token);
        crate::wire::encode_u8_frame(code::PIERCE_FIREWALL, &w.into_inner())
    }
}

/// Peer `QueueUpload` message (peer code 43): ask a peer to queue a file for us.
pub struct QueueUpload {
    pub filename: String,
}

impl QueueUpload {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_string(&self.filename);
        Message::new(code::QUEUE_UPLOAD, w.into_inner())
    }
}

/// SharedFoldersFiles(message (server code 35): announce how many folders/files
/// we share. Sent after login when shares are configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFoldersFiles {
    pub folders: u32,
    pub files: u32,
}

impl SharedFoldersFiles {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_u32(self.folders);
        w.write_u32(self.files);
        Message::new(code::SHARED_FOLDERS_FILES, w.into_inner())
    }
}

/// Server `GetUserStats` request (server code 36).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetUserStats {
    pub username: String,
}

impl GetUserStats {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_string(&self.username);
        Message::new(code::GET_USER_STATS, w.into_inner())
    }
}

/// Server `GetUserStats` response (server code 36): aggregate share/transfer
/// statistics for a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserStats {
    pub username: String,
    pub avg_speed: u32,
    pub num_downloads: u32,
    pub num_files: u32,
    pub num_dirs: u32,
}

impl UserStats {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        Ok(Self {
            username: r.read_string()?,
            avg_speed: r.read_u32()?,
            num_downloads: r.read_u32()?,
            num_files: r.read_u32()?,
            num_dirs: r.read_u32()?,
        })
    }

    /// Encode (used by the in-process mock server in tests).
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_string(&self.username);
        w.write_u32(self.avg_speed);
        w.write_u32(self.num_downloads);
        w.write_u32(self.num_files);
        w.write_u32(self.num_dirs);
        Message::new(code::GET_USER_STATS, w.into_inner())
    }
}

/// A peer-initiated file search arriving on a `P` connection (peer code 4
/// with a trailing query string; used for wishlist-style direct searches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerFileSearch {
    pub token: u32,
    pub query: String,
}

/// Decode a peer code 4 payload. Code 4 is dual-use: token + query = file
/// search; token-only = browse request. Returns `Ok(None)` when the payload is
/// token-only (browse) or malformed.
pub fn decode_peer_search_or_browse(payload: &[u8]) -> Result<Option<PeerFileSearch>, WireError> {
    let mut r = Reader::new(payload);
    let token = r.read_u32()?;
    if r.is_empty() {
        return Ok(None); // browse request
    }
    let query = r.read_string()?;
    Ok(Some(PeerFileSearch { token, query }))
}

/// Peer `BrowseRequest` (peer code 4, token-only payload): ask a peer for its
/// complete shared-folder tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowseRequest {
    pub token: u32,
}

impl BrowseRequest {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_u32(self.token);
        Message::new(code::PEER_SEARCH_OR_BROWSE, w.into_inner())
    }
}

/// One folder inside a `BrowseResponse`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowseFolder {
    /// Folder path as the peer reports it (share-relative).
    pub name: String,
    pub files: Vec<SearchFileEntry>,
}

/// Decoded peer `BrowseResponse` (peer code 5): a peer's full share tree.
/// The wire payload is zlib compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowseResponse {
    pub username: String,
    pub token: u32,
    pub folders: Vec<BrowseFolder>,
}

fn decode_folder_files(r: &mut Reader<'_>) -> Result<Vec<SearchFileEntry>, WireError> {
    let count = r.read_u32()? as usize;
    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        let entry = decode_single_file(r)?;
        files.push(entry);
    }
    Ok(files)
}

/// Decode one bare file record (`code` byte, filename, size, extension,
/// attributes). Used by browse/folder-contents responses.
fn decode_single_file(r: &mut Reader<'_>) -> Result<SearchFileEntry, WireError> {
    let _code = r.read_u8()?; // always 1
    let filename = r.read_string()?;
    let size = r.read_u64()?;
    let extension = r.read_string()?;
    let attr_count = r.read_u32()? as usize;
    let mut attributes = Vec::with_capacity(attr_count);
    for _ in 0..attr_count {
        let attr_code = r.read_u32()?;
        let attr_value = r.read_u32()?;
        attributes.push((attr_code, attr_value));
    }
    Ok(SearchFileEntry {
        filename,
        size,
        extension,
        attributes,
    })
}

fn encode_single_file(w: &mut Writer, f: &SearchFileEntry) {
    w.write_u8(1);
    w.write_string(&f.filename);
    w.write_u64(f.size);
    w.write_string(&f.extension);
    w.write_u32(f.attributes.len() as u32);
    for (c, v) in &f.attributes {
        w.write_u32(*c);
        w.write_u32(*v);
    }
}

impl BrowseResponse {
    pub fn decode(plain: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(plain);
        let username = r.read_string()?;
        let token = r.read_u32()?;
        let folder_count = r.read_u32()? as usize;
        let mut folders = Vec::with_capacity(folder_count);
        for _ in 0..folder_count {
            let name = r.read_string()?;
            let files = decode_folder_files(&mut r)?;
            folders.push(BrowseFolder { name, files });
        }
        Ok(Self {
            username,
            token,
            folders,
        })
    }

    /// Encode into a zlib-compressed peer message (as responders send it).
    pub fn encode_message(&self) -> Result<Message, std::io::Error> {
        let mut plain = Writer::new();
        plain.write_string(&self.username);
        plain.write_u32(self.token);
        plain.write_u32(self.folders.len() as u32);
        for folder in &self.folders {
            plain.write_string(&folder.name);
            plain.write_u32(folder.files.len() as u32);
            for file in &folder.files {
                encode_single_file(&mut plain, file);
            }
        }
        let compressed = zlib_compress(&plain.into_inner())?;
        Ok(Message::new(code::PEER_BROWSE_RESPONSE, compressed))
    }
}

/// Peer `FolderContentsRequest` (peer code 36): ask a peer for the contents of
/// one shared folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderContentsRequest {
    pub token: u32,
    /// Folder path as reported by the peer's browse/share listing.
    pub dir: String,
}

/// Decoded peer `FolderContentsResponse` (peer code 37). The wire payload is
/// zlib compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderContentsResponse {
    pub username: String,
    pub token: u32,
    pub dir: String,
    pub files: Vec<SearchFileEntry>,
}

impl FolderContentsRequest {
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_u32(self.token);
        w.write_string(&self.dir);
        Message::new(code::PEER_FOLDER_CONTENTS_REQUEST, w.into_inner())
    }
}

impl FolderContentsResponse {
    pub fn decode(plain: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(plain);
        let username = r.read_string()?;
        let token = r.read_u32()?;
        let dir = r.read_string()?;
        let files = decode_folder_files(&mut r)?;
        Ok(Self {
            username,
            token,
            dir,
            files,
        })
    }

    /// Encode into a zlib-compressed peer message (as responders send it).
    pub fn encode_message(&self) -> Result<Message, std::io::Error> {
        let mut plain = Writer::new();
        plain.write_string(&self.username);
        plain.write_u32(self.token);
        plain.write_string(&self.dir);
        plain.write_u32(self.files.len() as u32);
        for file in &self.files {
            encode_single_file(&mut plain, file);
        }
        let compressed = zlib_compress(&plain.into_inner())?;
        Ok(Message::new(
            code::PEER_FOLDER_CONTENTS_RESPONSE,
            compressed,
        ))
    }
}

/// Compress a payload with zlib (search/browse responses travel compressed).
pub(crate) fn zlib_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data)?;
    enc.finish()
}

impl FileSearchResponse {
    /// Encode into a zlib-compressed peer message (as responders send it).
    /// Mirrors [`decode_file_search_response`] field-for-field.
    pub fn encode_message(&self) -> Result<Message, std::io::Error> {
        let write_entries = |w: &mut Writer, files: &[SearchFileEntry]| {
            w.write_u32(files.len() as u32);
            for file in files {
                encode_single_file(w, file);
            }
        };
        let mut plain = Writer::new();
        plain.write_string(&self.username);
        plain.write_u32(self.token);
        write_entries(&mut plain, &self.files);
        plain.write_bool(self.slot_free);
        plain.write_u32(self.avg_speed);
        plain.write_u32(self.queue_length);
        plain.write_u32(0); // unknown/reserved
        write_entries(&mut plain, &self.private_files);
        let compressed = zlib_compress(&plain.into_inner())?;
        Ok(Message::new(code::FILE_SEARCH_RESPONSE, compressed))
    }
}

/// Peer `TransferRequest` message (peer code 40), sent by the uploading peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    pub direction: u32,
    pub token: u32,
    pub filename: String,
    /// Present when direction == UPLOAD (peer uploading to us).
    pub file_size: Option<u64>,
}

impl TransferRequest {
    /// Encode an uploader-side request (we are about to upload to a peer).
    pub fn encode_upload(token: u32, filename: &str, file_size: u64) -> Message {
        let mut w = Writer::new();
        w.write_u32(direction::UPLOAD);
        w.write_u32(token);
        w.write_string(filename);
        w.write_u64(file_size);
        Message::new(code::TRANSFER_REQUEST, w.into_inner())
    }

    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        let direction = r.read_u32()?;
        let token = r.read_u32()?;
        let filename = r.read_string()?;
        let file_size = if direction == direction::UPLOAD {
            Some(r.read_u64()?)
        } else {
            None
        };
        Ok(Self {
            direction,
            token,
            filename,
            file_size,
        })
    }
}

/// Peer `TransferResponse` (peer code 41). Accepting a download carries the
/// expected file size; rejecting carries a reason string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferResponse {
    pub token: u32,
    pub allowed: bool,
    pub file_size: Option<u64>,
    pub reason: Option<String>,
}

impl TransferResponse {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        let token = r.read_u32()?;
        let allowed = r.read_bool()?;
        if allowed {
            Ok(Self {
                token,
                allowed,
                file_size: Some(r.read_u64()?),
                reason: None,
            })
        } else {
            Ok(Self {
                token,
                allowed,
                file_size: None,
                reason: Some(r.read_string()?),
            })
        }
    }

    pub fn encode_accept(token: u32, file_size: u64) -> Message {
        let mut w = Writer::new();
        w.write_u32(token);
        w.write_bool(true);
        w.write_u64(file_size);
        Message::new(code::TRANSFER_RESPONSE, w.into_inner())
    }
}

/// Peer `PlaceInQueueResponse` (peer code 44).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceInQueueResponse {
    pub filename: String,
    pub place: u32,
}

impl PlaceInQueueResponse {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        Ok(Self {
            filename: r.read_string()?,
            place: r.read_u32()?,
        })
    }

    /// Encode (used by uploaders reporting queue positions).
    pub fn encode(&self) -> Message {
        let mut w = Writer::new();
        w.write_string(&self.filename);
        w.write_u32(self.place);
        Message::new(code::PLACE_IN_QUEUE_RESPONSE, w.into_inner())
    }
}

/// Peer `UploadFailed` (peer code 46): filename only.
pub struct UploadFailed {
    pub filename: String,
}

impl UploadFailed {
    pub fn decode(msg: &Message) -> Result<Self, WireError> {
        let mut r = Reader::new(&msg.payload);
        Ok(Self {
            filename: r.read_string()?,
        })
    }

    /// Encode a refusal for a requested upload (file not in our share).
    pub fn encode(filename: &str) -> Message {
        let mut w = Writer::new();
        w.write_string(filename);
        Message::new(code::UPLOAD_FAILED, w.into_inner())
    }
}

/// File-connection `FileTransferInit` message: a bare `uint32` token (no code).
pub struct FileTransferInit {
    pub token: u32,
}

impl FileTransferInit {
    pub fn encode(&self) -> Vec<u8> {
        self.token.to_le_bytes().to_vec()
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() < 4 {
            return Err(WireError::UnexpectedEof);
        }
        Ok(Self {
            token: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        })
    }
}

/// File-connection `FileOffset` message: a bare `uint64` offset (no code).
pub struct FileOffset {
    pub offset: u64,
}

impl FileOffset {
    pub fn encode(&self) -> Vec<u8> {
        self.offset.to_le_bytes().to_vec()
    }
}

/// Distributed `DistribSearch` message (distributed code 3, `uint8` code
/// framing). The message payload is distributed raw; the identifier is the
/// code point of ASCII `1` (49).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistribSearch {
    pub identifier: u32,
    pub username: String,
    pub token: u32,
    pub query: String,
}

impl DistribSearch {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(self.identifier);
        w.write_string(&self.username);
        w.write_u32(self.token);
        w.write_string(&self.query);
        crate::wire::encode_u8_frame(code::DISTRIB_SEARCH, &w.into_inner())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let (c, payload) = crate::wire::decode_u8_frame(buf)?;
        if c != code::DISTRIB_SEARCH {
            return Err(WireError::InvalidLength(c as u32));
        }
        let mut r = Reader::new(&payload);
        Ok(Self {
            identifier: r.read_u32()?,
            username: r.read_string()?,
            token: r.read_u32()?,
            query: r.read_string()?,
        })
    }
}

/// Distributed `DistribBranchLevel` message (distributed code 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistribBranchLevel {
    pub level: i32,
}

impl DistribBranchLevel {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(self.level as u32);
        crate::wire::encode_u8_frame(code::DISTRIB_BRANCH_LEVEL, &w.into_inner())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let (c, payload) = crate::wire::decode_u8_frame(buf)?;
        if c != code::DISTRIB_BRANCH_LEVEL {
            return Err(WireError::InvalidLength(c as u32));
        }
        let mut r = Reader::new(&payload);
        Ok(Self {
            level: r.read_u32()? as i32,
        })
    }
}

/// Distributed `DistribBranchRoot` message (distributed code 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistribBranchRoot {
    pub root: String,
}

impl DistribBranchRoot {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_string(&self.root);
        crate::wire::encode_u8_frame(code::DISTRIB_BRANCH_ROOT, &w.into_inner())
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let (c, payload) = crate::wire::decode_u8_frame(buf)?;
        if c != code::DISTRIB_BRANCH_ROOT {
            return Err(WireError::InvalidLength(c as u32));
        }
        let mut r = Reader::new(&payload);
        Ok(Self {
            root: r.read_string()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn file_search_encodes_token_then_query() {
        let msg = FileSearch {
            token: 42,
            query: "flac".to_string(),
        }
        .encode();
        assert_eq!(msg.code, code::FILE_SEARCH);
        let mut r = Reader::new(&msg.payload);
        assert_eq!(r.read_u32().unwrap(), 42);
        assert_eq!(r.read_string().unwrap(), "flac");
    }

    #[test]
    fn file_search_response_roundtrip_through_zlib() {
        // Build the plain payload by hand and compress it, then decode.
        let mut w = Writer::new();
        w.write_string("alice");
        w.write_u32(7);
        w.write_u32(1); // one file
        w.write_u8(1); // code
        w.write_string("music/song.flac");
        w.write_u64(30_000_000);
        w.write_string("flac");
        w.write_u32(2); // two attributes
        w.write_u32(0); // bitrate
        w.write_u32(950);
        w.write_u32(1); // duration
        w.write_u32(240);
        w.write_bool(true); // slot free
        w.write_u32(500); // avg speed
        w.write_u32(0); // queue length
        w.write_u32(0); // unknown
        w.write_u32(0); // private files

        let msg = Message::new(code::FILE_SEARCH_RESPONSE, zlib_compress(&w.into_inner()));
        let decoded = decode_file_search_response_message(&msg).unwrap();
        assert_eq!(decoded.username, "alice");
        assert_eq!(decoded.token, 7);
        assert_eq!(decoded.files.len(), 1);
        assert_eq!(decoded.files[0].filename, "music/song.flac");
        assert_eq!(decoded.files[0].size, 30_000_000);
        assert_eq!(decoded.files[0].bitrate(), Some(950));
        assert_eq!(decoded.files[0].duration(), Some(240));
        assert!(decoded.slot_free);
        assert_eq!(decoded.avg_speed, 500);
    }

    #[test]
    fn transfer_request_upload_carries_size() {
        let mut w = Writer::new();
        w.write_u32(direction::UPLOAD);
        w.write_u32(99);
        w.write_string("a/b.mp3");
        w.write_u64(12345);
        let msg = Message::new(code::TRANSFER_REQUEST, w.into_inner());
        let decoded = TransferRequest::decode(&msg).unwrap();
        assert_eq!(decoded.direction, direction::UPLOAD);
        assert_eq!(decoded.token, 99);
        assert_eq!(decoded.file_size, Some(12345));
    }

    #[test]
    fn peer_init_uses_u8_framing() {
        let init = PeerInit {
            username: "me".to_string(),
            conn_type: "P".to_string(),
            token: 0,
        };
        let framed = init.encode();
        let (c, _payload) = crate::wire::decode_u8_frame(&framed).unwrap();
        assert_eq!(c, code::PEER_INIT);
        let decoded = PeerInit::decode(&framed).unwrap();
        assert_eq!(decoded.username, "me");
        assert_eq!(decoded.conn_type, "P");
        assert_eq!(decoded.token, 0);
    }

    #[test]
    fn distrib_search_roundtrip() {
        let ds = DistribSearch {
            identifier: 49,
            username: "parent".to_string(),
            token: 5,
            query: "flac".to_string(),
        };
        let framed = ds.encode();
        let decoded = DistribSearch::decode(&framed).unwrap();
        assert_eq!(decoded.username, "parent");
        assert_eq!(decoded.token, 5);
        assert_eq!(decoded.query, "flac");
    }

    #[test]
    fn file_offset_and_init_roundtrip() {
        assert_eq!(FileTransferInit { token: 42 }.encode(), 42u32.to_le_bytes());
        assert_eq!(FileOffset { offset: 9876 }.encode(), 9876u64.to_le_bytes());
    }

    #[test]
    fn have_no_parent_roundtrip() {
        let msg = HaveNoParent { no_parent: true }.encode();
        assert_eq!(msg.code, code::HAVE_NO_PARENT);
        let mut r = Reader::new(&msg.payload);
        assert!(r.read_bool().unwrap());
        assert!(r.is_empty());
        let decoded = Message::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn accept_children_roundtrip() {
        let msg = AcceptChildren { accept: true }.encode();
        assert_eq!(msg.code, code::ACCEPT_CHILDREN);
        let mut r = Reader::new(&msg.payload);
        assert!(r.read_bool().unwrap());
        assert!(r.is_empty());
        let decoded = Message::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn branch_level_roundtrip() {
        let msg = BranchLevel { level: 3 }.encode();
        assert_eq!(msg.code, code::BRANCH_LEVEL);
        let mut r = Reader::new(&msg.payload);
        assert_eq!(r.read_u32().unwrap(), 3);
        let decoded = Message::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn branch_root_roundtrip() {
        let msg = BranchRoot {
            root: "rootuser".to_string(),
        }
        .encode();
        assert_eq!(msg.code, code::BRANCH_ROOT);
        let mut r = Reader::new(&msg.payload);
        assert_eq!(r.read_string().unwrap(), "rootuser");
        let decoded = Message::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn possible_parents_decodes() {
        let mut w = Writer::new();
        w.write_u32(2);
        w.write_string("alice");
        w.write_u32(0x7f00_0001);
        w.write_u32(2234);
        w.write_string("bob");
        w.write_u32(0x0a00_0001);
        w.write_u32(2235);
        let msg = Message::new(code::POSSIBLE_PARENTS, w.into_inner());
        let decoded = PossibleParents::decode(&msg).unwrap();
        assert_eq!(decoded.parents.len(), 2);
        assert_eq!(decoded.parents[0].username, "alice");
        assert_eq!(decoded.parents[0].ip, 0x7f00_0001);
        assert_eq!(decoded.parents[0].port, 2234);
        assert_eq!(decoded.parents[1].username, "bob");
        assert_eq!(decoded.parents[1].ip, 0x0a00_0001);
        assert_eq!(decoded.parents[1].port, 2235);
    }

    #[test]
    fn parent_min_speed_decodes() {
        let mut w = Writer::new();
        w.write_u32(500);
        let msg = Message::new(code::PARENT_MIN_SPEED, w.into_inner());
        let decoded = ParentMinSpeed::decode(&msg).unwrap();
        assert_eq!(decoded.speed, 500);
    }

    #[test]
    fn parent_speed_ratio_decodes() {
        let mut w = Writer::new();
        w.write_u32(4);
        let msg = Message::new(code::PARENT_SPEED_RATIO, w.into_inner());
        let decoded = ParentSpeedRatio::decode(&msg).unwrap();
        assert_eq!(decoded.ratio, 4);
    }

    #[test]
    fn embedded_message_wrapping_distrib_search_decodes() {
        let search = DistribSearch {
            identifier: 49,
            username: "rootuser".to_string(),
            token: 99,
            query: "flac".to_string(),
        };
        let framed = search.encode();
        let mut w = Writer::new();
        w.write_u8(code::DISTRIB_SEARCH);
        w.write_bytes(&framed);
        let msg = Message::new(code::EMBEDDED_MESSAGE, w.into_inner());
        let embedded = EmbeddedMessage::decode(&msg).unwrap();
        assert_eq!(embedded.distributed_code, code::DISTRIB_SEARCH);
        let decoded = embedded.as_distrib_search().unwrap();
        assert_eq!(decoded.username, "rootuser");
        assert_eq!(decoded.token, 99);
        assert_eq!(decoded.query, "flac");
    }

    #[test]
    fn excluded_search_phrases_decodes() {
        let mut w = Writer::new();
        w.write_u32(2);
        w.write_string("phrase one");
        w.write_string("phrase two");
        let msg = Message::new(code::EXCLUDED_SEARCH_PHRASES, w.into_inner());
        let decoded = ExcludedSearchPhrases::decode(&msg).unwrap();
        assert_eq!(decoded.phrases, vec!["phrase one", "phrase two"]);
    }

    #[test]
    fn distrib_branch_level_decode_roundtrip() {
        for level in [0i32, 3, -1, i32::MIN] {
            let framed = DistribBranchLevel { level }.encode();
            let decoded = DistribBranchLevel::decode(&framed).unwrap();
            assert_eq!(decoded.level, level);
        }
    }

    #[test]
    fn distrib_branch_root_decode_roundtrip() {
        let framed = DistribBranchRoot {
            root: "rootuser".to_string(),
        }
        .encode();
        let decoded = DistribBranchRoot::decode(&framed).unwrap();
        assert_eq!(decoded.root, "rootuser");
    }

    #[test]
    fn distrib_branch_level_rejects_wrong_code() {
        let framed = DistribSearch {
            identifier: 49,
            username: "x".to_string(),
            token: 1,
            query: "q".to_string(),
        }
        .encode();
        assert!(DistribBranchLevel::decode(&framed).is_err());
    }

    #[test]
    fn shared_folders_files_encodes_counts() {
        let msg = SharedFoldersFiles {
            folders: 3,
            files: 120,
        }
        .encode();
        assert_eq!(msg.code, code::SHARED_FOLDERS_FILES);
        let mut r = Reader::new(&msg.payload);
        assert_eq!(r.read_u32().unwrap(), 3);
        assert_eq!(r.read_u32().unwrap(), 120);
    }

    #[test]
    fn user_stats_roundtrip() {
        let stats = UserStats {
            username: "alice".to_string(),
            avg_speed: 64000,
            num_downloads: 5,
            num_files: 1000,
            num_dirs: 40,
        };
        let decoded = UserStats::decode(&stats.encode()).unwrap();
        assert_eq!(decoded, stats);
    }

    fn sample_file(name: &str) -> SearchFileEntry {
        SearchFileEntry {
            filename: name.to_string(),
            size: 42,
            extension: "mp3".to_string(),
            attributes: vec![(0, 320), (1, 180)],
        }
    }

    #[test]
    fn file_search_response_encode_decode_roundtrip() {
        let resp = FileSearchResponse {
            username: "me".to_string(),
            token: 11,
            files: vec![sample_file("music/a.mp3"), sample_file("music/b.mp3")],
            slot_free: true,
            avg_speed: 900,
            queue_length: 2,
            private_files: Vec::new(),
        };
        let msg = resp.encode_message().unwrap();
        let decoded = decode_file_search_response_message(&msg).unwrap();
        assert_eq!(decoded.username, "me");
        assert_eq!(decoded.token, 11);
        assert_eq!(decoded.files.len(), 2);
        assert_eq!(decoded.files[0].bitrate(), Some(320));
        assert!(decoded.slot_free);
        assert_eq!(decoded.queue_length, 2);
    }

    #[test]
    fn peer_search_vs_browse_payload_disambiguation() {
        // Browse request: bare token.
        let mut w = Writer::new();
        w.write_u32(77);
        assert!(decode_peer_search_or_browse(&w.into_inner())
            .unwrap()
            .is_none());

        // File search: token + query.
        let mut w = Writer::new();
        w.write_u32(88);
        w.write_string("flac");
        let s = decode_peer_search_or_browse(&w.into_inner())
            .unwrap()
            .unwrap();
        assert_eq!(s.token, 88);
        assert_eq!(s.query, "flac");
    }

    #[test]
    fn browse_response_roundtrip_through_zlib() {
        let resp = BrowseResponse {
            username: "bob".to_string(),
            token: 9,
            folders: vec![
                BrowseFolder {
                    name: "music".to_string(),
                    files: vec![sample_file("music/x.mp3")],
                },
                BrowseFolder {
                    name: "docs".to_string(),
                    files: Vec::new(),
                },
            ],
        };
        let msg = resp.encode_message().unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&msg.payload[..]);
        use std::io::Read;
        let mut plain = Vec::new();
        decoder.read_to_end(&mut plain).unwrap();
        let decoded = BrowseResponse::decode(&plain).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn folder_contents_roundtrip_through_zlib() {
        let resp = FolderContentsResponse {
            username: "carol".to_string(),
            token: 4,
            dir: "music/album".to_string(),
            files: vec![sample_file("music/album/t.mp3")],
        };
        let msg = resp.encode_message().unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(&msg.payload[..]);
        use std::io::Read;
        let mut plain = Vec::new();
        decoder.read_to_end(&mut plain).unwrap();
        let decoded = FolderContentsResponse::decode(&plain).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn folder_contents_request_encodes_token_then_dir() {
        let msg = FolderContentsRequest {
            token: 5,
            dir: "music/album".to_string(),
        }
        .encode();
        assert_eq!(msg.code, code::PEER_FOLDER_CONTENTS_REQUEST);
        let mut r = Reader::new(&msg.payload);
        assert_eq!(r.read_u32().unwrap(), 5);
        assert_eq!(r.read_string().unwrap(), "music/album");
    }
}
