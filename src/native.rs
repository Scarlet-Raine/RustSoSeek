//! Native Soulseek client (clean-room implementation).
//!
//! Implements login, server search, and peer download directly over the
//! Soulseek wire protocol. No slskd process, no HTTP sidecar. All wire types
//! are confined to this crate via [`crate::wire`] and [`crate::proto`].

use crate::proto::{
    self, BrowseRequest, BrowseResponse, FileSearch, FileSearchResponse, FileTransferInit,
    FolderContentsRequest, FolderContentsResponse, GetPeerAddress, GetUserStats, PeerInit,
    PierceFireWall, PlaceInQueueResponse, QueueUpload, TransferRequest, TransferResponse,
    UserStats,
};
use crate::share::{ShareIndex, SharedFileMeta};
use crate::wire::{self, code, conn_type, direction, Message};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{tcp::OwnedReadHalf, tcp::OwnedWriteHalf, TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

/// Longest a single server-socket write may take before the connection is
/// treated as dead. Keeps a half-open server socket from swallowing writes
/// forever.
const SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Caller-side bound for queueing plus flushing one server message. Kept above
/// [`SERVER_WRITE_TIMEOUT`] so that, when the socket stalls, the writer's own
/// verdict is what the caller reports.
const SERVER_SEND_TIMEOUT: Duration = Duration::from_secs(12);

/// Server messages buffered ahead of the socket. A full queue means the socket
/// stalled, so further fire-and-forget writes are dropped instead of blocking.
const SERVER_WRITE_QUEUE: usize = 256;

/// Error text used when the server writer task is gone.
const SERVER_GONE: &str = "soulseek server connection closed";

/// Error text used when a server write exceeded its bound.
const SERVER_WRITE_STALLED: &str = "timed out writing to soulseek server";

/// Configuration for the native Soulseek client.
#[derive(Debug, Clone)]
pub struct NativeConfig {
    /// Soulseek server address (default `vps.slsknet.org:2242`).
    pub server_addr: String,
    pub username: String,
    pub password: String,
    /// Listen port announced to the server for peer/file connections.
    pub listen_port: u16,
    /// Directory completed downloads are written to.
    pub download_dir: String,
    /// Local directories to share with the network. Indexed at connect() and
    /// via `rescan_shares()`; announced to the server via SharedFoldersFiles.
    pub shared_dirs: Vec<String>,
    /// Maximum simultaneous upload slots for peers downloading from us.
    pub max_upload_slots: usize,
    /// Maximum simultaneous uploads per single peer.
    pub max_uploads_per_user: usize,
    /// Reserved major version (agpeer reserves 177, see SOULSEEK_REWRITE.md).
    pub major_version: u32,
    /// Reserved minor version (agpeer reserves 710, see SOULSEEK_REWRITE.md).
    pub minor_version: u32,
}

impl Default for NativeConfig {
    fn default() -> Self {
        Self {
            server_addr: "vps.slsknet.org:2242".to_string(),
            username: String::new(),
            password: String::new(),
            listen_port: 2234,
            download_dir: "downloads".to_string(),
            shared_dirs: Vec::new(),
            max_upload_slots: 1,
            max_uploads_per_user: 1,
            major_version: 177,
            minor_version: 710,
        }
    }
}

/// One normalized search result (native form, pre-shared-model).
#[derive(Debug, Clone)]
struct SearchResultEntry {
    username: String,
    filename: String,
    size: u64,
    extension: String,
    bitrate: Option<u32>,
    duration: Option<u32>,
    slot_free: bool,
    avg_speed: u32,
    queue_length: u32,
    token: u32,
}

/// A normalized search result exposed by the client. Deliberately free of any
/// host-application ID or metadata types so the client stays self-contained;
/// the embedding application is responsible for mapping this into its own
/// result model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// The Soulseek username that shared the file.
    pub username: String,
    /// Full remote path of the file (directory + filename).
    pub filename: String,
    /// File size in bytes, when advertised.
    pub size: Option<u64>,
    /// File extension (lowercased), when present.
    pub extension: Option<String>,
    /// Audio bitrate in kbps, when advertised.
    pub bitrate: Option<u32>,
    /// Audio duration in seconds, when advertised.
    pub duration: Option<u32>,
    /// Number of users ahead of us in the peer's queue.
    pub queue_length: Option<u32>,
    /// Whether the peer had a free upload slot when it responded.
    pub free_upload_slots: Option<bool>,
    /// The peer's advertised average upload speed in bytes/second.
    pub upload_speed: Option<u64>,
    /// The search token this result correlated to.
    pub token: u32,
}

/// A download we have accepted from a peer. Keyed by the peer-supplied
/// transfer token, which the `F` connection echoes in `FileTransferInit`.
#[derive(Debug, Clone)]
struct Download {
    username: String,
    filename: String,
    size: u64,
    offset: u64,
}

/// A download requested but not yet matched to a `TransferRequest`.
#[derive(Debug, Clone)]
struct PendingDownload {
    username: String,
    filename: String,
    size: u64,
}

/// Download progress snapshot exposed to the backend adapter.
#[derive(Debug, Clone)]
pub struct DownloadStatus {
    pub username: String,
    pub filename: String,
    pub size: u64,
    pub offset: u64,
}

/// One file inside a peer's shared tree, as returned by browsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareFileInfo {
    pub virtual_path: String,
    pub size: u64,
    pub extension: Option<String>,
    pub bitrate: Option<u32>,
    pub duration: Option<u32>,
}

/// One folder inside a peer's shared tree, as returned by browsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareFolderInfo {
    /// Folder path as the peer reports it (share-relative).
    pub name: String,
    pub files: Vec<ShareFileInfo>,
}

/// Full browse of a user's shares (`browse_user`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowseResultInfo {
    pub username: String,
    pub folders: Vec<ShareFolderInfo>,
}

/// Contents of a single folder on a peer's share (`folder_contents`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderContentsResult {
    pub username: String,
    pub dir: String,
    pub files: Vec<ShareFileInfo>,
}

/// The folder that contains a given search result
/// (`result_source_folder`): all sibling files plus the containing path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFolderView {
    pub username: String,
    /// Containing folder as the peer reports it.
    pub folder: String,
    pub files: Vec<ShareFileInfo>,
}

/// Aggregate statistics about another user (`user_stats`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserStatsInfo {
    pub username: String,
    /// Advertised average upload speed in bytes/second.
    pub avg_speed: u32,
    pub num_downloads: u32,
    pub num_files: u32,
    pub num_dirs: u32,
}

impl From<UserStats> for UserStatsInfo {
    fn from(u: UserStats) -> Self {
        Self {
            username: u.username,
            avg_speed: u.avg_speed,
            num_downloads: u.num_downloads,
            num_files: u.num_files,
            num_dirs: u.num_dirs,
        }
    }
}

fn file_info_from_entry(entry: &crate::proto::SearchFileEntry) -> ShareFileInfo {
    ShareFileInfo {
        virtual_path: entry.filename.clone(),
        size: entry.size,
        extension: if entry.extension.is_empty() {
            None
        } else {
            Some(entry.extension.to_lowercase())
        },
        bitrate: entry.bitrate(),
        duration: entry.duration(),
    }
}

impl From<BrowseResponse> for BrowseResultInfo {
    fn from(b: BrowseResponse) -> Self {
        Self {
            username: b.username,
            folders: b
                .folders
                .into_iter()
                .map(|f| ShareFolderInfo {
                    name: f.name,
                    files: f.files.iter().map(file_info_from_entry).collect(),
                })
                .collect(),
        }
    }
}

impl From<FolderContentsResponse> for FolderContentsResult {
    fn from(f: FolderContentsResponse) -> Self {
        Self {
            username: f.username,
            dir: f.dir,
            files: f.files.iter().map(file_info_from_entry).collect(),
        }
    }
}

/// An upload we are serving (or have offered and awaiting acceptance).
#[derive(Debug, Clone)]
struct Upload {
    username: String,
    virtual_path: String,
    local_path: std::path::PathBuf,
    size: u64,
    offset: u64,
    /// True once the downloader accepted our TransferRequest.
    accepted: bool,
    since: std::time::Instant,
}

/// A queued upload waiting for a free slot.
#[derive(Debug, Clone)]
struct PendingUpload {
    username: String,
    virtual_path: String,
}

/// Upload progress snapshot exposed to the backend adapter. Queued (not yet
/// accepted) uploads report `offset = 0`.
#[derive(Debug, Clone)]
pub struct UploadStatus {
    pub username: String,
    pub filename: String,
    pub size: u64,
    pub offset: u64,
}

/// Shared state between the client and its background tasks.
#[derive(Default)]
struct Shared {
    searches: HashMap<u32, Vec<SearchResultEntry>>,
    /// peer token -> download (populated on accepted TransferRequest).
    downloads: HashMap<u32, Download>,
    /// downloads queued but awaiting a TransferRequest.
    pending: Vec<PendingDownload>,
    /// username -> pending address resolutions (multiple waiters may race for
    /// the same peer: a download plus several search answers).
    pending_addr: HashMap<String, Vec<oneshot::Sender<SocketAddr>>>,
    /// filenames cancelled by the caller; file connections stop writing and
    /// (when requested) delete the partial file.
    cancelled: std::collections::HashSet<String>,
    /// Tokens with a file connection currently streaming, so the outbound and
    /// relayed/inbound `F` paths cannot both write the same partial file.
    active_transfers: std::collections::HashSet<u32>,
    /// Peer-rejected downloads (username, filename) not yet observed by the
    /// embedding application; drained via
    /// [`NativeClient::take_failed_downloads`].
    failed_downloads: Vec<(String, String)>,
    /// Search phrases excluded from the search network (server code 160).
    excluded_phrases: Vec<String>,
    /// Our branch position (nth generation) in the distributed network.
    branch_level: Option<u32>,
    /// Username of the root of our distributed branch.
    branch_root: Option<String>,
    /// Address of our distributed parent, if any.
    parent: Option<SocketAddr>,
    /// Addresses of our distributed children.
    children: Vec<SocketAddr>,
    /// Index of our own shared files, when `shared_dirs` is configured.
    share_index: Option<Arc<ShareIndex>>,
    /// Transfer token -> upload we are serving (awaiting acceptance or
    /// actively streaming over an `F` connection).
    uploads: HashMap<u32, Upload>,
    /// FIFO of peers waiting for a free upload slot.
    upload_queue: Vec<PendingUpload>,
    /// Uploads we failed to serve (downloader rejection), drained via
    /// `take_failed_uploads`.
    failed_uploads: Vec<(String, String)>,
    /// username -> pending `GetUserStats` response.
    pending_stats: HashMap<String, oneshot::Sender<UserStatsInfo>>,
    /// Browse token -> pending full-share tree.
    pending_browse: HashMap<u32, oneshot::Sender<BrowseResultInfo>>,
    /// Folder-contents token -> pending single folder listing.
    pending_folder: HashMap<u32, oneshot::Sender<FolderContentsResult>>,
}

/// The native Soulseek client. Cheap to clone (wraps `Arc`s).
#[derive(Clone)]
pub struct NativeClient {
    inner: Arc<NativeInner>,
}

struct NativeInner {
    config: NativeConfig,
    shared: Arc<Mutex<Shared>>,
    /// Outbound queue for the server socket, drained by the writer task.
    server_tx: mpsc::Sender<ServerWrite>,
    listener: Arc<TcpListener>,
}

/// One outbound server-socket message: the encoded bytes, plus a completion
/// signal for callers that need to know the write actually happened.
struct ServerWrite {
    bytes: Vec<u8>,
    ack: Option<oneshot::Sender<std::io::Result<()>>>,
}

impl NativeInner {
    /// Queue a server message without waiting for the write. `Full` means the
    /// socket stalled; `Closed` means the writer task is gone.
    fn server_try_send(&self, bytes: Vec<u8>) -> Result<(), mpsc::error::TrySendError<()>> {
        self.server_tx
            .try_send(ServerWrite { bytes, ack: None })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => mpsc::error::TrySendError::Full(()),
                mpsc::error::TrySendError::Closed(_) => mpsc::error::TrySendError::Closed(()),
            })
    }

    /// Queue a server message and wait, with a hard bound, for it to reach the
    /// socket. A stalled server connection therefore surfaces as an error
    /// after [`SERVER_SEND_TIMEOUT`] instead of blocking the caller forever.
    async fn server_send(&self, bytes: Vec<u8>) -> Result<(), crate::error::Error> {
        let (ack_tx, ack_rx) = oneshot::channel();
        let write = async {
            self.server_tx
                .send(ServerWrite {
                    bytes,
                    ack: Some(ack_tx),
                })
                .await
                .map_err(|_| crate::error::Error::Unavailable(SERVER_GONE.into()))?;
            match ack_rx.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(crate::error::Error::Io(e.to_string())),
                Err(_) => Err(crate::error::Error::Unavailable(SERVER_GONE.into())),
            }
        };
        match tokio::time::timeout(SERVER_SEND_TIMEOUT, write).await {
            Ok(result) => result,
            Err(_) => Err(crate::error::Error::Unavailable(
                SERVER_WRITE_STALLED.into(),
            )),
        }
    }
}

/// Map a non-blocking server-send failure into a client error.
fn server_send_error(e: mpsc::error::TrySendError<()>) -> crate::error::Error {
    match e {
        mpsc::error::TrySendError::Full(()) => crate::error::Error::Unavailable(
            "soulseek server write queue full (socket stalled)".into(),
        ),
        mpsc::error::TrySendError::Closed(()) => {
            crate::error::Error::Unavailable(SERVER_GONE.into())
        }
    }
}

impl NativeClient {
    /// Connect, log in, announce our listen port, and start the background
    /// keep-alive / server-read / peer-accept tasks.
    pub async fn connect(config: NativeConfig) -> Result<Self, crate::error::Error> {
        let mut stream = TcpStream::connect(&config.server_addr)
            .await
            .map_err(|e| crate::error::Error::Unavailable(e.to_string()))?;

        let hash = wire::md5_hex(format!("{}{}", config.username, config.password).as_bytes());
        let login = crate::wire::LoginRequest {
            username: config.username.clone(),
            password: config.password.clone(),
            major_version: config.major_version,
            hash,
            minor_version: config.minor_version,
        };
        stream
            .write_all(&login.encode().encode())
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        let response = read_message(&mut stream)
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        let login_response = crate::wire::LoginResponse::decode(&response)
            .map_err(|e| crate::error::Error::Invalid(e.to_string()))?;
        if !login_response.success {
            return Err(crate::error::Error::AuthenticationFailed);
        }

        stream
            .write_all(
                &crate::wire::SetListenPort {
                    port: config.listen_port as u32,
                }
                .encode()
                .encode(),
            )
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;

        // Index the shares up front (synchronous, bounded by local disk) and
        // announce the totals so other clients' browse/stats views work.
        let share_index = if config.shared_dirs.is_empty() {
            None
        } else {
            tracing::info!(
                dirs = config.shared_dirs.len(),
                "soulseek: indexing shared directories"
            );
            Some(Arc::new(ShareIndex::build(&config.shared_dirs)))
        };
        if let Some(index) = &share_index {
            let msg = proto::SharedFoldersFiles {
                folders: index.roots as u32,
                files: index.files.len() as u32,
            }
            .encode();
            stream
                .write_all(&msg.encode())
                .await
                .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        }

        let listener = TcpListener::bind(("0.0.0.0", config.listen_port))
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;

        let (read_half, write_half) = stream.into_split();
        let (server_tx, server_rx) = mpsc::channel(SERVER_WRITE_QUEUE);
        let shared = Arc::new(Mutex::new(Shared {
            share_index,
            ..Shared::default()
        }));
        let listener = Arc::new(listener);

        // The write half has exactly one owner, the writer task: callers queue
        // a message instead of racing for the socket, so a stalled write can
        // never hold up unrelated requests.
        Self::spawn_server_writer(write_half, server_rx);

        let inner = Arc::new(NativeInner {
            config,
            shared: shared.clone(),
            server_tx,
            listener,
        });
        let client = NativeClient { inner };

        // Announce our distributed-network posture: we have no parent yet and
        // will accept child nodes.
        client
            .inner
            .server_send(proto::HaveNoParent { no_parent: true }.encode().encode())
            .await?;
        client
            .inner
            .server_send(proto::AcceptChildren { accept: true }.encode().encode())
            .await?;

        client.spawn_keep_alive();
        client.spawn_server_read(read_half);
        client.spawn_peer_accept();
        Ok(client)
    }

    /// The socket address peers connect to for search responses / transfers.
    pub fn listen_addr(&self) -> SocketAddr {
        self.inner
            .listener
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
    }

    fn spawn_keep_alive(&self) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                match inner.server_try_send(crate::wire::server_ping().encode()) {
                    Ok(()) => {}
                    // Socket stalled: skip this ping rather than queue behind it.
                    Err(mpsc::error::TrySendError::Full(())) => {
                        tracing::warn!("soulseek: server write queue full; ping skipped");
                    }
                    Err(mpsc::error::TrySendError::Closed(())) => break,
                }
            }
        });
    }

    /// Owns the server socket's write half and drains the outbound queue. Each
    /// write is bounded by [`SERVER_WRITE_TIMEOUT`]; a socket that cannot
    /// accept a message is abandoned, so the connection fails fast instead of
    /// absorbing writes forever into a stalled send buffer.
    fn spawn_server_writer(mut write_half: OwnedWriteHalf, mut rx: mpsc::Receiver<ServerWrite>) {
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let result = match tokio::time::timeout(
                    SERVER_WRITE_TIMEOUT,
                    write_half.write_all(&job.bytes),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        SERVER_WRITE_STALLED,
                    )),
                };
                let failed = result.is_err();
                if let Some(ack) = job.ack {
                    let _ = ack.send(result);
                }
                if failed {
                    tracing::warn!("soulseek: server write failed; dropping writer");
                    break;
                }
            }
            // Dropping `rx` fails every queued caller at once instead of
            // leaving them waiting on a socket that is gone.
        });
    }

    /// Server read loop: resolve `GetPeerAddress` responses into the pending
    /// oneshot channels, and pierce the firewall for indirect connection
    /// requests (`ConnectToPeer`).
    fn spawn_server_read(&self, mut read_half: OwnedReadHalf) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            loop {
                let msg = match read_message_owned(&mut read_half).await {
                    Ok(m) => m,
                    Err(_) => return,
                };
                match msg.code {
                    code::GET_PEER_ADDRESS => {
                        if let Ok(resp) = proto::GetPeerAddressResponse::decode(&msg) {
                            resolve_peer_address(&inner, resp);
                        }
                    }
                    code::GET_USER_STATS => {
                        if let Ok(stats) = UserStats::decode(&msg) {
                            resolve_user_stats(&inner, stats);
                        }
                    }
                    code::FILE_SEARCH => {
                        // The server relays other users' searches to us; we
                        // answer from our share index over a direct peer
                        // connection to the searcher.
                        if let Some(req) = decode_server_file_search(&msg) {
                            tracing::debug!(
                                username = %req.username,
                                token = req.token,
                                query = %req.query,
                                "soulseek: server-relayed search received"
                            );
                            let inner = inner.clone();
                            tokio::spawn(async move {
                                answer_query(&inner, &req.username, req.token, &req.query).await;
                            });
                        }
                    }
                    code::CONNECT_TO_PEER => {
                        if let Ok(resp) = proto::ConnectToPeerResponse::decode(&msg) {
                            pierce_firewall(&inner, resp);
                        }
                    }
                    code::POSSIBLE_PARENTS => {
                        if let Ok(resp) = proto::PossibleParents::decode(&msg) {
                            if let Some(parent) = resp.parents.into_iter().next() {
                                let addr = SocketAddr::new(
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(parent.ip)),
                                    parent.port as u16,
                                );
                                inner.shared.lock().unwrap().parent = Some(addr);
                                let inner = inner.clone();
                                tokio::spawn(async move {
                                    connect_to_parent(inner, addr).await;
                                });
                            }
                        }
                    }
                    code::PARENT_MIN_SPEED => {
                        if let Ok(resp) = proto::ParentMinSpeed::decode(&msg) {
                            tracing::trace!(speed = resp.speed, "parent min speed");
                        }
                    }
                    code::PARENT_SPEED_RATIO => {
                        if let Ok(resp) = proto::ParentSpeedRatio::decode(&msg) {
                            tracing::trace!(ratio = resp.ratio, "parent speed ratio");
                        }
                    }
                    code::EMBEDDED_MESSAGE => {
                        if let Ok(embedded) = proto::EmbeddedMessage::decode(&msg) {
                            if embedded.distributed_code == code::DISTRIB_SEARCH {
                                if let Ok(search) = embedded.as_distrib_search() {
                                    handle_distributed_search(&inner, search);
                                }
                            }
                        }
                    }
                    code::RESET_DISTRIBUTED => {
                        let mut shared = inner.shared.lock().unwrap();
                        shared.branch_level = None;
                        shared.branch_root = None;
                        shared.parent = None;
                        shared.children.clear();
                    }
                    code::EXCLUDED_SEARCH_PHRASES => {
                        if let Ok(resp) = proto::ExcludedSearchPhrases::decode(&msg) {
                            inner.shared.lock().unwrap().excluded_phrases = resp.phrases;
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    fn spawn_peer_accept(&self) {
        let inner = self.inner.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = inner.listener.accept().await else {
                    continue;
                };
                let inner = inner.clone();
                tokio::spawn(async move {
                    let _ = handle_incoming(stream, inner).await;
                });
            }
        });
    }

    /// Start a server-side search, returning the token used to correlate
    /// results. Fails rather than hanging when the server socket cannot take
    /// the request (see [`SERVER_SEND_TIMEOUT`]).
    pub async fn start_search(&self, query: &str) -> Result<u32, crate::error::Error> {
        let token = next_token();
        let msg = FileSearch {
            token,
            query: query.to_string(),
        }
        .encode();
        // Track the token before the request goes out so a fast peer response
        // cannot arrive before we are listening for it.
        self.inner
            .shared
            .lock()
            .unwrap()
            .searches
            .insert(token, Vec::new());
        if let Err(e) = self.inner.server_send(msg.encode()).await {
            self.inner.shared.lock().unwrap().searches.remove(&token);
            return Err(e);
        }
        Ok(token)
    }

    /// Fetch the accumulated results for a search token, normalized.
    pub fn results(&self, token: u32, max_results: usize) -> Vec<SearchResult> {
        let shared = self.inner.shared.lock().unwrap();
        let Some(entries) = shared.searches.get(&token) else {
            return Vec::new();
        };
        let mut out: Vec<SearchResult> = entries.iter().map(normalize_result).collect();
        out.sort_by_key(result_health);
        out.truncate(max_results);
        out
    }

    /// Stop tracking a search.
    pub fn stop_search(&self, token: u32) {
        self.inner.shared.lock().unwrap().searches.remove(&token);
    }

    /// The address of our current distributed-network parent, if any.
    pub fn parent(&self) -> Option<SocketAddr> {
        self.inner.shared.lock().unwrap().parent
    }

    /// Phrases excluded from the search network (server code 160). Recorded for
    /// the share/respond path, which is out of scope for v1.
    pub fn excluded_phrases(&self) -> Vec<String> {
        self.inner.shared.lock().unwrap().excluded_phrases.clone()
    }

    /// Snapshot of download progress for the backend adapter.
    pub fn download_status(&self) -> Vec<DownloadStatus> {
        self.inner
            .shared
            .lock()
            .unwrap()
            .downloads
            .values()
            .map(|d| DownloadStatus {
                username: d.username.clone(),
                filename: d.filename.clone(),
                size: d.size,
                offset: d.offset,
            })
            .collect()
    }

    /// Drain peer-rejected downloads (`UploadFailed`) as `(username, filename)`
    /// pairs. The filename is reported in the form the peer refused (often
    /// backslash-separated); consumers should match paths separator-insensitively.
    pub fn take_failed_downloads(&self) -> Vec<(String, String)> {
        std::mem::take(&mut self.inner.shared.lock().unwrap().failed_downloads)
    }

    /// Cancel a download by filename, optionally deleting the partial file.
    /// Removes the pending/accepted download and marks it cancelled so any
    /// in-flight `F` connection stops writing.
    pub fn cancel(&self, filename: &str, delete_data: bool) {
        let mut shared = self.inner.shared.lock().unwrap();
        shared.cancelled.insert(filename.to_string());
        shared.pending.retain(|p| p.filename != filename);
        shared.downloads.retain(|_, d| d.filename != filename);
        drop(shared);
        if delete_data {
            remove_partial_file(&self.inner.config.download_dir, filename);
        }
    }

    /// Re-index the configured shared directories. Announced counts update on
    /// the next successful operation that needs them; the server-side totals
    /// can be refreshed by reconnecting.
    pub fn rescan_shares(&self) -> Option<(usize, usize)> {
        let index = ShareIndex::build(&self.inner.config.shared_dirs);
        let summary = Some((index.roots, index.files.len()));
        self.inner.shared.lock().unwrap().share_index = Some(Arc::new(index));
        summary
    }

    /// Snapshot of our upload progress and queued uploads. Queued entries
    /// report `offset = 0`; entries disappear once complete or cancelled.
    pub fn upload_status(&self) -> Vec<UploadStatus> {
        let mut shared = self.inner.shared.lock().unwrap();
        sweep_stale_uploads(&mut shared);
        let mut out: Vec<UploadStatus> = shared
            .uploads
            .values()
            .map(|u| UploadStatus {
                username: u.username.clone(),
                filename: u.virtual_path.clone(),
                size: u.size,
                offset: u.offset,
            })
            .collect();
        for q in &shared.upload_queue {
            let size = {
                match &shared.share_index {
                    Some(idx) => idx.lookup(&q.virtual_path).map(|f| f.size).unwrap_or(0),
                    None => 0,
                }
            };
            out.push(UploadStatus {
                username: q.username.clone(),
                filename: q.virtual_path.clone(),
                size,
                offset: 0,
            });
        }
        out
    }

    /// Drain downloads we failed to serve (peer rejected our TransferRequest),
    /// as `(username, filename)` pairs.
    pub fn take_failed_uploads(&self) -> Vec<(String, String)> {
        std::mem::take(&mut self.inner.shared.lock().unwrap().failed_uploads)
    }

    /// Cancel an outgoing upload offer/queued request. Removing an active
    /// entry also stops any in-flight `F` stream for it.
    pub fn cancel_upload(&self, username: &str, filename: &str) {
        let want = normalized_path(filename);
        let mut shared = self.inner.shared.lock().unwrap();
        shared
            .upload_queue
            .retain(|p| !(p.username == username && normalized_path(&p.virtual_path) == want));
        shared
            .uploads
            .retain(|_, u| !(u.username == username && normalized_path(&u.virtual_path) == want));
    }

    /// Fetch aggregate statistics about another user (files/dirs shared,
    /// average speed). Fails after 30 s without a server response.
    pub async fn user_stats(&self, username: &str) -> Result<UserStatsInfo, crate::error::Error> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .shared
            .lock()
            .unwrap()
            .pending_stats
            .insert(username.to_string(), tx);
        let msg = GetUserStats {
            username: username.to_string(),
        }
        .encode();
        self.inner.server_send(msg.encode()).await?;
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(info)) => Ok(info),
            Ok(Err(_)) | Err(_) => Err(crate::error::Error::Unavailable(
                "user stats response timeout".into(),
            )),
        }
    }

    /// Browse another user's complete share tree over a direct peer
    /// connection. Fails after 60 s without a response; large shares may take
    /// tens of seconds to transfer and decode.
    pub async fn browse_user(
        &self,
        username: &str,
    ) -> Result<BrowseResultInfo, crate::error::Error> {
        let token = next_token();
        let (tx, rx) = oneshot::channel();
        self.inner
            .shared
            .lock()
            .unwrap()
            .pending_browse
            .insert(token, tx);

        let inner = self.inner.clone();
        let user = username.to_string();
        // The browse response usually arrives on this same socket; keep it
        // alive by handing it to the peer message loop, which resolves the
        // pending registry entry keyed by token.
        if let Err(e) = async {
            let mut stream = connect_peer(&inner, &user).await?;
            stream
                .write_all(&BrowseRequest { token }.encode().encode())
                .await?;
            tokio::spawn(async move {
                let _ = handle_peer_messages(stream, inner, Some(user)).await;
            });
            Ok::<(), std::io::Error>(())
        }
        .await
        {
            self.inner
                .shared
                .lock()
                .unwrap()
                .pending_browse
                .remove(&token);
            return Err(crate::error::Error::Io(e.to_string()));
        }
        match tokio::time::timeout(std::time::Duration::from_secs(60), rx).await {
            Ok(Ok(tree)) => Ok(tree),
            _ => Err(crate::error::Error::Unavailable("browse timeout".into())),
        }
    }

    /// Request the contents of one folder from a peer's share. Fails after
    /// 30 s without a response.
    pub async fn folder_contents(
        &self,
        username: &str,
        dir: &str,
    ) -> Result<FolderContentsResult, crate::error::Error> {
        let token = next_token();
        let (tx, rx) = oneshot::channel();
        self.inner
            .shared
            .lock()
            .unwrap()
            .pending_folder
            .insert(token, tx);

        let inner = self.inner.clone();
        let user = username.to_string();
        let dir = dir.to_string();
        if let Err(e) = async {
            let mut stream = connect_peer(&inner, &user).await?;
            stream
                .write_all(&FolderContentsRequest { token, dir }.encode().encode())
                .await?;
            tokio::spawn(async move {
                let _ = handle_peer_messages(stream, inner, Some(user)).await;
            });
            Ok::<(), std::io::Error>(())
        }
        .await
        {
            self.inner
                .shared
                .lock()
                .unwrap()
                .pending_folder
                .remove(&token);
            return Err(crate::error::Error::Io(e.to_string()));
        }
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(folder)) => Ok(folder),
            _ => Err(crate::error::Error::Unavailable(
                "folder contents timeout".into(),
            )),
        }
    }

    /// Given one search result, browse its source peer and return the whole
    /// folder containing that file (siblings included).
    pub async fn result_source_folder(
        &self,
        result: &SearchResult,
    ) -> Result<SourceFolderView, crate::error::Error> {
        let tree = self.browse_user(&result.username).await?;
        let target = normalized_path(&result.filename);
        for folder in &tree.folders {
            for file in &folder.files {
                if normalized_path(&file.virtual_path) == target {
                    return Ok(SourceFolderView {
                        username: tree.username.clone(),
                        folder: folder.name.clone(),
                        files: folder.files.clone(),
                    });
                }
            }
        }
        Err(crate::error::Error::Invalid(format!(
            "result not found while browsing {}'s shares",
            result.username
        )))
    }

    /// Queue a download from a peer for a search result. Resolves the peer
    /// address via the server, opens a `P` connection, and sends `QueueUpload`.
    /// The matching `TransferRequest` is handled by the peer-message loop, and
    /// the eventual `F` connection is written to disk.
    pub async fn download(
        &self,
        username: &str,
        filename: &str,
        size: u64,
    ) -> Result<(), crate::error::Error> {
        let wire_filename = filename.replace('\\', "/");
        self.inner
            .shared
            .lock()
            .unwrap()
            .pending
            .push(PendingDownload {
                username: username.to_string(),
                filename: wire_filename.clone(),
                size,
            });

        let inner = self.inner.clone();
        let user = username.to_string();
        let mut stream = connect_peer(&inner, &user)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::NotFound => {
                    crate::error::Error::Unavailable(e.to_string())
                }
                _ => crate::error::Error::Io(e.to_string()),
            })?;

        stream
            .write_all(
                &QueueUpload {
                    filename: wire_filename,
                }
                .encode()
                .encode(),
            )
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;

        tokio::spawn(async move {
            let _ = handle_peer_messages(stream, inner, Some(user)).await;
        });

        Ok(())
    }
}

/// Resolve a peer address through the server and open a `P` connection
/// introducing ourselves. Multiple concurrent waiters for the same peer share
/// one `GetPeerAddress` round trip each (the server answers each request).
async fn connect_peer(
    inner: &Arc<NativeInner>,
    username: &str,
) -> Result<TcpStream, std::io::Error> {
    let (tx, rx) = oneshot::channel();
    {
        let mut shared = inner.shared.lock().unwrap();
        shared
            .pending_addr
            .entry(username.to_string())
            .or_default()
            .push(tx);
        // Bounded growth: cap waiters per peer so a runaway caller cannot leak
        // channels waiting on a silent server.
        if let Some(waiters) = shared.pending_addr.get_mut(username) {
            while waiters.len() > 32 {
                waiters.remove(0);
            }
        }
    }
    {
        let msg = GetPeerAddress {
            username: username.to_string(),
        }
        .encode();
        if let Err(e) = inner.server_try_send(msg.encode()) {
            // Release whatever was registered under us before failing.
            let mut shared = inner.shared.lock().unwrap();
            if let Some(v) = shared.pending_addr.get_mut(username) {
                v.retain(|_| false);
            }
            return Err(std::io::Error::other(server_send_error(e).to_string()));
        }
    }
    let addr = match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
        Ok(Ok(addr)) => addr,
        _ => {
            // Release whatever was registered under us.
            let mut shared = inner.shared.lock().unwrap();
            if let Some(v) = shared.pending_addr.get_mut(username) {
                v.retain(|_| false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "peer address unavailable",
            ));
        }
    };
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(
            &PeerInit {
                username: inner.config.username.clone(),
                conn_type: conn_type::PEER.to_string(),
                token: 0,
            }
            .encode(),
        )
        .await?;
    Ok(stream)
}

/// Delete a partial download file (basename only) from the download dir.
fn remove_partial_file(download_dir: &str, filename: &str) {
    let Some(name) = std::path::Path::new(filename).file_name() else {
        return;
    };
    let path = std::path::Path::new(download_dir).join(name);
    let _ = std::fs::remove_file(path);
}

/// Resolve a `GetPeerAddress` response into every pending oneshot channel
/// registered for that username.
fn resolve_peer_address(inner: &Arc<NativeInner>, resp: proto::GetPeerAddressResponse) {
    let addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(resp.ip)),
        resp.port as u16,
    );
    let waiters = inner
        .shared
        .lock()
        .unwrap()
        .pending_addr
        .remove(&resp.username)
        .unwrap_or_default();
    for tx in waiters {
        let _ = tx.send(addr);
    }
}

/// A server-relayed search addressed to us (server code 26 payload).
struct ServerFileSearch {
    username: String,
    token: u32,
    query: String,
}

fn decode_server_file_search(msg: &Message) -> Option<ServerFileSearch> {
    let mut r = crate::wire::Reader::new(&msg.payload);
    Some(ServerFileSearch {
        username: r.read_string().ok()?,
        token: r.read_u32().ok()?,
        query: r.read_string().ok()?,
    })
}

/// Map an indexed file into the wire form search/browse responses carry.
fn response_entry(meta: &SharedFileMeta) -> crate::proto::SearchFileEntry {
    crate::proto::SearchFileEntry {
        filename: meta.virtual_path.clone(),
        size: meta.size,
        extension: meta.extension.clone(),
        attributes: meta.attributes.clone(),
    }
}

/// Whether a fresh upload offer fits within the configured slot policy.
fn upload_slot_available(
    shared: &Shared,
    config_max_slots: usize,
    config_max_per_user: usize,
    username: &str,
) -> bool {
    let active = shared.uploads.values().filter(|u| u.accepted).count();
    let mine = shared
        .uploads
        .values()
        .filter(|u| u.accepted && u.username == username)
        .count();
    active < config_max_slots && mine < config_max_per_user
}

/// Drop uploads that were never accepted (or whose transfer stalled long ago),
/// freeing their slots. Refreshed on every progress write for accepted ones.
fn sweep_stale_uploads(shared: &mut Shared) {
    const CUTOFF: std::time::Duration = std::time::Duration::from_secs(300);
    let dropped: Vec<(String, String)> = shared
        .uploads
        .iter()
        .filter(|(_, u)| u.since.elapsed() >= CUTOFF)
        .map(|(_, u)| (u.username.clone(), u.virtual_path.clone()))
        .collect();
    shared.uploads.retain(|_, u| u.since.elapsed() < CUTOFF);
    for (username, vpath) in dropped {
        tracing::warn!(
            username = %username,
            filename = %vpath,
            "soulseek: upload stalled/expired without acceptance"
        );
    }
}

/// Best-effort start queued uploads now that a slot may be free. Each claim is
/// served over a fresh `P` connection dialed to the queued peer.
fn try_promote_uploads(inner: &Arc<NativeInner>) {
    // (username, virtual_path, size, token)
    let claims: Vec<(String, String, u64, u32)> = {
        let mut shared = inner.shared.lock().unwrap();
        sweep_stale_uploads(&mut shared);
        let mut out = Vec::new();
        while let Some(head) = shared.upload_queue.first().cloned() {
            if shared.uploads.values().filter(|u| u.accepted).count()
                >= inner.config.max_upload_slots
            {
                break;
            }
            let mine = shared
                .uploads
                .values()
                .filter(|u| u.accepted && u.username == head.username)
                .count();
            if mine >= inner.config.max_uploads_per_user {
                // This user is at their cap; stop scanning behind them.
                break;
            }
            shared.upload_queue.remove(0);
            let Some(f) = shared
                .share_index
                .as_ref()
                .and_then(|i| i.lookup(&head.virtual_path))
            else {
                continue; // vanished in a rescan; drop silently
            };
            let entry = (f.virtual_path.clone(), f.size, f.local_path.clone());
            let (vpath, size, local_path) = entry;
            let token = next_token();
            shared.uploads.insert(
                token,
                Upload {
                    username: head.username.clone(),
                    virtual_path: vpath.clone(),
                    local_path,
                    size,
                    offset: 0,
                    accepted: false,
                    since: std::time::Instant::now(),
                },
            );
            out.push((head.username, vpath, size, token));
        }
        out
    };

    for (username, vpath, size, token) in claims {
        let inner = inner.clone();
        tokio::spawn(async move {
            match connect_peer(&inner, &username).await {
                Ok(mut stream) => {
                    let req = TransferRequest::encode_upload(token, &vpath, size);
                    match stream.write_all(&req.encode()).await {
                        Ok(()) => {
                            tracing::info!(
                                username = %username,
                                filename = %vpath,
                                "soulseek: promoted queued upload"
                            );
                            tokio::spawn(async move {
                                let _ = handle_peer_messages(stream, inner, Some(username)).await;
                            });
                        }
                        Err(e) => {
                            inner.shared.lock().unwrap().uploads.remove(&token);
                            tracing::warn!(error = %e, "soulseek: promotion TransferRequest failed");
                        }
                    }
                }
                Err(e) => {
                    // Peer unreachable: return them to the queue front and
                    // stop promoting further this round.
                    let mut shared = inner.shared.lock().unwrap();
                    shared.uploads.remove(&token);
                    shared.upload_queue.insert(
                        0,
                        PendingUpload {
                            username,
                            virtual_path: vpath,
                        },
                    );
                    tracing::warn!(error = %e, "soulseek: promotion connect failed; requeued");
                }
            }
        });
    }
}

/// Resolve a pending `user_stats` call from a server response.
fn resolve_user_stats(inner: &Arc<NativeInner>, stats: UserStats) {
    let info = UserStatsInfo::from(stats);
    let tx = inner
        .shared
        .lock()
        .unwrap()
        .pending_stats
        .remove(&info.username);
    if let Some(tx) = tx {
        let _ = tx.send(info);
    }
}

/// Decompress a zlib-framed peer payload (search/browse/folder responses).
fn decompress_payload(payload: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    use std::io::Read;
    let mut decoder = flate2::read::ZlibDecoder::new(payload);
    let mut plain = Vec::new();
    decoder.read_to_end(&mut plain)?;
    Ok(plain)
}

/// Build a FileSearchResponse from our share index for one query, or `None`
/// when nothing matches (responders stay silent for empty result sets).
async fn answer_query(inner: &Arc<NativeInner>, searcher: &str, token: u32, query: &str) {
    let response = {
        let shared = inner.shared.lock().unwrap();
        let Some(index) = &shared.share_index else {
            return;
        };
        let matches = index.find_matches(query, &shared.excluded_phrases, 100);
        if matches.is_empty() {
            return;
        }
        let active = shared.uploads.values().filter(|u| u.accepted).count();
        FileSearchResponse {
            username: inner.config.username.clone(),
            token,
            files: matches.iter().map(response_entry).collect(),
            slot_free: active < inner.config.max_upload_slots,
            avg_speed: 0,
            queue_length: shared.upload_queue.len() as u32,
            private_files: Vec::new(),
        }
    };
    tracing::info!(
        username = %searcher,
        token,
        files = response.files.len(),
        "soulseek: answering search from shares"
    );
    match connect_peer(inner, searcher).await {
        Ok(stream) => {
            let msg = match response.encode_message() {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(error = %e, "soulseek: search response encode failed");
                    return;
                }
            };
            let inner = inner.clone();
            let searcher = searcher.to_string();
            tokio::spawn(async move {
                let mut stream = stream;
                if stream.write_all(&msg.encode()).await.is_ok() {
                    // Keep serving this socket for a follow-up QueueUpload
                    // arriving over the same connection.
                    let _ = handle_peer_messages(stream, inner, Some(searcher)).await;
                }
            });
        }
        Err(e) => {
            tracing::warn!(username = %searcher, error = %e, "soulseek: failed to dial searcher");
        }
    }
}

enum QueueAction {
    /// Not in our share: refuse.
    Fail,
    /// No slot available: enqueue and report position.
    Queue(u32),
    /// Slot available: offer with this token.
    Offer {
        token: u32,
        vpath: String,
        size: u64,
    },
}

/// Handle an inbound `QueueUpload` from a peer on an established `P`
/// connection: refuse, enqueue with a position report, or offer immediately.
async fn handle_queue_upload(
    stream: &mut TcpStream,
    inner: &Arc<NativeInner>,
    requested: String,
    peer_username: Option<&str>,
) -> Result<(), std::io::Error> {
    let Some(user) = peer_username else {
        return Ok(());
    };
    let action = {
        let mut shared = inner.shared.lock().unwrap();
        sweep_stale_uploads(&mut shared);
        let found = shared
            .share_index
            .as_ref()
            .and_then(|i| i.lookup(&requested))
            .map(|f| (f.virtual_path.clone(), f.size));
        match found {
            None => QueueAction::Fail,
            Some((vpath, size)) => {
                if upload_slot_available(
                    &shared,
                    inner.config.max_upload_slots,
                    inner.config.max_uploads_per_user,
                    user,
                ) {
                    // Re-lookup to grab local path within the same lock.
                    let local_path = shared
                        .share_index
                        .as_ref()
                        .and_then(|i| i.lookup(&vpath))
                        .map(|f| f.local_path.clone())
                        .unwrap_or_default();
                    let token = next_token();
                    shared.uploads.insert(
                        token,
                        Upload {
                            username: user.to_string(),
                            virtual_path: vpath.clone(),
                            local_path,
                            size,
                            offset: 0,
                            accepted: false,
                            since: std::time::Instant::now(),
                        },
                    );
                    QueueAction::Offer { token, vpath, size }
                } else {
                    shared.upload_queue.push(PendingUpload {
                        username: user.to_string(),
                        virtual_path: vpath.clone(),
                    });
                    tracing::debug!(
                        username = %user,
                        filename = %vpath,
                        place = shared.upload_queue.len(),
                        "soulseek: upload queued"
                    );
                    QueueAction::Queue(shared.upload_queue.len() as u32)
                }
            }
        }
    };
    match action {
        QueueAction::Fail => {
            stream
                .write_all(&proto::UploadFailed::encode(&requested).encode())
                .await?;
        }
        QueueAction::Queue(place) => {
            // Echo the requested form; peers match on it separator-insensitively.
            stream
                .write_all(
                    &PlaceInQueueResponse {
                        filename: requested.clone(),
                        place,
                    }
                    .encode()
                    .encode(),
                )
                .await?;
        }
        QueueAction::Offer { token, vpath, size } => {
            let req = TransferRequest::encode_upload(token, &vpath, size).encode();
            if let Err(e) = stream.write_all(&req).await {
                // Requester is gone before we could even offer; release slot.
                inner.shared.lock().unwrap().uploads.remove(&token);
                return Err(e);
            }
            tracing::info!(
                username = %user,
                filename = %vpath,
                size,
                "soulseek: offered upload"
            );
        }
    }
    Ok(())
}

/// Process the downloader's acceptance/rejection of our TransferRequest.
fn handle_transfer_response_upload(inner: &Arc<NativeInner>, tr: TransferResponse) {
    if tr.allowed {
        let mut shared = inner.shared.lock().unwrap();
        if let Some(u) = shared.uploads.get_mut(&tr.token) {
            u.accepted = true;
            u.since = std::time::Instant::now();
            tracing::info!(
                username = %u.username,
                filename = %u.virtual_path,
                "soulseek: downloader accepted upload; awaiting F connection"
            );
        }
        return;
    }
    let removed = inner.shared.lock().unwrap().uploads.remove(&tr.token);
    if let Some(u) = removed {
        let entry = (u.username.clone(), u.virtual_path.clone());
        inner.shared.lock().unwrap().failed_uploads.push(entry);
        tracing::info!(
            filename = %u.virtual_path,
            reason = ?tr.reason,
            "soulseek: downloader rejected our transfer offer"
        );
    }
    try_promote_uploads(inner);
}

/// Answer an inbound direct search (peer code 4 carrying a query) on the same
/// connection it arrived on.
async fn handle_peer_file_search(
    stream: &mut TcpStream,
    inner: &Arc<NativeInner>,
    search: proto::PeerFileSearch,
) -> Result<(), std::io::Error> {
    let response = {
        let shared = inner.shared.lock().unwrap();
        let Some(index) = &shared.share_index else {
            return Ok(());
        };
        let matches = index.find_matches(&search.query, &shared.excluded_phrases, 100);
        if matches.is_empty() {
            return Ok(());
        }
        let active = shared.uploads.values().filter(|u| u.accepted).count();
        FileSearchResponse {
            username: inner.config.username.clone(),
            token: search.token,
            files: matches.iter().map(response_entry).collect(),
            slot_free: active < inner.config.max_upload_slots,
            avg_speed: 0,
            queue_length: shared.upload_queue.len() as u32,
            private_files: Vec::new(),
        }
    };
    let msg = response.encode_message()?;
    stream.write_all(&msg.encode()).await
}

/// Answer a browse request (peer code 4, token-only payload) with our complete
/// share tree grouped by folder, zlib-compressed, on the same socket.
async fn handle_browse_request(
    stream: &mut TcpStream,
    inner: &Arc<NativeInner>,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    let mut r = crate::wire::Reader::new(payload);
    let token = r.read_u32().map_err(wire::into_io)?;
    let folders: Vec<(String, Vec<crate::proto::SearchFileEntry>)> = {
        let shared = inner.shared.lock().unwrap();
        match &shared.share_index {
            None => Vec::new(),
            Some(index) => {
                use std::collections::BTreeMap;
                let mut groups: BTreeMap<String, Vec<crate::proto::SearchFileEntry>> =
                    BTreeMap::new();
                for f in &index.files {
                    let dir = match f.virtual_path.rfind('/') {
                        Some(i) => f.virtual_path[..i].to_string(),
                        None => String::new(),
                    };
                    groups.entry(dir).or_default().push(response_entry(f));
                }
                groups.into_iter().collect()
            }
        }
    };
    let resp = BrowseResponse {
        username: inner.config.username.clone(),
        token,
        folders: folders
            .into_iter()
            .map(|(name, files)| crate::proto::BrowseFolder { name, files })
            .collect(),
    };
    let msg = resp.encode_message()?;
    tracing::info!(
        token,
        folders = resp.folders.len(),
        "soulseek: answering browse request"
    );
    stream.write_all(&msg.encode()).await
}

/// Answer a `FolderContentsRequest` (peer code 36) for one directory.
async fn handle_folder_request(
    stream: &mut TcpStream,
    inner: &Arc<NativeInner>,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    let mut r = crate::wire::Reader::new(payload);
    let token = r.read_u32().map_err(wire::into_io)?;
    let dir = r.read_string().map_err(wire::into_io)?;
    let want_dir = normalized_path(&dir).to_lowercase();
    let files: Vec<crate::proto::SearchFileEntry> = {
        let shared = inner.shared.lock().unwrap();
        match &shared.share_index {
            Some(index) => index
                .files
                .iter()
                .filter(|f| {
                    let parent = match normalized_path(&f.virtual_path).rfind('/') {
                        Some(i) => normalized_path(&f.virtual_path)[..i].to_lowercase(),
                        None => String::new(),
                    };
                    parent == want_dir
                })
                .map(response_entry)
                .collect(),
            None => Vec::new(),
        }
    };
    let resp = FolderContentsResponse {
        username: inner.config.username.clone(),
        token,
        dir,
        files,
    };
    let msg = resp.encode_message()?;
    stream.write_all(&msg.encode()).await
}

/// Respond to an indirect connection request by connecting to the peer and
/// sending `PierceFireWall` with the server-provided token. The relayed
/// connection then serves the role named by `resp.conn_type`: peer messages
/// (`P`) or a file transfer (`F`, where we are the downloader and the uploader
/// streams after our `FileOffset`). Dispatching on the type matters: parsing
/// an `F` relay as a `P` connection reads the uploader's bare 4-byte
/// `FileTransferInit` token as a bogus length prefix and silently strands the
/// transfer until the uploader gives up.
fn pierce_firewall(inner: &Arc<NativeInner>, resp: proto::ConnectToPeerResponse) {
    let inner = inner.clone();
    tokio::spawn(async move {
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(resp.ip)),
            resp.port as u16,
        );
        let mut stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    username = %resp.username,
                    conn_type = %resp.conn_type,
                    token = resp.token,
                    error = %e,
                    "soulseek: PierceFireWall connect failed"
                );
                return;
            }
        };
        if let Err(e) = stream
            .write_all(&PierceFireWall { token: resp.token }.encode())
            .await
        {
            tracing::warn!(
                username = %resp.username,
                conn_type = %resp.conn_type,
                token = resp.token,
                error = %e,
                "soulseek: PierceFireWall write failed"
            );
            return;
        }
        tracing::info!(
            username = %resp.username,
            conn_type = %resp.conn_type,
            token = resp.token,
            "soulseek: PierceFireWall relay established"
        );
        match resp.conn_type.as_str() {
            conn_type::FILE => {
                if let Err(e) = handle_file_connection(stream, inner).await {
                    tracing::warn!(
                        username = %resp.username,
                        error = %e,
                        "soulseek: relayed F connection failed"
                    );
                }
            }
            _ => {
                let _ = handle_peer_messages(stream, inner, Some(resp.username.clone())).await;
            }
        }
    });
}

fn next_token() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Marks a transfer token as actively streaming for its lifetime, so the
/// outbound `F` path and an inbound/relayed `F` connection cannot both write
/// the same partial file. Removing the token on drop keeps failed attempts
/// from blocking later delivery paths.
struct ActiveGuard {
    shared: Arc<Mutex<Shared>>,
    token: u32,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.shared
            .lock()
            .unwrap()
            .active_transfers
            .remove(&self.token);
    }
}

/// Try to claim exclusive write access for a transfer token.
fn claim_transfer(shared: &Arc<Mutex<Shared>>, token: u32) -> Option<ActiveGuard> {
    let mut guard = shared.lock().unwrap();
    if guard.active_transfers.contains(&token) {
        return None;
    }
    guard.active_transfers.insert(token);
    Some(ActiveGuard {
        shared: Arc::clone(shared),
        token,
    })
}

/// Handle a distributed search request: forward the raw message to every child
/// peer over a fresh `D` connection, and answer it from our own share index.
///
/// A distributed search that loops back to a token we initiated is already
/// tracked in `shared.searches`; we never respond to our own searches.
fn handle_distributed_search(inner: &Arc<NativeInner>, search: proto::DistribSearch) {
    let is_own = inner
        .shared
        .lock()
        .unwrap()
        .searches
        .contains_key(&search.token);

    if !is_own && search.username != inner.config.username {
        let inner = inner.clone();
        let (user, token, query) = (search.username.clone(), search.token, search.query.clone());
        tokio::spawn(async move {
            answer_query(&inner, &user, token, &query).await;
        });
    }

    let children = inner.shared.lock().unwrap().children.clone();
    let inner = inner.clone();
    for child in children {
        let inner = inner.clone();
        let search = search.clone();
        tokio::spawn(async move {
            forward_distributed_search(inner, child, search).await;
        });
    }
}

/// Send the distributed `D` handshake on an outbound connection: `PeerInit`
/// (type D) followed by our branch level/root when known.
async fn send_distributed_handshake(
    stream: &mut TcpStream,
    inner: &Arc<NativeInner>,
) -> std::io::Result<()> {
    stream
        .write_all(
            &PeerInit {
                username: inner.config.username.clone(),
                conn_type: conn_type::DISTRIBUTED.to_string(),
                token: 0,
            }
            .encode(),
        )
        .await?;
    let (level, root) = {
        let shared = inner.shared.lock().unwrap();
        (shared.branch_level, shared.branch_root.clone())
    };
    if let Some(level) = level {
        stream
            .write_all(
                &proto::DistribBranchLevel {
                    level: level as i32,
                }
                .encode(),
            )
            .await?;
    }
    if let Some(root) = root {
        stream
            .write_all(&proto::DistribBranchRoot { root }.encode())
            .await?;
    }
    Ok(())
}

/// Read and dispatch `uint8`-code distributed messages on an established `D`
/// connection until it closes. Records branch level/root, handles distributed
/// searches (relaying them onward), and ignores other codes.
async fn distributed_read_loop(
    mut stream: TcpStream,
    inner: Arc<NativeInner>,
    register_as_child: bool,
) -> Result<(), std::io::Error> {
    if register_as_child {
        if let Ok(peer) = stream.peer_addr() {
            let mut shared = inner.shared.lock().unwrap();
            if !shared.children.contains(&peer) {
                shared.children.push(peer);
            }
        }
    }
    loop {
        let (code_byte, payload) = read_u8_message(&mut stream).await?;
        let framed = wire::encode_u8_frame(code_byte, &payload);
        match code_byte {
            code::DISTRIB_BRANCH_LEVEL => {
                if let Ok(level) = proto::DistribBranchLevel::decode(&framed) {
                    inner.shared.lock().unwrap().branch_level = Some(level.level as u32);
                }
            }
            code::DISTRIB_BRANCH_ROOT => {
                if let Ok(root) = proto::DistribBranchRoot::decode(&framed) {
                    inner.shared.lock().unwrap().branch_root = Some(root.root);
                }
            }
            code::DISTRIB_SEARCH => {
                if let Ok(search) = proto::DistribSearch::decode(&framed) {
                    handle_distributed_search(&inner, search);
                }
            }
            _ => {}
        }
    }
}

/// Handle an inbound distributed (`D`) connection after `PeerInit` has been
/// consumed: register the peer as a child and process its distributed messages.
async fn handle_distributed_connection(
    stream: TcpStream,
    inner: Arc<NativeInner>,
) -> Result<(), std::io::Error> {
    distributed_read_loop(stream, inner, true).await
}

/// Connect to a potential parent over a `D` connection: send `PeerInit`
/// (type D) and our branch level/root if known, then read the parent's
/// distributed messages. Best-effort; failures are ignored.
async fn connect_to_parent(inner: Arc<NativeInner>, addr: SocketAddr) {
    let Ok(mut stream) = TcpStream::connect(addr).await else {
        return;
    };
    if send_distributed_handshake(&mut stream, &inner)
        .await
        .is_err()
    {
        return;
    }
    let _ = distributed_read_loop(stream, inner, false).await;
}

/// Best-effort forward a distributed search to a single child: connect, send
/// the distributed handshake, then the re-encoded search frame.
async fn forward_distributed_search(
    inner: Arc<NativeInner>,
    child: SocketAddr,
    search: proto::DistribSearch,
) {
    let Ok(mut stream) = TcpStream::connect(child).await else {
        return;
    };
    if send_distributed_handshake(&mut stream, &inner)
        .await
        .is_err()
    {
        return;
    }
    let _ = stream.write_all(&search.encode()).await;
}

fn normalize_result(r: &SearchResultEntry) -> SearchResult {
    SearchResult {
        username: r.username.clone(),
        filename: r.filename.clone(),
        size: Some(r.size),
        extension: if r.extension.is_empty() {
            None
        } else {
            Some(r.extension.to_lowercase())
        },
        bitrate: r.bitrate,
        duration: r.duration,
        queue_length: Some(r.queue_length),
        free_upload_slots: Some(r.slot_free),
        upload_speed: Some(r.avg_speed as u64),
        token: r.token,
    }
}

fn result_health(r: &SearchResult) -> (std::cmp::Reverse<u8>, std::cmp::Reverse<u64>, u32) {
    let slots = match r.free_upload_slots {
        Some(true) => 2,
        None => 1,
        Some(false) => 0,
    };
    (
        std::cmp::Reverse(slots),
        std::cmp::Reverse(r.upload_speed.unwrap_or(0)),
        r.queue_length.unwrap_or(u32::MAX),
    )
}

/// Read one framed `uint32`-code message from a `TcpStream`.
async fn read_message(stream: &mut TcpStream) -> Result<Message, std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let body_len = u32::from_le_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    let mut framed = Vec::with_capacity(4 + body_len);
    framed.extend_from_slice(&len_buf);
    framed.extend_from_slice(&body);
    Message::decode(&framed).map_err(wire::into_io)
}

/// Read one framed `uint32`-code message from an `OwnedReadHalf`.
async fn read_message_owned(stream: &mut OwnedReadHalf) -> Result<Message, std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let body_len = u32::from_le_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    let mut framed = Vec::with_capacity(4 + body_len);
    framed.extend_from_slice(&len_buf);
    framed.extend_from_slice(&body);
    Message::decode(&framed).map_err(wire::into_io)
}

/// Read one `uint8`-code framed message, returning `(code, payload)`.
async fn read_u8_message(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let body_len = u32::from_le_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    let mut framed = Vec::with_capacity(4 + body_len);
    framed.extend_from_slice(&len_buf);
    framed.extend_from_slice(&body);
    wire::decode_u8_frame(&framed).map_err(wire::into_io)
}

/// Handle an incoming connection on our listen socket.
async fn handle_incoming(
    mut stream: TcpStream,
    inner: Arc<NativeInner>,
) -> Result<(), std::io::Error> {
    let (code_byte, payload) = match read_u8_message(&mut stream).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "soulseek: inbound connection failed to parse framing (possibly a legacy F connection without PeerInit)"
            );
            return Ok(());
        }
    };
    if code_byte != code::PEER_INIT {
        tracing::warn!(
            code = code_byte,
            "soulseek: inbound connection with non-PeerInit framing dropped"
        );
        return Ok(());
    }
    let init = proto::PeerInit::decode(&crate::wire::encode_u8_frame(code_byte, &payload))
        .map_err(wire::into_io)?;
    tracing::info!(
        conn_type = %init.conn_type,
        "soulseek: inbound connection"
    );

    match init.conn_type.as_str() {
        conn_type::PEER => handle_peer_messages(stream, inner, Some(init.username)).await,
        conn_type::FILE => handle_file_connection(stream, inner).await,
        conn_type::DISTRIBUTED => handle_distributed_connection(stream, inner).await,
        _ => Ok(()),
    }
}

/// Process peer messages on an established `P` connection. `peer_username`
/// is known on outbound connections we initiated (downloads) and `None` on
/// inbound search/transfer connections.
async fn handle_peer_messages(
    mut stream: TcpStream,
    inner: Arc<NativeInner>,
    peer_username: Option<String>,
) -> Result<(), std::io::Error> {
    tracing::info!(
        username = ?peer_username,
        "soulseek: peer message loop started"
    );
    loop {
        let msg = match read_message(&mut stream).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::info!(
                    username = ?peer_username,
                    "soulseek: peer message loop ended (peer closed connection)"
                );
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(
                    username = ?peer_username,
                    error = %e,
                    "soulseek: peer message loop read error"
                );
                return Err(e);
            }
        };
        tracing::debug!(
            username = ?peer_username,
            code = msg.code,
            "soulseek: peer message received"
        );
        match msg.code {
            code::FILE_SEARCH_RESPONSE => {
                if let Ok(resp) = proto::decode_file_search_response_message(&msg) {
                    record_search_response(&inner, resp);
                }
            }
            code::TRANSFER_REQUEST => {
                if let Ok(req) = TransferRequest::decode(&msg) {
                    handle_transfer_request(&mut stream, &inner, req, peer_username.as_deref())
                        .await?;
                }
            }
            code::PLACE_IN_QUEUE_RESPONSE => {
                let _ = PlaceInQueueResponse::decode(&msg);
            }
            code::QUEUE_UPLOAD => {
                if let Ok(filename) = crate::wire::Reader::new(&msg.payload).read_string() {
                    handle_queue_upload(&mut stream, &inner, filename, peer_username.as_deref())
                        .await?;
                }
            }
            code::TRANSFER_RESPONSE => {
                // As the uploader we sent a TransferRequest and receive this.
                // (The downloader side sends TransferResponse; it never parses
                // one on its own connection.)
                if let Ok(tr) = TransferResponse::decode(&msg) {
                    handle_transfer_response_upload(&inner, tr);
                }
            }
            code::PEER_SEARCH_OR_BROWSE => {
                match proto::decode_peer_search_or_browse(&msg.payload) {
                    Ok(Some(search)) => {
                        handle_peer_file_search(&mut stream, &inner, search).await?;
                    }
                    Ok(None) => handle_browse_request(&mut stream, &inner, &msg.payload).await?,
                    Err(_) => {}
                }
            }
            code::PEER_BROWSE_RESPONSE => {
                if let Ok(plain) = decompress_payload(&msg.payload) {
                    if let Ok(resp) = BrowseResponse::decode(&plain) {
                        let token = resp.token;
                        let info = BrowseResultInfo::from(resp);
                        let tx = inner.shared.lock().unwrap().pending_browse.remove(&token);
                        if let Some(tx) = tx {
                            tracing::info!(
                                username = %info.username,
                                folders = info.folders.len(),
                                "soulseek: browse response received"
                            );
                            let _ = tx.send(info);
                        } else {
                            tracing::debug!(token, "soulseek: browse response for unknown token");
                        }
                    }
                }
            }
            code::PEER_FOLDER_CONTENTS_REQUEST => {
                handle_folder_request(&mut stream, &inner, &msg.payload).await?;
            }
            code::PEER_FOLDER_CONTENTS_RESPONSE => {
                if let Ok(plain) = decompress_payload(&msg.payload) {
                    if let Ok(resp) = FolderContentsResponse::decode(&plain) {
                        let token = resp.token;
                        let info = FolderContentsResult::from(resp);
                        let tx = inner.shared.lock().unwrap().pending_folder.remove(&token);
                        if let Some(tx) = tx {
                            let _ = tx.send(info);
                        }
                    }
                }
            }
            code::UPLOAD_FAILED => {
                // The peer refused our queue request (file not found in their
                // index, queue/ratio policy, transfer refused). Fail the
                // matching pending download loudly instead of hanging forever
                // as "queued", and record the refusal for the embedding
                // application (drained via `take_failed_downloads`).
                if let Ok(filename) = crate::wire::Reader::new(&msg.payload).read_string() {
                    let peer = peer_username.as_deref().unwrap_or("").to_string();
                    let outcome = {
                        let mut shared = inner.shared.lock().unwrap();
                        let before = shared.pending.len();
                        shared
                            .pending
                            .retain(|p| !(p.filename == filename && p.username == peer));
                        // Drop dead accepted entries so they stop reporting
                        // progress, but never touch one that is actively
                        // streaming over an `F` connection right now.
                        let mut streaming_token = None;
                        let mut dead_tokens = Vec::new();
                        for (token, d) in shared.downloads.iter() {
                            if d.username == peer
                                && normalized_path(&d.filename) == normalized_path(&filename)
                            {
                                if shared.active_transfers.contains(token) {
                                    streaming_token = Some(*token);
                                } else {
                                    dead_tokens.push(*token);
                                }
                            }
                        }
                        for token in dead_tokens {
                            shared.downloads.remove(&token);
                        }
                        // Record the refusal for the embedding application
                        // (`take_failed_downloads`) unless the file is
                        // mid-stream from another delivery path.
                        if streaming_token.is_none() {
                            shared
                                .failed_downloads
                                .push((peer.clone(), filename.clone()));
                        }
                        (shared.pending.len() != before, streaming_token.is_some())
                    };
                    tracing::warn!(
                        username = ?peer_username,
                        filename = %filename,
                        removed_pending = outcome.0,
                        was_streaming = outcome.1,
                        "soulseek: peer refused download (UploadFailed)"
                    );
                }
            }
            _ => {}
        }
    }
}

fn record_search_response(inner: &Arc<NativeInner>, resp: FileSearchResponse) {
    let mut shared = inner.shared.lock().unwrap();
    let Some(entries) = shared.searches.get_mut(&resp.token) else {
        return;
    };
    for file in resp.files {
        let bitrate = file.bitrate();
        let duration = file.duration();
        let filename = file.filename;
        let extension = file.extension;
        entries.push(SearchResultEntry {
            username: resp.username.clone(),
            filename,
            size: file.size,
            extension,
            bitrate,
            duration,
            slot_free: resp.slot_free,
            avg_speed: resp.avg_speed,
            queue_length: resp.queue_length,
            token: resp.token,
        });
    }
}

/// Normalize a peer path to forward slashes for matching. Search responses
/// often carry backslash paths (Windows clients) while the same client sends
/// `TransferRequest` with forward slashes; never let a separator mismatch
/// strand a pending download forever.
fn normalized_path(s: &str) -> String {
    s.replace('\\', "/")
}

async fn handle_transfer_request(
    stream: &mut TcpStream,
    inner: &Arc<NativeInner>,
    req: TransferRequest,
    peer_username: Option<&str>,
) -> Result<(), std::io::Error> {
    let matched = {
        let mut shared = inner.shared.lock().unwrap();
        let exact = shared.pending.iter().position(|p| {
            p.filename == req.filename
                && match peer_username {
                    Some(u) => p.username == u,
                    None => true,
                }
        });
        let pos = exact.or_else(|| {
            let normalized_req = normalized_path(&req.filename);
            shared.pending.iter().position(|p| {
                normalized_path(&p.filename) == normalized_req
                    && match peer_username {
                        Some(u) => p.username == u,
                        None => true,
                    }
            })
        });
        match pos {
            Some(i) => {
                let pending = shared.pending.remove(i);
                if exact.is_none() {
                    tracing::info!(
                        username = &pending.username,
                        queued = %pending.filename,
                        requested = %req.filename,
                        "soulseek: matched pending download by normalized path (separator mismatch)"
                    );
                }
                let expected = req.file_size.unwrap_or(pending.size);
                shared.downloads.insert(
                    req.token,
                    Download {
                        username: pending.username,
                        filename: pending.filename,
                        size: expected,
                        offset: 0,
                    },
                );
                Some(expected)
            }
            None => {
                tracing::warn!(
                    username = ?peer_username,
                    requested = %req.filename,
                    pending_count = shared.pending.len(),
                    "soulseek: TransferRequest did not match any pending download"
                );
                None
            }
        }
    };

    if let Some(expected) = matched {
        stream
            .write_all(&TransferResponse::encode_accept(req.token, expected).encode())
            .await?;

        // Fallback: also open an `F` connection TO the uploader for peers
        // that expect the downloader to connect (slskd-style). Most uploaders
        // dial the downloader (or relay via ConnectToPeer type F) themselves
        // immediately after the accept, so delay this attempt to give their
        // delivery a chance to claim the transfer first.
        if req.direction == direction::UPLOAD {
            if let Ok(addr) = stream.peer_addr() {
                let inner = inner.clone();
                let token = req.token;
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    if let Err(e) = initiate_f_download(inner, addr, token, expected).await {
                        tracing::debug!(
                            token,
                            error = %e,
                            "soulseek: outbound F fallback ended"
                        );
                    }
                });
            }
        }
    }
    Ok(())
}

/// Open the file connection to an accepting uploader and stream the file to
/// disk. Wire order: `PeerInit(F)` (u8 code framing), the 4-byte
/// `FileTransferInit` token, then the *downloader* sends its 8-byte
/// `FileOffset` (bytes already downloaded; 0 for a fresh transfer) before raw
/// file data is streamed. Per the protocol documentation, `FileOffset` is
/// always sent by the downloader at the start of an `F` connection; a peer
/// that waits for it would otherwise strand the transfer. Some uploaders send
/// their own `FileOffset` first and then wait for ours; absorb that with a
/// short read window so neither variant deadlocks or corrupts the stream.
async fn initiate_f_download(
    inner: Arc<NativeInner>,
    addr: std::net::SocketAddr,
    token: u32,
    expected: u64,
) -> Result<(), std::io::Error> {
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(
            &proto::PeerInit {
                username: inner.config.username.clone(),
                conn_type: conn_type::FILE.to_string(),
                token: 0,
            }
            .encode(),
        )
        .await?;
    stream
        .write_all(&proto::FileTransferInit { token }.encode())
        .await?;

    // Only one delivery path may write this transfer; if the uploader is
    // already delivering via a relayed/inbound `F` connection, abort quietly.
    let Some(_active) = claim_transfer(&inner.shared, token) else {
        tracing::debug!(
            token,
            "soulseek: outbound F aborted; transfer already streaming"
        );
        return Ok(());
    };

    // Absorb a gratuitous uploader `FileOffset` if one arrives before we send
    // ours (some peers pre-announce it and then wait for our declaration).
    {
        let mut offset_buf = [0u8; 8];
        match tokio::time::timeout(
            std::time::Duration::from_millis(150),
            stream.read_exact(&mut offset_buf),
        )
        .await
        {
            Ok(Ok(_)) => {
                tracing::debug!(
                    token,
                    peer_offset = u64::from_le_bytes(offset_buf),
                    "soulseek: F uploader announced FileOffset before ours"
                );
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    token,
                    error = %e,
                    "soulseek: uploader closed outbound F (likely dials the downloader itself)"
                );
                return Err(e);
            }
            Err(_) => {}
        }
    }
    // v1 has no resume; declare zero unless a partial local file exists.
    let offset = 0u64;
    stream
        .write_all(&proto::FileOffset { offset }.encode())
        .await?;

    let (filename, dest_dir, dest) = {
        let shared = inner.shared.lock().unwrap();
        let Some(d) = shared.downloads.get(&token) else {
            tracing::warn!(token, "soulseek: F connection for unknown download token");
            return Ok(());
        };
        if shared.cancelled.contains(&d.filename) {
            return Ok(());
        }
        let name = d.filename.clone();
        let dir = std::path::Path::new(&inner.config.download_dir).to_path_buf();
        let basename = std::path::Path::new(&name)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "download.bin".to_string());
        let dest = dir.join(basename);
        (name, dir, dest)
    };
    std::fs::create_dir_all(&dest_dir).ok();
    tracing::info!(token, offset, filename = %filename, "soulseek: F download initiated (we connect)");

    let mut out = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&dest)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    if offset > 0 {
        out.seek(std::io::SeekFrom::Start(offset)).await?;
    }

    let mut total = offset;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if inner.shared.lock().unwrap().cancelled.contains(&filename) {
            break;
        }
        let n = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        out.write_all(&buf[..n]).await?;
        total += n as u64;
        if let Some(dl) = inner.shared.lock().unwrap().downloads.get_mut(&token) {
            dl.offset = total;
        }
        if expected > 0 && total >= expected {
            break;
        }
    }
    out.flush().await?;
    tracing::info!(
        filename = %filename,
        bytes = total,
        expected = %expected,
        complete = expected > 0 && total >= expected,
        "soulseek: F download connection closed"
    );
    Ok(())
}

/// Dispatch an `F` connection by transfer token: token in `downloads` means we
/// are receiving (existing behavior); otherwise it must be an upload we are
/// serving. The 4-byte `FileTransferInit` is read here for both modes.
async fn handle_file_connection(
    mut stream: TcpStream,
    inner: Arc<NativeInner>,
) -> Result<(), std::io::Error> {
    let mut token_buf = [0u8; 4];
    stream.read_exact(&mut token_buf).await?;
    let init = FileTransferInit::decode(&token_buf).map_err(wire::into_io)?;
    tracing::info!(token = init.token, "soulseek: F connection opened");

    let is_download = {
        inner
            .shared
            .lock()
            .unwrap()
            .downloads
            .contains_key(&init.token)
    };
    if is_download {
        serve_download_f(stream, inner, init.token).await
    } else {
        serve_upload_f(stream, inner, init.token).await
    }
}

/// Uploader side of an `F` connection: read the downloader's 8-byte resume
/// offset, then stream our local file from that offset until complete,
/// cancelled, or EOF. Completing or cancelling frees a slot and promotes the
/// next queued upload.
async fn serve_upload_f(
    mut stream: TcpStream,
    inner: Arc<NativeInner>,
    token: u32,
) -> Result<(), std::io::Error> {
    let mut offset_buf = [0u8; 8];
    stream.read_exact(&mut offset_buf).await?;
    let dl_offset = u64::from_le_bytes(offset_buf);

    let upload = {
        let shared = inner.shared.lock().unwrap();
        shared.uploads.get(&token).cloned()
    };
    let Some(upload) = upload else {
        tracing::warn!(
            token,
            "soulseek: F connection for unknown/expired upload token"
        );
        return Ok(());
    };

    let Some(local_path) = upload.local_path.to_str().map(|s| s.to_string()) else {
        return Ok(());
    };
    let mut file = match tokio::fs::File::open(&local_path).await {
        Ok(f) => f,
        Err(e) => {
            // File vanished since indexing: fail this offer and free slot.
            inner.shared.lock().unwrap().uploads.remove(&token);
            try_promote_uploads(&inner);
            tracing::warn!(
                token,
                filename = %upload.virtual_path,
                error = %e,
                "soulseek: shared file unavailable; upload dropped"
            );
            return Ok(());
        }
    };
    let size = upload.size;
    if size > 0 && dl_offset >= size {
        // Nothing left to send; treat as complete.
        finish_upload(&inner, token);
        return Ok(());
    }
    if dl_offset > 0 {
        file.seek(std::io::SeekFrom::Start(dl_offset)).await?;
    }
    tracing::info!(
        token,
        username = %upload.username,
        filename = %upload.virtual_path,
        offset = dl_offset,
        "soulseek: streaming upload"
    );

    let mut sent = dl_offset;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // A removed entry means cancellation.
        if !inner.shared.lock().unwrap().uploads.contains_key(&token) {
            break;
        }
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        stream.write_all(&buf[..n]).await?;
        sent += n as u64;
        {
            let mut shared = inner.shared.lock().unwrap();
            if let Some(u) = shared.uploads.get_mut(&token) {
                u.offset = sent;
                u.since = std::time::Instant::now();
            }
        }
        if size > 0 && sent >= size {
            break;
        }
    }
    stream.flush().await?;

    let complete = size > 0 && sent >= size;
    tracing::info!(
        filename = %upload.virtual_path,
        bytes = sent,
        expected = size,
        complete,
        "soulseek: upload F connection closed"
    );
    if complete {
        finish_upload(&inner, token);
    } else {
        // Incomplete: leave the entry so the downloader may reconnect with an
        // offset; the stale sweep frees the slot if they never come back.
    }
    Ok(())
}

/// Mark one upload finished: free its slot and promote queued uploads.
fn finish_upload(inner: &Arc<NativeInner>, token: u32) {
    let removed = inner.shared.lock().unwrap().uploads.remove(&token);
    if let Some(u) = removed {
        tracing::info!(
            username = %u.username,
            filename = %u.virtual_path,
            "soulseek: upload complete"
        );
    }
    try_promote_uploads(inner);
}

/// Downloader side of an `F` connection (we are receiving the file).
async fn serve_download_f(
    mut stream: TcpStream,
    inner: Arc<NativeInner>,
    token: u32,
) -> Result<(), std::io::Error> {
    let (filename, expected_size, offset) = {
        let shared = inner.shared.lock().unwrap();
        match shared.downloads.get(&token) {
            Some(d) => {
                if shared.cancelled.contains(&d.filename) {
                    return Ok(());
                }
                (d.filename.clone(), d.size, d.offset)
            }
            None => {
                tracing::warn!(
                    token = token,
                    "soulseek: F connection for unknown transfer token"
                );
                return Ok(());
            }
        }
    };

    // Only one delivery path may write this transfer; the outbound `F`
    // fallback aborts when we win the claim here.
    let Some(_active) = claim_transfer(&inner.shared, token) else {
        tracing::debug!(
            token = token,
            "soulseek: duplicate F delivery for active transfer ignored"
        );
        return Ok(());
    };

    stream
        .write_all(&proto::FileOffset { offset }.encode())
        .await?;

    let dest_dir = std::path::Path::new(&inner.config.download_dir);
    std::fs::create_dir_all(dest_dir).ok();
    let file_name = std::path::Path::new(&filename)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download.bin".to_string());
    let dest = dest_dir.join(file_name);
    let mut out = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&dest)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    out.seek(std::io::SeekFrom::Start(offset)).await?;

    let mut total = offset;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // Stop immediately if this download was cancelled after the file was
        // opened.
        if inner.shared.lock().unwrap().cancelled.contains(&filename) {
            break;
        }
        let n = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };
        out.write_all(&buf[..n]).await?;
        total += n as u64;
        if let Some(dl) = inner.shared.lock().unwrap().downloads.get_mut(&token) {
            dl.offset = total;
        }
        // Stop once the advertised size is reached (the downloader is
        // responsible for closing the connection on completion). An unknown
        // size (0) means "read until EOF".
        if expected_size > 0 && total >= expected_size {
            break;
        }
    }
    out.flush().await?;
    tracing::info!(
        filename = %filename,
        bytes = total,
        expected = %expected_size,
        complete = expected_size > 0 && total >= expected_size,
        "soulseek: F connection closed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::direction;
    use std::net::Ipv4Addr;

    /// A mock server that answers login, `FileSearch` (no response), and
    /// `GetPeerAddress` (returning a fixed peer address).
    struct MockServer {
        addr: SocketAddr,
        shutdown: Option<oneshot::Sender<()>>,
    }

    impl MockServer {
        async fn spawn(peer_addr: SocketAddr) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = oneshot::channel();
            tokio::spawn(async move {
                let mut shutdown = rx;
                loop {
                    tokio::select! {
                        _ = &mut shutdown => return,
                        accepted = listener.accept() => {
                            let Ok((mut stream, _)) = accepted else { continue };
                            tokio::spawn(async move {
                                let _ = handle_server_conn(&mut stream, peer_addr).await;
                            });
                        }
                    }
                }
            });
            Self {
                addr,
                shutdown: Some(tx),
            }
        }

        async fn stop(mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    async fn handle_server_conn(
        stream: &mut TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        // Login.
        let login = read_message(stream).await?;
        assert_eq!(login.code, code::LOGIN);
        stream
            .write_all(&crate::wire::LoginResponse::encode_success("hi", 0, "hash", false).encode())
            .await?;

        loop {
            let msg = match read_message(stream).await {
                Ok(m) => m,
                Err(_) => return Ok(()),
            };
            match msg.code {
                code::FILE_SEARCH | code::SET_LISTEN_PORT => {}
                code::SHARED_FOLDERS_FILES => {}
                code::GET_PEER_ADDRESS => {
                    let mut r = crate::wire::Reader::new(&msg.payload);
                    let username = r.read_string().unwrap();
                    let ip = match peer_addr.ip() {
                        std::net::IpAddr::V4(v4) => u32::from(v4),
                        _ => u32::from(Ipv4Addr::LOCALHOST),
                    };
                    let mut w = crate::wire::Writer::new();
                    w.write_string(&username);
                    w.write_u32(ip);
                    w.write_u32(peer_addr.port() as u32);
                    w.write_u32(0); // obfuscation type
                    w.write_u16(0); // obfuscated port
                    stream
                        .write_all(&Message::new(code::GET_PEER_ADDRESS, w.into_inner()).encode())
                        .await?;
                }
                code::GET_USER_STATS => {
                    let username = {
                        let mut r = crate::wire::Reader::new(&msg.payload);
                        r.read_string().unwrap()
                    };
                    stream
                        .write_all(
                            &UserStats {
                                username,
                                avg_speed: 12345,
                                num_downloads: 3,
                                num_files: 42,
                                num_dirs: 7,
                            }
                            .encode()
                            .encode(),
                        )
                        .await?;
                }
                code::SERVER_PING => {}
                _ => {}
            }
        }
    }

    /// A mock peer that answers a search, then serves a download: accepts a `P`
    /// connection, sends a `TransferRequest`, reads the accept, and then serves
    /// the file data over the `F` connection the *downloader* (client) opens to
    /// it — the modern transfer direction.
    struct MockPeer {
        listen: SocketAddr,
        shutdown: Option<oneshot::Sender<()>>,
    }

    impl MockPeer {
        async fn spawn() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listen = listener.local_addr().unwrap();
            let files: Arc<Mutex<HashMap<u32, Vec<u8>>>> = Arc::default();
            let (tx, rx) = oneshot::channel();
            tokio::spawn(async move {
                let mut shutdown = rx;
                loop {
                    tokio::select! {
                        _ = &mut shutdown => return,
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else { continue };
                            let files = files.clone();
                            tokio::spawn(async move {
                                let _ = serve_peer_connection(stream, files).await;
                            });
                        }
                    }
                }
            });
            Self {
                listen,
                shutdown: Some(tx),
            }
        }

        async fn stop(mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        /// Send a `FileSearchResponse` to the client's listen socket.
        async fn send_search_response(client_addr: SocketAddr, token: u32) {
            let mut stream = TcpStream::connect(client_addr).await.unwrap();
            let init = PeerInit {
                username: "alice".to_string(),
                conn_type: conn_type::PEER.to_string(),
                token: 0,
            };
            stream.write_all(&init.encode()).await.unwrap();

            // Plain payload then zlib compress.
            let mut w = crate::wire::Writer::new();
            w.write_string("alice");
            w.write_u32(token);
            w.write_u32(1); // one file
            w.write_u8(1);
            w.write_string("music/song.flac");
            w.write_u64(12);
            w.write_string("flac");
            w.write_u32(2);
            w.write_u32(0);
            w.write_u32(950);
            w.write_u32(1);
            w.write_u32(240);
            w.write_bool(true);
            w.write_u32(500);
            w.write_u32(0);
            w.write_u32(0);
            w.write_u32(0);
            let plain = w.into_inner();
            let mut enc =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut enc, &plain).unwrap();
            let compressed = enc.finish().unwrap();
            stream
                .write_all(&Message::new(code::FILE_SEARCH_RESPONSE, compressed).encode())
                .await
                .unwrap();
        }
    }

    /// Dispatch an inbound connection by its `PeerInit` type: `P` connections
    /// serve the queue/transfer-request round trip; `F` connections serve the
    /// file data once the downloader opens them.
    async fn serve_peer_connection(
        mut stream: TcpStream,
        files: Arc<Mutex<HashMap<u32, Vec<u8>>>>,
    ) -> Result<(), std::io::Error> {
        let (c, payload) = read_u8_message(&mut stream).await?;
        assert_eq!(c, code::PEER_INIT);
        let init = PeerInit::decode(&crate::wire::encode_u8_frame(c, &payload)).unwrap();
        if init.conn_type == conn_type::FILE {
            return serve_uploader_f(&mut stream, files).await;
        }
        assert_eq!(init.conn_type, conn_type::PEER);

        // QueueUpload (u32 code).
        let msg = read_message(&mut stream).await?;
        assert_eq!(msg.code, code::QUEUE_UPLOAD);
        let mut r = crate::wire::Reader::new(&msg.payload);
        let filename = r.read_string().unwrap();

        // TransferRequest (direction=UPLOAD, token=7, size=12).
        let mut w = crate::wire::Writer::new();
        w.write_u32(direction::UPLOAD);
        w.write_u32(7);
        w.write_string(&filename);
        w.write_u64(12);
        stream
            .write_all(&Message::new(code::TRANSFER_REQUEST, w.into_inner()).encode())
            .await?;

        // TransferResponse (accept).
        let resp = read_message(&mut stream).await?;
        assert_eq!(resp.code, code::TRANSFER_RESPONSE);
        let tr = TransferResponse::decode(&resp).unwrap();
        assert!(tr.allowed);
        assert_eq!(tr.file_size, Some(12));

        files.lock().unwrap().insert(7, b"hello world!".to_vec());
        Ok(())
    }

    /// Uploader side of a downloader-initiated `F` connection: read the 4-byte
    /// `FileTransferInit` token and the downloader's 8-byte `FileOffset`, then
    /// stream the file payload. The downloader closes once all bytes arrived.
    async fn serve_uploader_f(
        stream: &mut TcpStream,
        files: Arc<Mutex<HashMap<u32, Vec<u8>>>>,
    ) -> Result<(), std::io::Error> {
        let mut token_buf = [0u8; 4];
        stream.read_exact(&mut token_buf).await?;
        let token = u32::from_le_bytes(token_buf);

        // The downloader declares its resume offset (0 for a fresh transfer).
        let mut offset_buf = [0u8; 8];
        stream.read_exact(&mut offset_buf).await?;
        assert_eq!(u64::from_le_bytes(offset_buf), 0);

        let data = files
            .lock()
            .unwrap()
            .get(&token)
            .cloned()
            .unwrap_or_default();
        stream.write_all(&data).await?;
        // Keep the connection open; the downloader closes on completion.
        let mut buf = [0u8; 16];
        while let Ok(n) = stream.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Regression test for NAT'd downloaders: an uploader that cannot reach
    /// our listen socket relays the file connection via
    /// `ConnectToPeer(conn_type = "F")`. After we `PierceFireWall` to them,
    /// they speak the file protocol on that same socket: bare 4-byte
    /// `FileTransferInit` token, our 8-byte `FileOffset`, then the payload.
    /// Parsing such a relay as a `P` connection strands the transfer.
    #[tokio::test]
    async fn pierce_firewall_f_relay_serves_file() {
        let tmp = std::env::temp_dir().join(format!("rustsoseek-relay-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        // Stand-in for the remote uploader's listen socket.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let uploader_addr = listener.local_addr().unwrap();
        let uploader = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // The piercing side sends only PierceFireWall (u8 frame).
            let (c, payload) = read_u8_message(&mut stream).await.unwrap();
            assert_eq!(c, code::PIERCE_FIREWALL);
            let mut r = crate::wire::Reader::new(&payload);
            assert_eq!(r.read_u32().unwrap(), 4242);

            // Uploader speaks F directly: token then read our offset.
            stream
                .write_all(&FileTransferInit { token: 7 }.encode())
                .await
                .unwrap();
            let mut off_buf = [0u8; 8];
            stream.read_exact(&mut off_buf).await.unwrap();
            assert_eq!(u64::from_le_bytes(off_buf), 0);
            stream.write_all(b"hello world!").await.unwrap();
            // The downloader closes on completion.
            let mut buf = [0u8; 16];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        });

        let server = MockServer::spawn("127.0.0.1:1".parse().unwrap()).await;
        let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_port = listen.local_addr().unwrap().port();
        drop(listen);

        let client = NativeClient::connect(NativeConfig {
            server_addr: server.addr.to_string(),
            username: "me".to_string(),
            password: "pw".to_string(),
            listen_port,
            download_dir: tmp.to_string_lossy().into_owned(),
            ..NativeConfig::default()
        })
        .await
        .expect("connect");

        // The accepted transfer is already registered under token 7.
        client.inner.shared.lock().unwrap().downloads.insert(
            7,
            Download {
                username: "alice".to_string(),
                filename: "music/song.flac".to_string(),
                size: 12,
                offset: 0,
            },
        );

        let ip = match uploader_addr.ip() {
            std::net::IpAddr::V4(v4) => u32::from(v4),
            _ => u32::from(Ipv4Addr::LOCALHOST),
        };
        pierce_firewall(
            &client.inner,
            proto::ConnectToPeerResponse {
                username: "alice".to_string(),
                conn_type: conn_type::FILE.to_string(),
                ip,
                port: uploader_addr.port() as u32,
                token: 4242,
                privileged: false,
                obfuscation_type: 0,
                obfuscated_port: 0,
            },
        );

        tokio::time::timeout(std::time::Duration::from_secs(5), uploader)
            .await
            .expect("uploader did not finish in time")
            .expect("uploader task failed");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let written = std::fs::read(tmp.join("song.flac")).expect("file written");
        assert_eq!(written, b"hello world!");

        server.stop().await;
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[tokio::test]
    async fn search_and_download_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("rustsoseek-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let peer = MockPeer::spawn().await;
        let server = MockServer::spawn(peer.listen).await;

        // The client binds its own listen socket on a random port.
        let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_port = listen.local_addr().unwrap().port();
        drop(listen);

        let client = NativeClient::connect(NativeConfig {
            server_addr: server.addr.to_string(),
            username: "me".to_string(),
            password: "pw".to_string(),
            listen_port,
            download_dir: tmp.to_string_lossy().into_owned(),
            ..NativeConfig::default()
        })
        .await
        .expect("connect");

        // Search: start a search, then have the mock peer respond.
        let token = client.start_search("flac").await.expect("search");
        let client_addr = client.listen_addr();
        let connect_addr = SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_addr.port(),
        );
        MockPeer::send_search_response(connect_addr, token).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let results = client.results(token, 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username, "alice");
        assert_eq!(results[0].filename, "music/song.flac");
        assert_eq!(results[0].extension.as_deref(), Some("flac"));
        assert_eq!(results[0].size, Some(12));
        assert_eq!(results[0].bitrate, Some(950));

        // Download: queue from the peer. The client opens the `F` connection
        // to the uploader itself and receives the streamed file.
        client
            .download("alice", "music/song.flac", 12)
            .await
            .expect("download");

        // The client declares its FileOffset then streams 12 bytes over the
        // downloader-initiated F connection.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let written = std::fs::read(tmp.join("song.flac")).expect("file written");
        assert_eq!(written, b"hello world!");

        peer.stop().await;
        server.stop().await;
        std::fs::remove_dir_all(&tmp).ok();
    }

    fn possible_parents_message(parent_addr: SocketAddr) -> Message {
        let mut w = crate::wire::Writer::new();
        w.write_u32(1);
        w.write_string("parentuser");
        let ip = match parent_addr.ip() {
            std::net::IpAddr::V4(v4) => u32::from(v4),
            _ => u32::from(Ipv4Addr::LOCALHOST),
        };
        w.write_u32(ip);
        w.write_u32(parent_addr.port() as u32);
        Message::new(code::POSSIBLE_PARENTS, w.into_inner())
    }

    /// Mock server that asserts the full login + listen-port + distributed
    /// handshake, then pushes `ExcludedSearchPhrases` and `PossibleParents`.
    async fn handle_distributed_server_conn(
        stream: &mut TcpStream,
        parent_addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let login = read_message(stream).await?;
        assert_eq!(login.code, code::LOGIN);
        stream
            .write_all(&crate::wire::LoginResponse::encode_success("hi", 0, "hash", false).encode())
            .await?;

        let msg = read_message(stream).await?;
        assert_eq!(msg.code, code::SET_LISTEN_PORT);
        let msg = read_message(stream).await?;
        assert_eq!(msg.code, code::HAVE_NO_PARENT);
        let mut r = crate::wire::Reader::new(&msg.payload);
        assert!(r.read_bool().unwrap());
        let msg = read_message(stream).await?;
        assert_eq!(msg.code, code::ACCEPT_CHILDREN);
        let mut r = crate::wire::Reader::new(&msg.payload);
        assert!(r.read_bool().unwrap());

        let mut w = crate::wire::Writer::new();
        w.write_u32(1);
        w.write_string("bad phrase");
        stream
            .write_all(&Message::new(code::EXCLUDED_SEARCH_PHRASES, w.into_inner()).encode())
            .await?;

        stream
            .write_all(&possible_parents_message(parent_addr).encode())
            .await?;

        // Keep the connection open so the client can process the messages above.
        loop {
            if read_message(stream).await.is_err() {
                return Ok(());
            }
        }
    }

    #[tokio::test]
    async fn distributed_network_setup_stores_state() {
        let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_port = listen.local_addr().unwrap().port();
        drop(listen);

        // Nothing listens here; the outbound D connection attempt fails and is
        // ignored, which is the expected offline behavior.
        let parent_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut shutdown = rx;
            loop {
                tokio::select! {
                    _ = &mut shutdown => return,
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { continue };
                        tokio::spawn(async move {
                            let _ = handle_distributed_server_conn(&mut stream, parent_addr).await;
                        });
                    }
                }
            }
        });

        let client = NativeClient::connect(NativeConfig {
            server_addr: server_addr.to_string(),
            username: "me".to_string(),
            password: "pw".to_string(),
            listen_port,
            download_dir: std::env::temp_dir().to_string_lossy().into_owned(),
            ..NativeConfig::default()
        })
        .await
        .expect("connect");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        {
            let shared = client.inner.shared.lock().unwrap();
            assert_eq!(shared.excluded_phrases, vec!["bad phrase"]);
            assert_eq!(shared.parent, Some(parent_addr));
        }

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn handle_distributed_search_forwards_to_children() {
        let child_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let child_addr = child_listener.local_addr().unwrap();

        let listen = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_port = listen.local_addr().unwrap().port();
        drop(listen);

        let server = MockServer::spawn("127.0.0.1:1".parse().unwrap()).await;
        let client = NativeClient::connect(NativeConfig {
            server_addr: server.addr.to_string(),
            username: "me".to_string(),
            password: "pw".to_string(),
            listen_port,
            download_dir: std::env::temp_dir().to_string_lossy().into_owned(),
            ..NativeConfig::default()
        })
        .await
        .expect("connect");

        client
            .inner
            .shared
            .lock()
            .unwrap()
            .children
            .push(child_addr);

        let child_task = tokio::spawn(async move {
            let (mut stream, _) = child_listener.accept().await.unwrap();
            let (c, _p) = read_u8_message(&mut stream).await.unwrap();
            assert_eq!(c, code::PEER_INIT);
            let (c, p) = read_u8_message(&mut stream).await.unwrap();
            assert_eq!(c, code::DISTRIB_SEARCH);
            let framed = crate::wire::encode_u8_frame(c, &p);
            let search = proto::DistribSearch::decode(&framed).unwrap();
            assert_eq!(search.token, 7);
            assert_eq!(search.query, "flac");
        });

        let search = proto::DistribSearch {
            identifier: 49,
            username: "rootuser".to_string(),
            token: 7,
            query: "flac".to_string(),
        };
        handle_distributed_search(&client.inner, search);

        tokio::time::timeout(std::time::Duration::from_secs(2), child_task)
            .await
            .expect("child did not receive the search in time")
            .expect("child task failed");

        server.stop().await;
    }

    // ------------------------------------------------------------------
    // Sharing-core integration tests (uploads, queues, browse, stats).
    // ------------------------------------------------------------------

    /// Create a temp share tree whose top directory is `Music`; returns the
    /// share root and the peer-visible virtual path of one file.
    fn make_share(tag: &str) -> (std::path::PathBuf, String) {
        let base = std::env::temp_dir().join(format!("rss-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(base.join("Music").join("MusicStore")).unwrap();
        std::fs::write(
            base.join("Music").join("MusicStore").join("song.txt"),
            b"hello data!",
        )
        .unwrap();
        (base.join("Music"), "Music/MusicStore/song.txt".to_string())
    }

    fn client_config(server: &SocketAddr, root: &std::path::Path, port: u16) -> NativeConfig {
        NativeConfig {
            server_addr: server.to_string(),
            username: "me".to_string(),
            password: "pw".to_string(),
            listen_port: port,
            download_dir: std::env::temp_dir().to_string_lossy().into_owned(),
            shared_dirs: vec![root.to_string_lossy().into_owned()],
            ..NativeConfig::default()
        }
    }

    async fn free_listen_port() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    #[tokio::test]
    async fn upload_round_trip_via_queue_transfer_f() {
        let (root, _vpath) = make_share("up");
        let server = MockServer::spawn("127.0.0.1:1".parse().unwrap()).await;
        let listen_port = free_listen_port().await;
        let client = NativeClient::connect(client_config(&server.addr, &root, listen_port))
            .await
            .expect("connect");

        // A raw downloader: queue the file, accept the offer, then dial `F`
        // and pull the bytes.
        let downloader = tokio::spawn(async move {
            let mut s = TcpStream::connect(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
                listen_port,
            ))
            .await
            .unwrap();
            s.write_all(
                &PeerInit {
                    username: "downloader".to_string(),
                    conn_type: conn_type::PEER.to_string(),
                    token: 0,
                }
                .encode(),
            )
            .await
            .unwrap();
            s.write_all(
                &QueueUpload {
                    filename: "Music/MusicStore/song.txt".to_string(),
                }
                .encode()
                .encode(),
            )
            .await
            .unwrap();

            // Expect TransferRequest(direction=UPLOAD).
            let msg = read_message(&mut s).await.unwrap();
            assert_eq!(msg.code, code::TRANSFER_REQUEST);
            let req = TransferRequest::decode(&msg).unwrap();
            assert_eq!(req.direction, direction::UPLOAD);
            assert_eq!(req.file_size, Some(11));

            // Accept.
            s.write_all(
                &TransferResponse::encode_accept(req.token, req.file_size.unwrap()).encode(),
            )
            .await
            .unwrap();

            // Dial the F connection with the same token.
            let mut f = TcpStream::connect(SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
                listen_port,
            ))
            .await
            .unwrap();
            f.write_all(
                &PeerInit {
                    username: "downloader".to_string(),
                    conn_type: conn_type::FILE.to_string(),
                    token: 0,
                }
                .encode(),
            )
            .await
            .unwrap();
            f.write_all(&FileTransferInit { token: req.token }.encode())
                .await
                .unwrap();
            f.write_all(&0u64.to_le_bytes()).await.unwrap(); // FileOffset

            let mut got = Vec::new();
            f.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, b"hello data!");
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), downloader)
            .await
            .expect("downloader did not finish in time")
            .expect("downloader task failed");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            client.upload_status().is_empty(),
            "upload entry should be released after completion"
        );
        assert!(client.take_failed_uploads().is_empty());

        server.stop().await;
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn upload_unknown_path_gets_upload_failed() {
        let (root, _vpath) = make_share("upfail");
        let server = MockServer::spawn("127.0.0.1:1".parse().unwrap()).await;
        let listen_port = free_listen_port().await;
        let _client = NativeClient::connect(client_config(&server.addr, &root, listen_port))
            .await
            .expect("connect");

        let mut s = TcpStream::connect(SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            listen_port,
        ))
        .await
        .unwrap();
        s.write_all(
            &PeerInit {
                username: "downloader".to_string(),
                conn_type: conn_type::PEER.to_string(),
                token: 0,
            }
            .encode(),
        )
        .await
        .unwrap();
        s.write_all(
            &QueueUpload {
                filename: "MusicStore/missing.txt".to_string(),
            }
            .encode()
            .encode(),
        )
        .await
        .unwrap();

        let msg = read_message(&mut s).await.unwrap();
        assert_eq!(msg.code, code::UPLOAD_FAILED);

        server.stop().await;
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn second_requester_is_queued_with_position() {
        let (root, _vpath) = make_share("queue");
        let server = MockServer::spawn("127.0.0.1:1".parse().unwrap()).await;
        let listen_port = free_listen_port().await;
        let client = NativeClient::connect(client_config(&server.addr, &root, listen_port))
            .await
            .expect("connect");
        assert_eq!(client.listen_addr().port(), listen_port);

        let addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), listen_port);

        // First requester: queue, get offer, accept — then hold the slot by
        // never opening an F connection.
        let mut first = TcpStream::connect(addr).await.unwrap();
        first
            .write_all(
                &PeerInit {
                    username: "d1".to_string(),
                    conn_type: conn_type::PEER.to_string(),
                    token: 0,
                }
                .encode(),
            )
            .await
            .unwrap();
        first
            .write_all(
                &QueueUpload {
                    filename: "Music/MusicStore/song.txt".to_string(),
                }
                .encode()
                .encode(),
            )
            .await
            .unwrap();
        let msg = read_message(&mut first).await.unwrap();
        assert_eq!(msg.code, code::TRANSFER_REQUEST);
        let req = TransferRequest::decode(&msg).unwrap();
        first
            .write_all(&TransferResponse::encode_accept(req.token, req.file_size.unwrap()).encode())
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        // Second requester exceeds max_upload_slots=1 -> place in queue 1.
        let mut second = TcpStream::connect(addr).await.unwrap();
        second
            .write_all(
                &PeerInit {
                    username: "d2".to_string(),
                    conn_type: conn_type::PEER.to_string(),
                    token: 0,
                }
                .encode(),
            )
            .await
            .unwrap();
        second
            .write_all(
                &QueueUpload {
                    filename: "Music/MusicStore/song.txt".to_string(),
                }
                .encode()
                .encode(),
            )
            .await
            .unwrap();
        let msg = read_message(&mut second).await.unwrap();
        assert_eq!(msg.code, code::PLACE_IN_QUEUE_RESPONSE);
        let pq = PlaceInQueueResponse::decode(&msg).unwrap();
        assert_eq!(pq.place, 1);

        // Queue is visible via upload_status with offset 0.
        let statuses = client.upload_status();
        assert!(statuses.iter().any(|s| s.offset == 0 && s.size == 11));

        server.stop().await;
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn incoming_distributed_search_answered_from_shares() {
        let (root, vpath) = make_share("distrib");

        // The searcher listens for our dialed P connection and the response.
        let search_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let searcher_addr = search_listener.local_addr().unwrap();
        let searcher = tokio::spawn(async move {
            let (mut stream, _) = search_listener.accept().await.unwrap();
            let (c, payload) = read_u8_message(&mut stream).await.unwrap();
            assert_eq!(c, code::PEER_INIT);
            let init = PeerInit::decode(&crate::wire::encode_u8_frame(c, &payload)).unwrap();
            assert_eq!(init.conn_type, conn_type::PEER);
            let msg = read_message(&mut stream).await.unwrap();
            assert_eq!(msg.code, code::FILE_SEARCH_RESPONSE);
            let mut decoder = flate2::read::ZlibDecoder::new(&msg.payload[..]);
            use std::io::Read;
            let mut plain = Vec::new();
            decoder.read_to_end(&mut plain).unwrap();
            let resp = proto::decode_file_search_response_plain(&plain).unwrap();
            assert_eq!(resp.username, "me");
            assert_eq!(resp.files.len(), 1);
            assert_eq!(
                normalized_path(&resp.files[0].filename),
                normalized_path(&vpath)
            );
        });

        let server = MockServer::spawn(searcher_addr).await;
        let listen_port = free_listen_port().await;
        let client = NativeClient::connect(client_config(&server.addr, &root, listen_port))
            .await
            .expect("connect");

        handle_distributed_search(
            &client.inner,
            proto::DistribSearch {
                identifier: 49,
                username: "searcher".to_string(),
                token: 1234,
                query: "song".to_string(),
            },
        );

        tokio::time::timeout(std::time::Duration::from_secs(5), searcher)
            .await
            .expect("searcher did not finish in time")
            .expect("searcher task failed");

        server.stop().await;
        std::fs::remove_dir_all(&root).ok();
    }

    #[tokio::test]
    async fn user_stats_resolves_from_server() {
        let server = MockServer::spawn("127.0.0.1:1".parse().unwrap()).await;
        let listen_port = free_listen_port().await;
        let tmp = std::env::temp_dir();
        let client = NativeClient::connect(NativeConfig {
            server_addr: server.addr.to_string(),
            username: "me".to_string(),
            password: "pw".to_string(),
            listen_port,
            download_dir: tmp.to_string_lossy().into_owned(),
            ..NativeConfig::default()
        })
        .await
        .expect("connect");

        let info = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.user_stats("alice"),
        )
        .await
        .expect("stats timed out")
        .expect("stats failed");
        assert_eq!(info.username, "alice");
        assert_eq!(info.avg_speed, 12345);
        assert_eq!(info.num_files, 42);
        assert_eq!(info.num_dirs, 7);

        server.stop().await;
    }

    /// A mock peer that answers browse (code 4 token-only) and folder-content
    /// (code 36) requests over a single P connection.
    async fn serve_browsing_peer(mut stream: TcpStream) {
        loop {
            let msg = match read_message(&mut stream).await {
                Ok(m) => m,
                Err(_) => return,
            };
            match msg.code {
                code::PEER_SEARCH_OR_BROWSE => {
                    let mut r = crate::wire::Reader::new(&msg.payload);
                    let token = r.read_u32().unwrap();
                    if !r.is_empty() {
                        continue; // a real file-search request; not under test here
                    }
                    let resp = BrowseResponse {
                        username: "me".to_string(),
                        token,
                        folders: vec![proto::BrowseFolder {
                            name: "music".to_string(),
                            files: vec![proto::SearchFileEntry {
                                filename: "music/song.flac".to_string(),
                                size: 30_000_000,
                                extension: "flac".to_string(),
                                attributes: vec![(0, 950), (1, 240)],
                            }],
                        }],
                    };
                    stream
                        .write_all(&resp.encode_message().unwrap().encode())
                        .await
                        .unwrap();
                }
                code::PEER_FOLDER_CONTENTS_REQUEST => {
                    let mut r = crate::wire::Reader::new(&msg.payload);
                    let token = r.read_u32().unwrap();
                    let dir = r.read_string().unwrap();
                    let resp = FolderContentsResponse {
                        username: "me".to_string(),
                        token,
                        dir: dir.clone(),
                        files: vec![proto::SearchFileEntry {
                            filename: format!("{dir}/t.mp3"),
                            size: 100,
                            extension: "mp3".to_string(),
                            attributes: vec![],
                        }],
                    };
                    stream
                        .write_all(&resp.encode_message().unwrap().encode())
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn browse_user_and_folder_contents_roundtrip() {
        // Browsing peer on a listener.
        let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = peer_listener.accept().await {
                tokio::spawn(serve_browsing_peer(s));
            }
        });

        let server = MockServer::spawn(peer_addr).await;
        let listen_port = free_listen_port().await;
        let tmp = std::env::temp_dir();
        let client = NativeClient::connect(NativeConfig {
            server_addr: server.addr.to_string(),
            username: "me".to_string(),
            password: "pw".to_string(),
            listen_port,
            download_dir: tmp.to_string_lossy().into_owned(),
            ..NativeConfig::default()
        })
        .await
        .expect("connect");

        let tree = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.browse_user("peer"),
        )
        .await
        .expect("browse timed out")
        .expect("browse failed");
        assert_eq!(tree.username, "me");
        assert_eq!(tree.folders.len(), 1);
        assert_eq!(tree.folders[0].name, "music");
        assert_eq!(tree.folders[0].files[0].virtual_path, "music/song.flac");
        assert_eq!(tree.folders[0].files[0].bitrate, Some(950));
        assert_eq!(tree.folders[0].files[0].duration, Some(240));

        let folder = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.folder_contents("peer", "music/album"),
        )
        .await
        .expect("folder timed out")
        .expect("folder failed");
        assert_eq!(folder.dir, "music/album");
        assert_eq!(folder.files.len(), 1);
        assert_eq!(folder.files[0].virtual_path, "music/album/t.mp3");

        server.stop().await;
    }

    /// A mock server that completes login, then holds the connection open
    /// without reading anything until the test tells it to close.
    async fn spawn_deaf_server() -> (SocketAddr, oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (close_tx, close_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(login) = read_message(&mut stream).await else {
                return;
            };
            assert_eq!(login.code, code::LOGIN);
            stream
                .write_all(
                    &crate::wire::LoginResponse::encode_success("hi", 0, "hash", false).encode(),
                )
                .await
                .unwrap();
            let _ = close_rx.await;
            drop(stream);
        });
        (addr, close_tx)
    }

    async fn connect_to_deaf_server(addr: SocketAddr) -> NativeClient {
        let listen_port = free_listen_port().await;
        let tmp = std::env::temp_dir();
        NativeClient::connect(NativeConfig {
            server_addr: addr.to_string(),
            username: "me".to_string(),
            password: "pw".to_string(),
            listen_port,
            download_dir: tmp.to_string_lossy().into_owned(),
            ..NativeConfig::default()
        })
        .await
        .expect("connect")
    }

    /// Once the server connection is gone, socket writes must fail rather than
    /// park the caller, so a search start still returns quickly.
    #[tokio::test]
    async fn dead_server_socket_does_not_park_search_start() {
        let (addr, close) = spawn_deaf_server().await;
        let client = connect_to_deaf_server(addr).await;

        // Server side drops the socket; its peer learns the connection is dead.
        let _ = close.send(());
        tokio::time::sleep(Duration::from_millis(200)).await;

        let outcomes = tokio::time::timeout(Duration::from_secs(5), async {
            let first = client.start_search("one").await;
            let second = client.start_search("two").await;
            let third = client.start_search("three").await;
            (first, second, third)
        })
        .await
        .expect("search start waited past its bound on a dead server socket");

        assert!(
            outcomes.0.is_err() || outcomes.1.is_err() || outcomes.2.is_err(),
            "a dead server socket should surface as an error, got {:?}",
            outcomes
        );
    }

    /// Regression for the reported hang: one stalled server write (half-dead
    /// connection, full send buffer) must not block a later search start. The
    /// mock server logs in and then never reads again, so the client's send
    /// buffer fills and the writer wedges mid-write. Ignored by default
    /// because a real stall costs about `SERVER_SEND_TIMEOUT`; run it with
    /// `cargo test --lib -- --ignored stalled_server_write`.
    #[tokio::test]
    #[ignore = "needs a real socket stall; run with --ignored"]
    async fn stalled_server_write_is_bounded_and_search_start_still_returns() {
        let (addr, close) = spawn_deaf_server().await;
        let client = connect_to_deaf_server(addr).await;

        // Wedge the writer: queue payloads until the queue refuses, which
        // means the writer is stuck inside a socket write.
        let chunk = vec![0u8; 64 * 1024];
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut wedged = false;
        while std::time::Instant::now() < deadline {
            if client.inner.server_try_send(chunk.clone()).is_err() {
                wedged = true;
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(wedged, "could not fill the server socket send buffer");

        // The search start must come back inside its bound, erroring out
        // rather than waiting on the wedged socket.
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            SERVER_SEND_TIMEOUT + Duration::from_secs(5),
            client.start_search("flac"),
        )
        .await
        .expect("start_search waited unboundedly on a stalled server socket");
        let elapsed = started.elapsed();
        println!("stalled start_search returned after {elapsed:?}: {outcome:?}");
        assert!(
            outcome.is_err(),
            "expected the stalled socket to surface as an error, got {outcome:?}"
        );

        let _ = close.send(());
    }
}
