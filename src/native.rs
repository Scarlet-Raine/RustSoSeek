//! Native Soulseek client (clean-room implementation).
//!
//! Implements login, server search, and peer download directly over the
//! Soulseek wire protocol. No slskd process, no HTTP sidecar. All wire types
//! are confined to this crate via [`crate::wire`] and [`crate::proto`].

use crate::proto::{
    self, FileSearch, FileSearchResponse, FileTransferInit, GetPeerAddress, PeerInit,
    PierceFireWall, PlaceInQueueResponse, QueueUpload, TransferRequest, TransferResponse,
};
use crate::wire::{self, code, conn_type, direction, Message};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::{tcp::OwnedReadHalf, tcp::OwnedWriteHalf, TcpListener, TcpStream};
use tokio::sync::oneshot;

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

/// Shared state between the client and its background tasks.
#[derive(Default)]
struct Shared {
    searches: HashMap<u32, Vec<SearchResultEntry>>,
    /// peer token -> download (populated on accepted TransferRequest).
    downloads: HashMap<u32, Download>,
    /// downloads queued but awaiting a TransferRequest.
    pending: Vec<PendingDownload>,
    /// username -> pending address resolution.
    pending_addr: HashMap<String, oneshot::Sender<SocketAddr>>,
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
}

/// The native Soulseek client. Cheap to clone (wraps `Arc`s).
#[derive(Clone)]
pub struct NativeClient {
    inner: Arc<NativeInner>,
}

struct NativeInner {
    config: NativeConfig,
    shared: Arc<Mutex<Shared>>,
    server: tokio::sync::Mutex<OwnedWriteHalf>,
    listener: Arc<TcpListener>,
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

        let listener = TcpListener::bind(("0.0.0.0", config.listen_port))
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;

        let (read_half, write_half) = stream.into_split();
        let shared = Arc::new(Mutex::new(Shared::default()));
        let server = tokio::sync::Mutex::new(write_half);
        let listener = Arc::new(listener);

        let inner = Arc::new(NativeInner {
            config,
            shared: shared.clone(),
            server,
            listener,
        });
        let client = NativeClient { inner };

        // Announce our distributed-network posture: we have no parent yet and
        // will accept child nodes.
        {
            let mut server = client.inner.server.lock().await;
            server
                .write_all(&proto::HaveNoParent { no_parent: true }.encode().encode())
                .await
                .map_err(|e| crate::error::Error::Io(e.to_string()))?;
            server
                .write_all(&proto::AcceptChildren { accept: true }.encode().encode())
                .await
                .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        }

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
                let mut server = inner.server.lock().await;
                if server
                    .write_all(&crate::wire::server_ping().encode())
                    .await
                    .is_err()
                {
                    break;
                }
            }
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

    /// Start a server-side search, returning the token used to correlate results.
    pub async fn start_search(&self, query: &str) -> Result<u32, crate::error::Error> {
        let token = next_token();
        let msg = FileSearch {
            token,
            query: query.to_string(),
        }
        .encode();
        let mut server = self.inner.server.lock().await;
        server
            .write_all(&msg.encode())
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        drop(server);

        self.inner
            .shared
            .lock()
            .unwrap()
            .searches
            .insert(token, Vec::new());
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
        let pending = PendingDownload {
            username: username.to_string(),
            // Normalize to Soulseek's wire-path form (forward slashes) for the
            // queue request and the pending match. Search responses often carry
            // backslash paths from Windows peers, but those peers index their
            // shares with forward slashes; queueing the backslash form makes
            // them answer `UploadFailed` instantly. The raw search filename
            // stays in the adapter's metadata for display.
            filename: filename.replace('\\', "/"),
            size,
        };
        self.inner
            .shared
            .lock()
            .unwrap()
            .pending
            .push(pending.clone());

        let (addr_tx, addr_rx) = oneshot::channel();
        self.inner
            .shared
            .lock()
            .unwrap()
            .pending_addr
            .insert(username.to_string(), addr_tx);

        {
            let msg = GetPeerAddress {
                username: username.to_string(),
            }
            .encode();
            let mut server = self.inner.server.lock().await;
            server
                .write_all(&msg.encode())
                .await
                .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        }

        // Bound the address-resolution wait so a silent server cannot leak the
        // task or the pending/pending_addr entries forever.
        let peer_addr = tokio::time::timeout(std::time::Duration::from_secs(30), addr_rx)
            .await
            .map_err(|_| crate::error::Error::Unavailable("peer address timeout".into()))?
            .map_err(|_| crate::error::Error::Unavailable("no peer address".into()))?;

        let mut peer = TcpStream::connect(peer_addr)
            .await
            .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        peer.write_all(
            &PeerInit {
                username: self.inner.config.username.clone(),
                conn_type: conn_type::PEER.to_string(),
                token: 0,
            }
            .encode(),
        )
        .await
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;
        peer.write_all(
            &QueueUpload {
                filename: filename.to_string(),
            }
            .encode()
            .encode(),
        )
        .await
        .map_err(|e| crate::error::Error::Io(e.to_string()))?;

        let inner = self.inner.clone();
        tokio::spawn(async move {
            let _ = handle_peer_messages(peer, inner, Some(pending.username)).await;
        });

        Ok(())
    }
}

/// Delete a partial download file (basename only) from the download dir.
fn remove_partial_file(download_dir: &str, filename: &str) {
    let Some(name) = std::path::Path::new(filename).file_name() else {
        return;
    };
    let path = std::path::Path::new(download_dir).join(name);
    let _ = std::fs::remove_file(path);
}

/// Resolve a `GetPeerAddress` response into the pending oneshot channel.
fn resolve_peer_address(inner: &Arc<NativeInner>, resp: proto::GetPeerAddressResponse) {
    let addr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(resp.ip)),
        resp.port as u16,
    );
    let tx = inner
        .shared
        .lock()
        .unwrap()
        .pending_addr
        .remove(&resp.username);
    if let Some(tx) = tx {
        let _ = tx.send(addr);
    }
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
/// peer over a fresh `D` connection.
///
/// A distributed search that loops back to a token we initiated is already
/// tracked in `shared.searches`. agpeer v1 shares no files, so we never
/// generate a `FileSearchResponse` in response to a distributed search; we
/// only relay it deeper into the network.
fn handle_distributed_search(inner: &Arc<NativeInner>, search: proto::DistribSearch) {
    let _loopback = inner
        .shared
        .lock()
        .unwrap()
        .searches
        .contains_key(&search.token);

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
        conn_type::PEER => handle_peer_messages(stream, inner, None).await,
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

async fn handle_file_connection(
    mut stream: TcpStream,
    inner: Arc<NativeInner>,
) -> Result<(), std::io::Error> {
    let mut token_buf = [0u8; 4];
    stream.read_exact(&mut token_buf).await?;
    let init = FileTransferInit::decode(&token_buf).map_err(wire::into_io)?;
    tracing::info!(token = init.token, "soulseek: F connection opened");

    let (filename, expected_size, offset) = {
        let shared = inner.shared.lock().unwrap();
        match shared.downloads.get(&init.token) {
            Some(d) => {
                if shared.cancelled.contains(&d.filename) {
                    return Ok(());
                }
                (d.filename.clone(), d.size, d.offset)
            }
            None => {
                tracing::warn!(
                    token = init.token,
                    "soulseek: F connection for unknown transfer token"
                );
                return Ok(());
            }
        }
    };

    // Only one delivery path may write this transfer; the outbound `F`
    // fallback aborts when we win the claim here.
    let Some(_active) = claim_transfer(&inner.shared, init.token) else {
        tracing::debug!(
            token = init.token,
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
        if let Some(dl) = inner.shared.lock().unwrap().downloads.get_mut(&init.token) {
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
}
