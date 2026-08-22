# RustSoSeek

A clean-room, native Rust client for the Soulseek peer-to-peer network.

RustSoSeek is a **library**, not an application: you embed it, spawn a client,
and drive it with async calls. It implements the Soulseek wire protocol
directly over TCP — no `slskd` sidecar, no HTTP API, no external process.

What it does today:

- **Login** to the Soulseek server (documented MD5 password hash scheme)
- **Search** — server file search, result normalization (bitrate/duration/
  extension parsing), health-sorted results
- **Downloads** — queue a file from a peer and stream it to disk, including
  all the connection-direction interop needed behind firewalls/NAT
  (see [How downloads work](#how-downloads-work))
- **Distributed search plumbing** — parent/child `D` connections and search
  relaying

What it deliberately does **not** do (v1): shares/uploads, chat rooms, private
messaging, and the "Rotated" (type 1) obfuscation cipher (only obfuscation
type 0, matching Nicotine+).

## Licensing

Licensed under [Apache-2.0](LICENSE).

This is a **clean-room implementation**: it was written from the public
Soulseek protocol documentation only (`SLSKPROTOCOL.md`, Museek+ wiki) and
contains no code translated or copied from `slskd` (AGPL-3.0),
`Soulseek.NET` (GPL-3.0), `Nicotine+` (GPL-3.0), `aioslsk`, or `museek+`.

## Installation

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
rustsoseek = { git = "https://github.com/Scarlet-Raine/RustSoSeek", tag = "v0.1.2" }
```

Requires Rust 1.88+ (tokio MSRV baseline for this workspace).

## Quickstart

Connect, search, pick a result, download it:

```rust
use rustsoseek::{NativeClient, NativeConfig};

#[tokio::main]
async fn main() -> Result<(), rustsoseek::Error> {
    let client = NativeClient::connect(NativeConfig {
        username: "my-username".into(),
        password: "my-password".into(),
        // everything else has a sane default (see Configuration below)
        ..NativeConfig::default()
    })
    .await?;

    // 1. Start a search; returns a token used to collect results.
    let token = client.start_search("artist album flac").await?;

    // 2. Results accumulate asynchronously as peers answer (~15 s covers
    //    most of the first wave).
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    let results = client.results(token, 100);

    // 3. Pick a candidate. free_upload_slots=true peers answer immediately;
    //    smaller files finish faster; low queue_length helps otherwise.
    let Some(pick) = results
        .iter()
        .find(|r| r.free_upload_slots == Some(true) && r.size.unwrap_or(0) > 0)
    else {
        return Ok(()); // nothing viable yet
    };

    // 4. Queue the download. Pass the filename exactly as the result
    //    reported it (any mix of / and \ separators works).
    client
        .download(&pick.username, &pick.filename, pick.size.unwrap_or(0))
        .await?;

    // 5. Poll progress until the entry disappears (complete or cleaned up).
    loop {
        let done = {
            let status = client.download_status();
            let mine = status.iter().find(|s| s.username == pick.username);
            match mine {
                Some(s) => {
                    println!("{} / {}", s.offset, s.size);
                    false
                }
                None => true, // finished (or refused — see below)
            }
        };
        if done {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // 6. Check whether the peer actually delivered. A refusal lands here
    //    instead of hanging forever as "queued".
    if !client.take_failed_downloads().is_empty() {
        eprintln!("peer refused the download; try another result");
    }
    Ok(())
}
```

Files land inside `download_dir`, named after the final path segment of the
peer's filename. When the expected size has been received the client closes
the connection — closing is always the downloader's job.

## API reference

### `NativeConfig`

| Field | Type | Default | Meaning |
|---|---|---|---|
| `server_addr` | `String` | `vps.slsknet.org:2242` | Soulseek server |
| `username` | `String` | — | account name |
| `password` | `String` | — | account password |
| `listen_port` | `u16` | `2234` | local TCP port for inbound peer connections (search responses, direct file delivery) |
| `download_dir` | `String` | `downloads` | where completed files are written |
| `major_version` | `u32` | `177` | reserved — see below |
| `minor_version` | `u32` | `710` | reserved — see below |

`connect()` performs login, announces `listen_port`, opens the listen socket,
and spawns the background keep-alive/server/peer/relay tasks. It fails fast
on unreachable servers (`Error::Unavailable`) and bad credentials
(`Error::AuthenticationFailed`). The returned `NativeClient` is cheap to
`Clone`.

agpeer logs in with major version `177`, minor version `710`. Do not reuse
these numbers elsewhere.

### `NativeClient` methods

```rust
// --- search ---
pub async fn start_search(&self, query: &str) -> Result<u32>   // -> search token
pub fn results(&self, token: u32, max_results: usize) -> Vec<SearchResult>
pub fn stop_search(&self, token: u32)

// --- downloads ---
pub async fn download(&self, username: &str, filename: &str, size: u64) -> Result<()>
pub fn download_status(&self) -> Vec<DownloadStatus>
pub fn take_failed_downloads(&self) -> Vec<(String, String)>
pub fn cancel(&self, filename: &str, delete_data: bool)

// --- introspection ---
pub fn listen_addr(&self) -> SocketAddr      // your advertised peer address
pub fn parent(&self) -> Option<SocketAddr>   // distributed parent, if any
pub fn excluded_phrases(&self) -> Vec<String> // server-provided search exclusions
```

Semantics that matter:

- **`results`** returns up to `max_results` entries sorted by health: free
  upload slots first, then faster uploaders, then shorter queues. Each call
  re-snapshots accumulated state; searches keep collecting until stopped.
- **`download_status`** contains an entry per accepted, unfinished download.
  Entries disappear once the transfer completes (or is cancelled/refused), so
  "no matching entry" means finished — cross-check `take_failed_downloads`
  to distinguish success from refusal.
- **`take_failed_downloads`** drains `(username, filename)` pairs for every
  time a peer answered `UploadFailed` (file gone from their share, policy
  rejection, or they gave up on delivering). Filenames echo the peer's own
  separator form; compare paths separator-insensitively.
- **`cancel`** matches by filename (separator-insensitive). Stops any active
  write immediately; `delete_data = true` also deletes the partial file.
- **No resume:** a fresh download always starts from offset 0. Killing a
  transfer mid-stream leaves a partial file; start over or cancel with
  `delete_data`.

### `SearchResult`

```rust
pub struct SearchResult {
    pub username: String,
    pub filename: String,               // peer's share-index path (either separator style)
    pub size: Option<u64>,
    pub extension: Option<String>,      // e.g. Some("flac")
    pub bitrate: Option<u32>,
    pub duration: Option<u32>,
    pub queue_length: Option<u32>,
    pub free_upload_slots: Option<bool>,
    pub upload_speed: Option<u64>,
    pub token: u32,
}
```

### `DownloadStatus`

```rust
pub struct DownloadStatus {
    pub username: String,
    pub filename: String,   // normalized (forward-slash) form
    pub size: u64,
    pub offset: u64,        // bytes written so far
}
```

### `Error`

```text
Unavailable           — cannot reach/login sequence failed pre-auth
AuthenticationFailed  — server rejected credentials
InvalidMessage(String)— malformed protocol data
Io(String)            — socket/filesystem failure
Internal(String)      — invariant violation, please report
```

## How downloads work

Understanding this section explains every log line starting with
`soulseek:` (target `rustsoseek::native`).

The queue handshake runs over a `P` (peer) connection:

1. We resolve the peer's address via the server (`GetPeerAddress`), dial it,
   introduce ourselves with `PeerInit(P)`.
2. We send `QueueUpload(filename)` — separators normalized to forward
   slashes, which every mainstream uploader accepts regardless of how their
   share index is formatted.
3. The peer eventually replies `TransferRequest(direction=Upload, token,
   filename, size)` — often seconds later for free-slot peers, minutes for
   queued ones. We match it against pending downloads (separator-insensitively
   — Windows peers echo backslash paths) and accept with `TransferResponse`.

Then the file arrives over an `F` connection, via whichever of three paths
the peer supports — you don't choose, the client handles all of them:

| Path | Who dials | Typical source |
|---|---|---|
| Direct inbound | peer connects to our `listen_port` | port-forwarded hosts |
| Relayed (`PierceFireWall`) | we connect *out* to the peer after a `ConnectToPeer(conn_type="F")` nudge via the server — the standard path when either side is behind NAT | most uploaders, no port forwarding needed anywhere |
| Outbound fallback | we connect out ~800 ms after accepting, send `PeerInit(F)` + `FileTransferInit` + `FileOffset` | slskd-style uploaders that expect the downloader to dial |

On any established `F` connection the downloader declares its resume offset
(`FileOffset`, 8 bytes little-endian, `0` for fresh transfers) and the
uploader streams raw file bytes until the announced `TransferRequest` size is
reached. Exactly one delivery path wins per transfer (a claim guard prevents
two paths writing the same file); the loser aborts quietly — look for
`outbound F aborted; transfer already streaming` at DEBUG level.

Failure modes surface honestly:

- Peer never answers → the download stays visible in `download_status`
  indefinitely (their slot may still open). Cancel it yourself if you'd
  rather not wait.
- Peer refuses (`UploadFailed`) → entry cleaned up and the refusal recorded
  for `take_failed_downloads`.

Downloads require no port forwarding: relayed delivery covers firewalled
hosts for the download direction.

## Logging

The crate logs through `tracing` under target `rustsoseek::native`: INFO for
connection lifecycle and transfer outcomes, DEBUG for per-message traffic.
A useful filter when debugging transfers:

```sh
RUST_LOG=info,rustsoseek=debug
```

Never log at TRACE in production — DEBUG already includes usernames and
filenames.

## Tests

Offline unit and integration tests use an in-process mock server and mock
peer (`src/mocknet.rs`) covering login, search, both file-delivery paths
(direct inbound and `PierceFireWall` relay), and refusal handling. They never
touch the live network:

```sh
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt -- --check
```

An opt-in live test exercises login + search against the real network. It is
`#[ignore]`d and gated behind environment variables:

```sh
AGPEER_LIVE_SOULSEEK=1 \
AGPEER_SOULSEEK_USERNAME=... \
AGPEER_SOULSEEK_PASSWORD=... \
cargo test --test live_soulseek -- --ignored
```

## Reserved protocol version

agpeer logs in with major version `177`, minor version `710`. Do not reuse
these numbers elsewhere.
