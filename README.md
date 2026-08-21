# RustSoSeek

A clean-room, native Rust client for the Soulseek peer-to-peer network.

Implements the Soulseek wire protocol directly over TCP — no `slskd` sidecar,
no HTTP API, no external process:

- login (with the documented MD5 password hash)
- server search and result normalization
- peer download (`QueueUpload` → `TransferRequest`/`TransferResponse` → `F`
  connection streaming), with resume/offset support
- distributed search plumbing (parent/child `D` connections, search relaying)

## Licensing

Licensed under [Apache-2.0](LICENSE).

This is a **clean-room implementation**: it was written from the public Soulseek
protocol documentation only (`SLSKPROTOCOL.md`, Museek+ wiki) and contains no
code translated or copied from `slskd` (AGPL-3.0), `Soulseek.NET` (GPL-3.0),
`Nicotine+` (GPL-3.0), `aioslsk`, or `museek+`.

Out of scope for v1:

- the "Rotated" (type 1) obfuscation cipher — only obfuscation type 0 (none)
  is supported, matching Nicotine+;
- shares, uploads, chat rooms, and private messaging.

## Usage

```rust
use rustsoseek::{NativeClient, NativeConfig};

let client = NativeClient::connect(NativeConfig {
    username: "user".into(),
    password: "pass".into(),
    ..NativeConfig::default()
}).await?;

let token = client.start_search("artist album").await?;
// ...wait for results to accumulate...
let results = client.results(token, 100);
```

The client is `#[must_use]`-friendly and `Clone`able; it owns its background
connection tasks and a listen socket for inbound peer connections.

## Tests

Offline unit and integration tests use an in-process mock server and mock peer
(`src/mocknet.rs`); they never touch the live network:

```sh
cargo test
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
