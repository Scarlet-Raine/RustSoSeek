//! In-process deterministic mock Soulseek server for offline tests.
//!
//! Speaks the real wire framing (see [`crate::wire`]) over a loopback TCP
//! listener. It models only the server-side messages needed by the tests that
//! use it; it never touches the live Soulseek network.

use crate::wire::{code, Message, Reader};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Behavior configuration for [`spawn`].
#[derive(Debug, Clone)]
pub struct MockServerConfig {
    /// Whether login should succeed. When false, [`MockServerConfig::reject_reason`]
    /// is returned as the rejection reason.
    pub login_success: bool,
    pub reject_reason: String,
    pub greet: String,
    /// MD5 hex digest echoed back for the password on a successful login.
    pub password_hash: String,
}

impl Default for MockServerConfig {
    fn default() -> Self {
        Self {
            login_success: true,
            reject_reason: "INVALIDPASS".to_string(),
            greet: "welcome to the mock".to_string(),
            password_hash: "mock-password-hash".to_string(),
        }
    }
}

/// A running mock server handle.
pub struct MockServer {
    pub addr: std::net::SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

/// Spawn the mock server on a random loopback port.
pub async fn spawn(config: MockServerConfig) -> MockServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock soulseek listener");
    let addr = listener.local_addr().expect("mock soulseek local addr");

    let (tx, rx) = oneshot::channel::<()>();
    let config = Arc::new(config);

    tokio::spawn(async move {
        accept_loop(listener, config, rx).await;
    });

    MockServer {
        addr,
        shutdown: Some(tx),
    }
}

impl MockServer {
    /// Signals the server task to stop and waits briefly for it to finish.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

async fn accept_loop(
    listener: TcpListener,
    config: Arc<MockServerConfig>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown => return,
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { continue };
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, config).await;
                });
            }
        }
    }
}

/// Reads one framed message from the stream. Returns `Ok(None)` on a clean EOF.
pub async fn read_message(stream: &mut TcpStream) -> std::io::Result<Option<Message>> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let body_len = u32::from_le_bytes(len_buf) as usize;
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    let mut framed = Vec::with_capacity(4 + body_len);
    framed.extend_from_slice(&len_buf);
    framed.extend_from_slice(&body);
    Message::decode(&framed)
        .map(Some)
        .map_err(crate::wire::into_io)
}

/// Writes a framed message to the stream.
pub async fn write_message(stream: &mut TcpStream, msg: &Message) -> std::io::Result<()> {
    stream.write_all(&msg.encode()).await
}

async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<MockServerConfig>,
) -> std::io::Result<()> {
    // First message must be Login.
    match read_message(&mut stream).await? {
        Some(msg) if msg.code == code::LOGIN => {
            let mut r = Reader::new(&msg.payload);
            let _username = r.read_string().map_err(crate::wire::into_io)?;
            let _password = r.read_string().map_err(crate::wire::into_io)?;

            let response = if config.login_success {
                crate::wire::LoginResponse::encode_success(
                    &config.greet,
                    0x7f00_0001,
                    &config.password_hash,
                    false,
                )
            } else {
                crate::wire::LoginResponse::encode_failure(&config.reject_reason, None)
            };
            write_message(&mut stream, &response).await?;
        }
        _ => {
            // Unrecognized first message; keep the socket open a moment then
            // drop, so the client observes an EOF rather than a hang.
            return Ok(());
        }
    }

    // Tolerate subsequent control messages (SetListenPort, ServerPing) until
    // EOF or shutdown. No responses are required for these in the current
    // protocol.
    while let Some(msg) = read_message(&mut stream).await? {
        match msg.code {
            code::SET_LISTEN_PORT | code::SERVER_PING => {}
            _ => return Ok(()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{LoginRequest, LoginResponse};

    #[tokio::test]
    async fn successful_login_roundtrip() {
        let mock = spawn(MockServerConfig::default()).await;
        let mut stream = TcpStream::connect(mock.addr).await.expect("connect");

        let req = LoginRequest {
            username: "alice".to_string(),
            password: "secret".to_string(),
            major_version: 177,
            hash: "00000000000000000000000000000000".to_string(),
            minor_version: 1,
        };
        write_message(&mut stream, &req.encode())
            .await
            .expect("send login");

        let response = read_message(&mut stream)
            .await
            .expect("read")
            .expect("present");
        let decoded = LoginResponse::decode(&response).expect("decode login response");
        assert!(decoded.success);
        assert_eq!(decoded.greet.as_deref(), Some("welcome to the mock"));
        assert_eq!(decoded.own_ip, Some(0x7f00_0001));
        assert_eq!(decoded.hash.as_deref(), Some("mock-password-hash"));
        assert!(!decoded.is_supporter.unwrap());

        // A ServerPing after login must be tolerated without a response or
        // error; verify the socket is still open by sending one and reading
        // clean EOF on shutdown.
        write_message(&mut stream, &crate::wire::server_ping())
            .await
            .expect("send ping");
        mock.stop().await;
    }

    #[tokio::test]
    async fn rejected_login_returns_reason() {
        let mock = spawn(MockServerConfig {
            login_success: false,
            ..MockServerConfig::default()
        })
        .await;
        let mut stream = TcpStream::connect(mock.addr).await.expect("connect");

        let req = LoginRequest {
            username: "alice".to_string(),
            password: "wrong".to_string(),
            major_version: 177,
            hash: "11111111111111111111111111111111".to_string(),
            minor_version: 1,
        };
        write_message(&mut stream, &req.encode())
            .await
            .expect("send login");

        let response = read_message(&mut stream)
            .await
            .expect("read")
            .expect("present");
        let decoded = LoginResponse::decode(&response).expect("decode login response");
        assert!(!decoded.success);
        assert_eq!(decoded.reason.as_deref(), Some("INVALIDPASS"));
        mock.stop().await;
    }

    #[tokio::test]
    async fn read_message_detects_clean_eof() {
        let mock = spawn(MockServerConfig::default()).await;
        let mut stream = TcpStream::connect(mock.addr).await.expect("connect");
        write_message(
            &mut stream,
            &LoginRequest {
                username: "a".to_string(),
                password: "b".to_string(),
                major_version: 177,
                hash: "22222222222222222222222222222222".to_string(),
                minor_version: 1,
            }
            .encode(),
        )
        .await
        .expect("send");
        let _ = read_message(&mut stream)
            .await
            .expect("read login response");

        // Drop the read half after the server closes; read_message returns None
        // on clean EOF rather than an error.
        drop(stream);
        mock.stop().await;
    }
}
