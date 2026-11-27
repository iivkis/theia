//! Cross-platform TCP stream operations. No packet manipulation or drivers.
use super::tls::{self, Flight};
use crate::client::ClientError;
use std::{io, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub(super) async fn connect(
    address: SocketAddr,
) -> io::Result<(TcpStream, crate::routing::carrier_socket::Lease)> {
    crate::routing::carrier_socket::connect_tcp(address, true).await
}

/// Every attempted write revalidates the original scope. A short write
/// does not authorize the remainder after a concurrent revoke.
pub(super) async fn write_checked(
    socket: &mut (impl AsyncWrite + Unpin),
    mut bytes: &[u8],
    check: &(dyn Fn() -> Result<(), ClientError> + Sync),
) -> Result<(), ClientError> {
    while !bytes.is_empty() {
        check()?;
        let n = socket.write(bytes).await.map_err(|_| ClientError::Io)?;
        if n == 0 {
            return Err(ClientError::Io);
        }
        bytes = &bytes[n..];
    }
    Ok(())
}

/// Cancellation-safe bounded read: every consumed byte stays in prefix,
/// including an incomplete record after a timeout. No bytes are sent here.
pub(super) async fn read_hello(
    input: &mut (impl AsyncRead + Unpin),
    prefix: &mut Vec<u8>,
) -> Result<bool, ClientError> {
    let mut buffer = [0; 4096];
    loop {
        match tls::inspect(prefix) {
            Flight::Complete { .. } => return Ok(true),
            Flight::Unsupported => return Ok(false),
            Flight::Need(end) => {
                let n = end.saturating_sub(prefix.len()).min(buffer.len());
                if n == 0 || end > tls::FLIGHT_LIMIT {
                    return Ok(false);
                }
                let read = input
                    .read(&mut buffer[..n])
                    .await
                    .map_err(|_| ClientError::Io)?;
                if read == 0 {
                    return Ok(false);
                }
                prefix.extend_from_slice(&buffer[..read]);
            }
        }
    }
}

pub(super) async fn read_record(socket: &mut TcpStream) -> Result<Vec<u8>, ClientError> {
    let mut header = [0; 5];
    socket
        .read_exact(&mut header)
        .await
        .map_err(|_| ClientError::Io)?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if !(1..=tls::RECORD_LIMIT).contains(&len) {
        return Err(ClientError::Protocol);
    }
    let mut bytes = vec![0; 5 + len];
    bytes[..5].copy_from_slice(&header);
    socket
        .read_exact(&mut bytes[5..])
        .await
        .map_err(|_| ClientError::Io)?;
    Ok(bytes)
}

/// Observe a complete bounded server handshake instead of counting a record
/// containing only its message type as a successful first response.
pub(super) enum ServerFlight {
    Hello(Vec<u8>),
    Alert(Vec<u8>),
}

pub(super) async fn read_server_hello(socket: &mut TcpStream) -> Result<ServerFlight, ClientError> {
    let mut raw = Vec::new();
    let mut handshake = Vec::new();
    for _ in 0..16 {
        let record = read_record(socket).await?;
        if record[0] == 21
            && raw.is_empty()
            && record[1] == 3
            && (1..=3).contains(&record[2])
            && record.len() == 7
        {
            return Ok(ServerFlight::Alert(record));
        }
        if record[0] != 22 || record[1] != 3 || !(1..=3).contains(&record[2]) {
            return Err(ClientError::Protocol);
        }
        if raw.len() + record.len() > tls::FLIGHT_LIMIT {
            return Err(ClientError::Protocol);
        }
        handshake.extend_from_slice(&record[5..]);
        raw.extend_from_slice(&record);
        if handshake.first() != Some(&2) {
            return Err(ClientError::Protocol);
        }
        if handshake.len() >= 4 {
            let total = 4
                + (usize::from(handshake[1]) << 16)
                + (usize::from(handshake[2]) << 8)
                + usize::from(handshake[3]);
            if !(42..=32 * 1024).contains(&total) {
                return Err(ClientError::Protocol);
            }
            if handshake.len() >= total {
                return if tls::server_hello(&handshake[..total]) {
                    Ok(ServerFlight::Hello(raw))
                } else {
                    Err(ClientError::Protocol)
                };
            }
        }
    }
    Err(ClientError::Protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    #[tokio::test]
    async fn partial_write_rechecks_before_remaining_bytes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (mut output, mut peer) = tokio::io::duplex(1);
        let attempts = AtomicUsize::new(0);
        let check = || {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(())
            } else {
                Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied))
            }
        };
        assert!(matches!(
            write_checked(&mut output, b"abc", &check).await,
            Err(ClientError::Open(crate::protocol::ErrorCode::PolicyDenied))
        ));
        drop(output);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"a");
    }

    #[tokio::test]
    async fn inspection_retains_prefix_on_timeout_and_leaves_tail() {
        let (mut app, mut proxy) = tokio::io::duplex(4096);
        let hello = tls::fixture("example.org");
        app.write_all(&hello[..8]).await.unwrap();
        let mut prefix = Vec::new();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            read_hello(&mut proxy, &mut prefix)
        )
        .await
        .is_err());
        assert_eq!(prefix, hello[..8]);
        app.write_all(&hello[8..]).await.unwrap();
        app.write_all(b"tail").await.unwrap();
        assert!(read_hello(&mut proxy, &mut prefix).await.unwrap());
        assert_eq!(prefix, hello);
        let mut tail = [0; 4];
        proxy.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");
        let (mut app, mut proxy) = tokio::io::duplex(64);
        app.write_all(b"hello world").await.unwrap();
        let mut prefix = Vec::new();
        assert!(!read_hello(&mut proxy, &mut prefix).await.unwrap());
        assert_eq!(prefix, b"hello");
    }

    #[tokio::test]
    async fn fragmented_server_hello_requires_complete_message_and_preserves_records() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (left, right) =
            tokio::join!(connect(listener.local_addr().unwrap()), listener.accept());
        let (mut client, _lease) = left.unwrap();
        let (mut server, _) = right.unwrap();
        let mut message = vec![2, 0, 0, 38, 3, 3];
        message.extend([1; 32]);
        message.extend([0, 0x13, 1, 0]);
        assert!(tls::server_hello(&message));
        for n in 0..message.len() {
            assert!(!tls::server_hello(&message[..n]));
        }
        let mut wire = Vec::new();
        for part in [&message[..2], &message[2..]] {
            wire.extend([22, 3, 3, 0, part.len() as u8]);
            wire.extend(part);
        }
        server.write_all(&wire).await.unwrap();
        assert!(
            matches!(read_server_hello(&mut client).await.unwrap(), ServerFlight::Hello(response) if response == wire)
        );
        let alert = [21, 3, 3, 0, 2, 2, 40];
        server.write_all(&alert).await.unwrap();
        assert!(
            matches!(read_server_hello(&mut client).await.unwrap(), ServerFlight::Alert(response) if response == alert)
        );
    }

    #[tokio::test]
    async fn socket_connect_is_scoped() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(connect(address), listener.accept());
        let (client, _lease) = client.unwrap();
        let (_server, _) = server.unwrap();
        assert_eq!(client.peer_addr().unwrap(), address);
        assert!(client.nodelay().unwrap());
    }
}
