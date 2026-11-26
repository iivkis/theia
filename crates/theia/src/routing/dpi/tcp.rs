//! Cross-platform TCP stream operations. No packet manipulation or drivers.
use super::tls::{self, Flight};
use crate::client::ClientError;
use std::{io, net::SocketAddr};
use tokio::{io::{AsyncRead, AsyncReadExt}, net::TcpStream};

pub(super) async fn connect(address: SocketAddr) -> io::Result<TcpStream> {
    let socket = TcpStream::connect(address).await?;
    socket.set_nodelay(true)?;
    if socket.peer_addr()? != address || !socket.nodelay()? {
        return Err(io::Error::other("socket policy not confirmed"));
    }
    Ok(socket)
}

/// Cancellation-safe bounded read: every consumed byte stays in prefix,
/// including an incomplete record after a timeout. No bytes are sent here.
pub(super) async fn read_hello(input: &mut (impl AsyncRead + Unpin), prefix: &mut Vec<u8>) -> Result<bool,ClientError> {
    let mut buffer = [0;4096];
    loop {
        match tls::inspect(prefix) {
            Flight::Complete { .. } => return Ok(true),
            Flight::Unsupported => return Ok(false),
            Flight::Need(end) => {
                let n = end.saturating_sub(prefix.len()).min(buffer.len());
                if n == 0 || end > tls::FLIGHT_LIMIT { return Ok(false); }
                let read = input.read(&mut buffer[..n]).await.map_err(|_|ClientError::Io)?;
                if read == 0 { return Ok(false); }
                prefix.extend_from_slice(&buffer[..read]);
            }
        }
    }
}

pub(super) async fn read_record(socket: &mut TcpStream) -> Result<Vec<u8>,ClientError> {
    let mut header=[0;5];
    socket.read_exact(&mut header).await.map_err(|_|ClientError::Io)?;
    let len=usize::from(u16::from_be_bytes([header[3],header[4]]));
    if !(1..=tls::RECORD_LIMIT).contains(&len) { return Err(ClientError::Protocol); }
    let mut bytes=vec![0;5+len];
    bytes[..5].copy_from_slice(&header);
    socket.read_exact(&mut bytes[5..]).await.map_err(|_|ClientError::Io)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    #[tokio::test]
    async fn inspection_retains_prefix_on_timeout_and_leaves_tail() {
        let (mut app,mut proxy)=tokio::io::duplex(4096);
        let hello=tls::fixture("example.org");
        app.write_all(&hello[..8]).await.unwrap();
        let mut prefix=Vec::new();
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20),read_hello(&mut proxy,&mut prefix)).await.is_err());
        assert_eq!(prefix,hello[..8]);
        app.write_all(&hello[8..]).await.unwrap();
        app.write_all(b"tail").await.unwrap();
        assert!(read_hello(&mut proxy,&mut prefix).await.unwrap());
        assert_eq!(prefix,hello);
        let mut tail=[0;4];
        proxy.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail,b"tail");
        let (mut app,mut proxy)=tokio::io::duplex(64);
        app.write_all(b"hello world").await.unwrap();
        let mut prefix=Vec::new();
        assert!(!read_hello(&mut proxy,&mut prefix).await.unwrap());
        assert_eq!(prefix,b"hello");
    }

    #[tokio::test]
    async fn socket_connect_is_scoped() {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address=listener.local_addr().unwrap();
        let (client,server)=tokio::join!(connect(address),listener.accept());
        let client=client.unwrap();
        let (_server,_)=server.unwrap();
        assert_eq!(client.peer_addr().unwrap(),address);
        assert!(client.nodelay().unwrap());
    }
}
