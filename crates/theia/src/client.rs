//! Authenticated H2 client transport used by the local proxy listeners.
//! Trust anchors are supplied by the caller; this API never disables PKI.
use crate::protocol::{self, Address, Decoder, Direction, ErrorCode, Frame, Role, Session};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use http::{header, HeaderValue, Request, StatusCode};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{collections::VecDeque, fmt, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;

const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    Configuration,
    Io,
    Tls,
    Http2,
    Unauthorized,
    Rejected(u16),
    Protocol,
    Open(ErrorCode),
    Timeout,
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never display credential, request headers, endpoint or target values.
        match self {
            Self::Configuration => f.write_str("invalid H2 client configuration"),
            Self::Io => f.write_str("client TCP operation failed"),
            Self::Tls => f.write_str("TLS identity or ALPN verification failed"),
            Self::Http2 => f.write_str("HTTP/2 transport failed"),
            Self::Unauthorized => f.write_str("server rejected authentication"),
            Self::Rejected(status) => write!(f, "server rejected request (HTTP {status})"),
            Self::Protocol => f.write_str("SmartTheia protocol violation"),
            Self::Open(code) => write!(f, "target connection rejected ({code:?})"),
            Self::Timeout => f.write_str("client operation timed out"),
        }
    }
}

impl std::error::Error for ClientError {}

/// One explicit H2 endpoint. Each opened tunnel currently uses its own
/// TLS connection and owns its driver; no automatic fallback or pooling.
pub struct H2Client {
    endpoint: String,
    server_name: ServerName<'static>,
    uri: http::Uri,
    authorization: HeaderValue,
    connector: TlsConnector,
}

impl H2Client {
    pub fn new(
        endpoint: &str,
        name: &str,
        token: &str,
        roots: RootCertStore,
    ) -> Result<Self, ClientError> {
        if roots.is_empty() || token.len() != 43 || token.contains('=') {
            return Err(ClientError::Configuration);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| ClientError::Configuration)?;
        if raw.len() != 32 || URL_SAFE_NO_PAD.encode(&raw) != token {
            return Err(ClientError::Configuration);
        }
        let authority: http::uri::Authority =
            endpoint.parse().map_err(|_| ClientError::Configuration)?;
        if authority.port_u16().unwrap_or(0) == 0 || authority.host().is_empty() {
            return Err(ClientError::Configuration);
        }
        let server_name =
            ServerName::try_from(name.to_owned()).map_err(|_| ClientError::Configuration)?;
        let uri = http::Uri::builder()
            .scheme("https")
            .authority(name)
            .path_and_query("/v1/session")
            .build()
            .map_err(|_| ClientError::Configuration)?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| ClientError::Configuration)?;
        authorization.set_sensitive(true);
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ClientError::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        tls.enable_early_data = false;
        Ok(Self {
            endpoint: endpoint.to_owned(),
            server_name,
            uri,
            authorization,
            connector: TlsConnector::from(Arc::new(tls)),
        })
    }

    /// Resolve only the configured server endpoint. DNS target names are
    /// encoded verbatim as OPEN_TCP and are never resolved by this client.
    /// A successful return is possible only after a valid OPEN_OK.
    pub async fn open(&self, address: Address, port: u16) -> Result<Tunnel, ClientError> {
        let open = Frame::OpenTcp { address, port };
        protocol::encode(&open).map_err(|_| ClientError::Configuration)?;
        timeout(OPEN_TIMEOUT, self.open_inner(open))
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    async fn open_inner(&self, open: Frame) -> Result<Tunnel, ClientError> {
        let socket = TcpStream::connect(self.endpoint.as_str())
            .await
            .map_err(|_| ClientError::Io)?;
        let tls = self
            .connector
            .connect(self.server_name.clone(), socket)
            .await
            .map_err(|_| ClientError::Tls)?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(ClientError::Tls);
        }
        let mut builder = h2::client::Builder::new();
        builder.max_header_list_size(8192);
        let (mut sender, connection) = builder
            .handshake(tls)
            .await
            .map_err(|_| ClientError::Http2)?;
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.await;
        }));
        // The request, including the credential, is constructed and sent
        // only after rustls has verified certificate, name and TLS handshake.
        let request = Request::post(self.uri.clone())
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::AUTHORIZATION, self.authorization.clone())
            .body(())
            .map_err(|_| ClientError::Configuration)?;
        let (response, mut outgoing) = sender
            .send_request(request, false)
            .map_err(|_| ClientError::Http2)?;
        let response = response.await.map_err(|_| ClientError::Http2)?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ClientError::Unauthorized);
            }
            other => return Err(ClientError::Rejected(other.as_u16())),
        }
        let mut incoming = response.into_body();
        let mut decoder = IncomingFrames::default();
        let mut state = Session::new(Role::Client);
        let hello = Frame::Hello {
            version: protocol::VERSION,
            capabilities: 0,
        };
        state
            .apply(Direction::Send, &hello)
            .map_err(|_| ClientError::Protocol)?;
        send_frame(&mut outgoing, &hello, false).await?;
        let ack = decoder
            .next(&mut incoming)
            .await?
            .ok_or(ClientError::Protocol)?;
        state
            .apply(Direction::Receive, &ack)
            .map_err(|_| ClientError::Protocol)?;
        if !matches!(ack, Frame::HelloAck { .. }) {
            return Err(ClientError::Protocol);
        }
        state
            .apply(Direction::Send, &open)
            .map_err(|_| ClientError::Protocol)?;
        send_frame(&mut outgoing, &open, false).await?;
        let result = decoder
            .next(&mut incoming)
            .await?
            .ok_or(ClientError::Protocol)?;
        state
            .apply(Direction::Receive, &result)
            .map_err(|_| ClientError::Protocol)?;
        match result {
            Frame::OpenOk if state.tunnel_open() => Ok(Tunnel {
                incoming,
                outgoing,
                decoder,
                state,
                _driver: driver,
            }),
            Frame::OpenError(code) => Err(ClientError::Open(code)),
            _ => Err(ClientError::Protocol),
        }
    }
}

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Construction is private: a Tunnel always represents a verified OPEN_OK.
/// Dropping it also aborts the dedicated HTTP/2 connection driver.
pub struct Tunnel {
    incoming: h2::RecvStream,
    outgoing: h2::SendStream<Bytes>,
    decoder: IncomingFrames,
    state: Session,
    _driver: Driver,
}

impl Tunnel {
    /// Relay a local duplex byte stream after OPEN_OK. Each direction has
    /// independent flow control, one bounded frame buffer and FIN state.
    pub async fn relay<S>(mut self, local: S) -> Result<(), ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut read, mut write) = tokio::io::split(local);
        let incoming = &mut self.incoming;
        let outgoing = &mut self.outgoing;
        let decoder = &mut self.decoder;
        let mut upload_state = self.state.clone();
        let mut download_state = self.state.clone();
        let upload = async {
            let mut buffer = [0; 4096];
            loop {
                let size = timeout(IO_TIMEOUT, read.read(&mut buffer))
                    .await
                    .map_err(|_| ClientError::Timeout)?
                    .map_err(|_| ClientError::Io)?;
                let frame = if size == 0 {
                    Frame::Fin
                } else {
                    Frame::Data(buffer[..size].to_vec())
                };
                upload_state
                    .apply(Direction::Send, &frame)
                    .map_err(|_| ClientError::Protocol)?;
                timeout(IO_TIMEOUT, send_frame(outgoing, &frame, size == 0))
                    .await
                    .map_err(|_| ClientError::Timeout)??;
                if size == 0 {
                    return Ok::<(), ClientError>(());
                }
            }
        };
        let download = async {
            loop {
                let frame = decoder.next(incoming).await?.ok_or(ClientError::Protocol)?;
                download_state
                    .apply(Direction::Receive, &frame)
                    .map_err(|_| ClientError::Protocol)?;
                match frame {
                    Frame::Data(data) => {
                        timeout(IO_TIMEOUT, write.write_all(&data))
                            .await
                            .map_err(|_| ClientError::Timeout)?
                            .map_err(|_| ClientError::Io)?;
                    }
                    Frame::Fin => {
                        timeout(IO_TIMEOUT, write.shutdown())
                            .await
                            .map_err(|_| ClientError::Timeout)?
                            .map_err(|_| ClientError::Io)?;
                        break;
                    }
                    Frame::Abort(code) => return Err(ClientError::Open(code)),
                    _ => return Err(ClientError::Protocol),
                }
            }
            if decoder.next(incoming).await?.is_some() {
                return Err(ClientError::Protocol);
            }
            Ok::<(), ClientError>(())
        };
        tokio::try_join!(upload, download)?;
        self.state
            .apply(Direction::Send, &Frame::Fin)
            .map_err(|_| ClientError::Protocol)?;
        self.state
            .apply(Direction::Receive, &Frame::Fin)
            .map_err(|_| ClientError::Protocol)?;
        self.state.finish().map_err(|_| ClientError::Protocol)
    }
}

async fn send_frame(
    outgoing: &mut h2::SendStream<Bytes>,
    frame: &Frame,
    end: bool,
) -> Result<(), ClientError> {
    let mut bytes = Bytes::from(protocol::encode(frame).map_err(|_| ClientError::Protocol)?);
    while !bytes.is_empty() {
        outgoing.reserve_capacity(bytes.len());
        let capacity = if outgoing.capacity() == 0 {
            std::future::poll_fn(|cx| outgoing.poll_capacity(cx))
                .await
                .ok_or(ClientError::Http2)?
                .map_err(|_| ClientError::Http2)?
        } else {
            outgoing.capacity()
        };
        if capacity == 0 {
            continue;
        }
        let part = bytes.split_to(capacity.min(bytes.len()));
        outgoing
            .send_data(part, end && bytes.is_empty())
            .map_err(|_| ClientError::Http2)?;
    }
    Ok(())
}

#[derive(Default)]
struct IncomingFrames {
    decoder: Decoder,
    ready: VecDeque<Frame>,
}

impl IncomingFrames {
    async fn next(&mut self, incoming: &mut h2::RecvStream) -> Result<Option<Frame>, ClientError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let chunk = timeout(IO_TIMEOUT, incoming.data())
                .await
                .map_err(|_| ClientError::Timeout)?;
            let Some(chunk) = chunk else {
                self.decoder.finish().map_err(|_| ClientError::Protocol)?;
                return Ok(None);
            };
            let chunk = chunk.map_err(|_| ClientError::Http2)?;
            self.ready.extend(
                self.decoder
                    .feed(&chunk)
                    .map_err(|_| ClientError::Protocol)?,
            );
            incoming
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(|_| ClientError::Http2)?;
        }
    }
}
