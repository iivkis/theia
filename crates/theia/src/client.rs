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
    Http3,
    QuicUnreachable,
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
            Self::Configuration => f.write_str("invalid client configuration"),
            Self::Io => f.write_str("client TCP operation failed"),
            Self::Tls => f.write_str("TLS identity or ALPN verification failed"),
            Self::Http2 => f.write_str("HTTP/2 transport failed"),
            Self::Http3 => f.write_str("HTTP/3 transport failed"),
            Self::QuicUnreachable => f.write_str("quic_unreachable"),
            Self::Unauthorized => f.write_str("server rejected authentication"),
            Self::Rejected(status) => write!(f, "server rejected request (HTTP {status})"),
            Self::Protocol => f.write_str("SmartTheia protocol violation"),
            Self::Open(code) => write!(f, "target connection rejected ({code:?})"),
            Self::Timeout => f.write_str("client operation timed out"),
        }
    }
}

impl std::error::Error for ClientError {}

pub(crate) fn bearer_header(token: &str) -> Result<HeaderValue, ClientError> {
    if token.len() != 43 || token.contains('=') {
        return Err(ClientError::Configuration);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ClientError::Configuration)?;
    if raw.len() != 32 || URL_SAFE_NO_PAD.encode(&raw) != token {
        return Err(ClientError::Configuration);
    }
    let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| ClientError::Configuration)?;
    authorization.set_sensitive(true);
    Ok(authorization)
}

enum H2Tls {
    Rustls(TlsConnector),
    #[cfg(feature = "experimental-btls-h2")]
    Btls {
        server_name: String,
        trusted_ca_pem: Arc<[u8]>,
    },
}

/// One explicit H2 endpoint. Every tunnel owns a dedicated, verified TLS/H2
/// connection driver. The default backend remains rustls; an experimental
/// BoringSSL backend is only available through an explicit feature-gated API.
pub struct H2Client {
    endpoint: String,
    server_name: ServerName<'static>,
    uri: http::Uri,
    authorization: HeaderValue,
    connector: H2Tls,
}

impl H2Client {
    pub fn new(
        endpoint: &str,
        name: &str,
        token: &str,
        roots: RootCertStore,
    ) -> Result<Self, ClientError> {
        if roots.is_empty() {
            return Err(ClientError::Configuration);
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ClientError::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        tls.enable_early_data = false;
        Self::with_connector(
            endpoint,
            name,
            token,
            H2Tls::Rustls(TlsConnector::from(Arc::new(tls))),
        )
    }

    /// Experimental API only: build a separately verified BoringSSL connector
    /// with one explicit CA PEM. Not selected by TOML, H3 or the default CLI;
    /// never treat this as a named Chrome/browser fingerprint.
    #[cfg(feature = "experimental-btls-h2")]
    pub fn new_experimental_btls(
        endpoint: &str,
        name: &str,
        token: &str,
        trusted_ca_pem: &[u8],
    ) -> Result<Self, ClientError> {
        crate::h2_btls::validate_ca(trusted_ca_pem)?;
        Self::with_connector(
            endpoint,
            name,
            token,
            H2Tls::Btls {
                server_name: name.to_owned(),
                trusted_ca_pem: Arc::from(trusted_ca_pem),
            },
        )
    }

    fn with_connector(
        endpoint: &str,
        name: &str,
        token: &str,
        connector: H2Tls,
    ) -> Result<Self, ClientError> {
        let authorization = bearer_header(token)?;
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
        Ok(Self {
            endpoint: endpoint.to_owned(),
            server_name,
            uri,
            authorization,
            connector,
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
        let (mut sender, driver) = match &self.connector {
            H2Tls::Rustls(connector) => {
                let tls = connector
                    .connect(self.server_name.clone(), socket)
                    .await
                    .map_err(|_| ClientError::Tls)?;
                if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                    return Err(ClientError::Tls);
                }
                start_h2(tls).await?
            }
            #[cfg(feature = "experimental-btls-h2")]
            H2Tls::Btls {
                server_name,
                trusted_ca_pem,
            } => {
                let tls = crate::h2_btls::connect(socket, server_name, trusted_ca_pem).await?;
                start_h2(tls).await?
            }
        };
        // Build and send the credential-bearing POST ONLY after the selected
        // backend verified TLS identity and ALPN and established HTTP/2.
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

/// Same HTTP/2 transport engine and ownership regardless of verified TLS
/// backend. The SmartTheia HELLO/OPEN_OK state machine below is shared.
async fn start_h2<S>(tls: S) -> Result<(h2::client::SendRequest<Bytes>, Driver), ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::client::Builder::new();
    // Theia never accepts server push. Advertise that explicitly instead
    // of allowing a peer to reserve unsolicited streams. This matches the
    // safe SETTINGS_ENABLE_PUSH=0 part of the measured Chromium reference,
    // while retaining Theia's strict 8 KiB response-header limit and
    // bounded default receive windows. No named browser profile is claimed.
    builder.enable_push(false);
    builder.max_header_list_size(8192);
    let (sender, connection) = builder
        .handshake(tls)
        .await
        .map_err(|_| ClientError::Http2)?;
    let driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    Ok((sender, driver))
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
