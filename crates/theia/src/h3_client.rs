//! Explicit H3 client core. No fallback, CLI or connection pooling yet.
use crate::{
    client::{bearer_header, error_kind, ClientError},
    diagnostics::{self, Value},
    protocol::{self, Address, Decoder, Direction, Frame, Role, Session},
    quic_transport::{ObservedEndpoint, QuicError},
};
use bytes::{Buf, Bytes};
use h3::{client::RequestStream, quic};
use http::{header, HeaderValue, Request, StatusCode, Uri};
use rustls::{pki_types::ServerName, RootCertStore};
use std::{collections::VecDeque, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    task::JoinHandle,
    time::timeout,
};

const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HEADERS: u64 = 8192;
type Tx = RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type Rx = RequestStream<h3_quinn::RecvStream, Bytes>;

pub struct H3Client {
    remote: SocketAddr,
    name: String,
    uri: Uri,
    authorization: HeaderValue,
    roots: RootCertStore,
    connect_timeout: Duration,
    certificate_pin: Option<crate::security_profile::CertificatePin>,
    server_identity: Option<crate::reality_identity::PublicIdentity>,
    stream_up: bool,
}

impl H3Client {
    /// Only the configured server address is resolved by the composition
    /// root. Target DNS names remain opaque SmartTheia addresses.
    pub fn new(
        remote: SocketAddr,
        name: &str,
        token: &str,
        roots: RootCertStore,
    ) -> Result<Self, ClientError> {
        if remote.port() == 0 || remote.ip().is_unspecified() || roots.is_empty() {
            return Err(ClientError::Configuration);
        }
        if !matches!(ServerName::try_from(name), Ok(ServerName::DnsName(_))) {
            return Err(ClientError::Configuration);
        }
        let uri = Uri::builder()
            .scheme("https")
            .authority(name)
            .path_and_query("/v1/session")
            .build()
            .map_err(|_| ClientError::Configuration)?;
        Ok(Self {
            remote,
            name: name.to_owned(),
            uri,
            authorization: bearer_header(token)?,
            roots,
            connect_timeout: Duration::from_secs(10),
            certificate_pin: None,
            server_identity: None,
            stream_up: false,
        })
    }

    pub fn with_certificate_pin(
        mut self,
        pin: Option<crate::security_profile::CertificatePin>,
    ) -> Result<Self, ClientError> {
        if pin.is_some() {
            if self.server_identity.is_some() {
                return Err(ClientError::Configuration);
            }
            self.uri = Uri::builder()
                .scheme("https")
                .authority(self.name.as_str())
                .path_and_query(crate::security_profile::PINNED_PATH)
                .build()
                .map_err(|_| ClientError::Configuration)?;
        } else if self.certificate_pin.is_some() {
            return Err(ClientError::Configuration);
        }
        self.certificate_pin = pin;
        Ok(self)
    }

    /// Independent server signing key, verified before bearer is transmitted.
    pub fn with_server_identity(
        mut self,
        identity: Option<crate::reality_identity::PublicIdentity>,
    ) -> Result<Self, ClientError> {
        if identity.is_some() {
            if self.certificate_pin.is_some() || self.server_identity.is_some() {
                return Err(ClientError::Configuration);
            }
            self.stream_up = true;
        } else if self.server_identity.is_some() {
            return Err(ClientError::Configuration);
        }
        self.server_identity = identity;
        Ok(self)
    }

    /// An explicit second HTTP stream; cannot weaken the selected identity.
    pub fn with_stream_up(mut self, enabled: bool) -> Result<Self, ClientError> {
        if (enabled && self.certificate_pin.is_none() && self.server_identity.is_none())
            || (self.stream_up && !enabled)
        {
            return Err(ClientError::Configuration);
        }
        self.stream_up = enabled;
        Ok(self)
    }

    pub(crate) fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub fn with_connect_timeout(mut self, duration: Duration) -> Result<Self, ClientError> {
        if !(Duration::from_millis(500)..=Duration::from_secs(15)).contains(&duration) {
            return Err(ClientError::Configuration);
        }
        self.connect_timeout = duration;
        Ok(self)
    }

    pub async fn open(&self, address: Address, port: u16) -> Result<H3Tunnel, ClientError> {
        let operation = diagnostics::next_id();
        crate::diag!(
            Debug,
            "client.h3",
            "open_begin",
            "op" = Value::Count(operation)
        );
        let open = Frame::OpenTcp { address, port };
        protocol::encode(&open).map_err(|_| ClientError::Configuration)?;
        let result = timeout(OPEN_TIMEOUT, self.open_inner(open, operation))
            .await
            .map_err(|_| ClientError::Timeout)
            .and_then(|result| result);
        match &result {
            Ok(_) => crate::diag!(
                Debug,
                "client.h3",
                "open_confirmed",
                "op" = Value::Count(operation)
            ),
            Err(error) => crate::diag!(
                Warn,
                "client.h3",
                "open_failed",
                "op" = Value::Count(operation),
                "reason" = Value::Label(error_kind(error))
            ),
        }
        result
    }

    async fn open_inner(&self, open: Frame, operation: u64) -> Result<H3Tunnel, ClientError> {
        let bind = if self.remote.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let endpoint = ObservedEndpoint::new(bind, self.roots.clone()).map_err(quic_error)?;
        // No credential/request data until verified full handshake and BBR.
        let connection = endpoint
            .connect(self.remote, &self.name, self.connect_timeout)
            .await
            .map_err(quic_error)?;
        if let Some(pin) = self.certificate_pin {
            let chain = connection
                .peer_identity()
                .ok_or(ClientError::Tls)?
                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .map_err(|_| ClientError::Tls)?;
            pin.verify(chain.first().ok_or(ClientError::Tls)?.as_ref())?;
        }
        let binding = if self.certificate_pin.is_some() || self.server_identity.is_some() {
            let mut key = zeroize::Zeroizing::new([0u8; 32]);
            connection
                .export_keying_material(
                    &mut key[..],
                    crate::channel_binding::LABEL,
                    crate::channel_binding::H3,
                )
                .map_err(|_| ClientError::Tls)?;
            Some(key)
        } else {
            None
        };
        crate::diag!(
            Trace,
            "client.h3",
            "quic_tls_bbr_verified",
            "op" = Value::Count(operation)
        );
        let mut builder = h3::client::builder();
        builder.max_field_section_size(MAX_HEADERS);
        let (mut driver, mut sender) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
            .await
            .map_err(|_| ClientError::Http3)?;
        // h3 closes the connection when the final SendRequest is dropped.
        // Keep a sender alive with the owned driver throughout relay.
        let keep_sender = sender.clone();
        let driver = Driver(tokio::spawn(async move {
            let _keep_sender = keep_sender;
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        }));
        if let Some(identity) = self.server_identity {
            let key = binding.as_ref().ok_or(ClientError::Tls)?;
            let mut stream = sender
                .send_request(crate::reality_identity::request(&self.uri)?)
                .await
                .map_err(|_| ClientError::Http3)?;
            stream.finish().await.map_err(|_| ClientError::Http3)?;
            let response = stream
                .recv_response()
                .await
                .map_err(|_| ClientError::Http3)?;
            identity.verify(key, &response)?;
            if stream
                .recv_data()
                .await
                .map_err(|_| ClientError::Http3)?
                .is_some()
                || stream
                    .recv_trailers()
                    .await
                    .map_err(|_| ClientError::Http3)?
                    .is_some()
            {
                return Err(ClientError::Protocol);
            }
        }
        let (response, mut tx, mut rx) = if self.stream_up {
            use crate::split_http::{self, Leg};
            let mut download = sender
                .send_request(crate::channel_binding::attach(
                    binding.as_ref(),
                    split_http::request(&self.uri, Leg::Download, &self.authorization)?,
                )?)
                .await
                .map_err(|_| ClientError::Http3)?;
            download.finish().await.map_err(|_| ClientError::Http3)?;
            let mut upload = sender
                .send_request(crate::channel_binding::attach(
                    binding.as_ref(),
                    split_http::request(&self.uri, Leg::Upload, &self.authorization)?,
                )?)
                .await
                .map_err(|_| ClientError::Http3)?;
            let upload_response = upload
                .recv_response()
                .await
                .map_err(|_| ClientError::Http3)?;
            split_http::check_status(upload_response.status())?;
            if upload
                .recv_data()
                .await
                .map_err(|_| ClientError::Http3)?
                .is_some()
                || upload
                    .recv_trailers()
                    .await
                    .map_err(|_| ClientError::Http3)?
                    .is_some()
            {
                return Err(ClientError::Protocol);
            }
            let response = download
                .recv_response()
                .await
                .map_err(|_| ClientError::Http3)?;
            let (tx, _) = upload.split();
            let (_, rx) = download.split();
            (response, tx, rx)
        } else {
            let request = Request::post(self.uri.clone())
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::AUTHORIZATION, self.authorization.clone())
                .body(())
                .map_err(|_| ClientError::Configuration)?;
            let mut stream = sender
                .send_request(crate::channel_binding::attach(binding.as_ref(), request)?)
                .await
                .map_err(|_| ClientError::Http3)?;
            let response = stream
                .recv_response()
                .await
                .map_err(|_| ClientError::Http3)?;
            let (tx, rx) = stream.split();
            (response, tx, rx)
        };
        crate::diag!(
            Trace,
            "client.h3",
            "response_received",
            "op" = Value::Count(operation),
            "status" = Value::Count(u64::from(response.status().as_u16()))
        );
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ClientError::Unauthorized);
            }
            other => return Err(ClientError::Rejected(other.as_u16())),
        }

        let mut decoder = Incoming::default();
        let mut state = Session::new(Role::Client);
        let hello = Frame::Hello {
            version: protocol::VERSION,
            capabilities: 0,
        };
        state
            .apply(Direction::Send, &hello)
            .map_err(|_| ClientError::Protocol)?;
        send(&mut tx, &hello).await?;
        let ack = decoder.next(&mut rx).await?.ok_or(ClientError::Protocol)?;
        state
            .apply(Direction::Receive, &ack)
            .map_err(|_| ClientError::Protocol)?;
        crate::diag!(
            Trace,
            "client.h3",
            "hello_ack_received",
            "op" = Value::Count(operation)
        );
        if !matches!(ack, Frame::HelloAck { .. }) {
            return Err(ClientError::Protocol);
        }
        state
            .apply(Direction::Send, &open)
            .map_err(|_| ClientError::Protocol)?;
        send(&mut tx, &open).await?;
        let answer = decoder.next(&mut rx).await?.ok_or(ClientError::Protocol)?;
        state
            .apply(Direction::Receive, &answer)
            .map_err(|_| ClientError::Protocol)?;
        match answer {
            Frame::OpenOk if state.tunnel_open() => Ok(H3Tunnel {
                operation,
                tx,
                rx,
                decoder,
                state,
                _driver: driver,
                _endpoint: endpoint,
            }),
            Frame::OpenError(code) => {
                crate::diag!(
                    Warn,
                    "client.h3",
                    "remote_open_refused",
                    "op" = Value::Count(operation),
                    "code" = Value::Count(code as u64)
                );
                Err(ClientError::Open(code))
            }
            _ => Err(ClientError::Protocol),
        }
    }
}

fn quic_error(error: QuicError) -> ClientError {
    match error {
        QuicError::Configuration => ClientError::Configuration,
        QuicError::Bind => ClientError::Io,
        QuicError::Timeout => ClientError::Timeout,
        QuicError::Unreachable => ClientError::QuicUnreachable,
        QuicError::Handshake | QuicError::Alpn => ClientError::Tls,
        QuicError::CongestionController => ClientError::Http3,
    }
}

struct Driver(JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A tunnel owns one dedicated verified QUIC connection and the H3 driver.
/// Its constructor is private and reachable only after valid OPEN_OK.
pub struct H3Tunnel {
    operation: u64,
    tx: Tx,
    rx: Rx,
    decoder: Incoming,
    state: Session,
    _driver: Driver,
    _endpoint: ObservedEndpoint,
}

impl H3Tunnel {
    pub async fn relay<S>(mut self, local: S) -> Result<(), ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let operation = self.operation;
        crate::diag!(
            Debug,
            "client.h3",
            "relay_begin",
            "op" = Value::Count(operation)
        );
        let (mut read, mut write) = tokio::io::split(local);
        let tx = &mut self.tx;
        let rx = &mut self.rx;
        let decoder = &mut self.decoder;
        let mut upload_state = self.state.clone();
        let mut download_state = self.state.clone();
        let activity = crate::relay_liveness::Activity::new();
        let (upload_done, upload_finished) = tokio::sync::oneshot::channel();
        let upload = async {
            let mut buffer = [0; 4096];
            loop {
                let n = read.read(&mut buffer).await.map_err(|_| ClientError::Io)?;
                let frame = if n == 0 {
                    Frame::Fin
                } else {
                    Frame::Data(buffer[..n].to_vec())
                };
                crate::diag!(
                    Trace,
                    "client.h3",
                    "upload_frame",
                    "op" = Value::Count(operation),
                    "bytes" = Value::Count(n as u64),
                    "fin" = Value::Flag(n == 0)
                );
                upload_state
                    .apply(Direction::Send, &frame)
                    .map_err(|_| ClientError::Protocol)?;
                send(tx, &frame).await?;
                if n == 0 {
                    timeout(IO_TIMEOUT, tx.finish())
                        .await
                        .map_err(|_| ClientError::Timeout)?
                        .map_err(|_| ClientError::Http3)?;
                    activity.fin();
                    let _ = upload_done.send(());
                    return Ok::<(), ClientError>(());
                }
                activity.data(n);
            }
        };
        let download = async {
            loop {
                let frame = decoder.next(rx).await?.ok_or(ClientError::Protocol)?;
                download_state
                    .apply(Direction::Receive, &frame)
                    .map_err(|_| ClientError::Protocol)?;
                match frame {
                    Frame::Data(data) => {
                        crate::diag!(
                            Trace,
                            "client.h3",
                            "download_frame",
                            "op" = Value::Count(operation),
                            "bytes" = Value::Count(data.len() as u64)
                        );
                        timeout(IO_TIMEOUT, write.write_all(&data))
                            .await
                            .map_err(|_| ClientError::Timeout)?
                            .map_err(|_| ClientError::Io)?;
                        activity.data(data.len());
                    }
                    Frame::Fin => {
                        crate::diag!(
                            Debug,
                            "client.h3",
                            "download_fin",
                            "op" = Value::Count(operation)
                        );
                        timeout(IO_TIMEOUT, write.shutdown())
                            .await
                            .map_err(|_| ClientError::Timeout)?
                            .map_err(|_| ClientError::Io)?;
                        activity.fin();
                        break;
                    }
                    Frame::Abort(code) => return Err(ClientError::Open(code)),
                    _ => return Err(ClientError::Protocol),
                }
            }
            if crate::relay_liveness::receive_tail(
                decoder.next(rx),
                upload_finished,
                ClientError::Timeout,
            )
            .await?
            .is_some()
            {
                return Err(ClientError::Protocol);
            }
            Ok::<(), ClientError>(())
        };
        if let Err(error) = activity.run(upload, download, ClientError::Timeout).await {
            crate::diag!(
                Warn,
                "client.h3",
                "relay_failed",
                "op" = Value::Count(operation),
                "reason" = Value::Label(error_kind(&error))
            );
            return Err(error);
        }
        crate::diag!(
            Debug,
            "client.h3",
            "relay_completed",
            "op" = Value::Count(operation)
        );
        self.state
            .apply(Direction::Send, &Frame::Fin)
            .map_err(|_| ClientError::Protocol)?;
        self.state
            .apply(Direction::Receive, &Frame::Fin)
            .map_err(|_| ClientError::Protocol)?;
        self.state.finish().map_err(|_| ClientError::Protocol)
    }
}

#[derive(Default)]
struct Incoming {
    decoder: Decoder,
    ready: VecDeque<Frame>,
}

impl Incoming {
    async fn next<S: quic::RecvStream>(
        &mut self,
        stream: &mut RequestStream<S, Bytes>,
    ) -> Result<Option<Frame>, ClientError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let data = stream.recv_data().await.map_err(|_| ClientError::Http3)?;
            let Some(mut data) = data else {
                self.decoder.finish().map_err(|_| ClientError::Protocol)?;
                let trailers = timeout(IO_TIMEOUT, stream.recv_trailers())
                    .await
                    .map_err(|_| ClientError::Timeout)?
                    .map_err(|_| ClientError::Http3)?;
                if trailers.is_some() {
                    return Err(ClientError::Protocol);
                }
                return Ok(None);
            };
            while data.has_remaining() {
                let n = data.remaining().min(4096);
                let bytes = data.copy_to_bytes(n);
                self.ready.extend(
                    self.decoder
                        .feed(&bytes)
                        .map_err(|_| ClientError::Protocol)?,
                );
            }
        }
    }
}

async fn send<S: quic::SendStream<Bytes>>(
    stream: &mut RequestStream<S, Bytes>,
    frame: &Frame,
) -> Result<(), ClientError> {
    let bytes = Bytes::from(protocol::encode(frame).map_err(|_| ClientError::Protocol)?);
    timeout(IO_TIMEOUT, stream.send_data(bytes))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|_| ClientError::Http3)
}
