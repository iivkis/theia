//! Identity-authenticated F-18 application-plane composition.
//!
//! This implementation is deliberately restricted to loopback controlled
//! fixtures. It exercises existing H2/H3 transport, bearer/grants, XHTTP
//! routing, TCP relay and signed descriptor delivery without enabling the
//! not-yet-integrated public REALITY admission or reference relay.
#![forbid(unsafe_code)]

use crate::{
    client::{ClientError, H2Client, Tunnel},
    config::{Inbound, ServerPolicy, User},
    descriptor::{self, Anchor, ClientPolicy, Verified},
    h3_client::{H3Client, H3Tunnel},
    identity_tls::{Branch, Identity},
    protocol::Address,
    server::{ServerContext, ServerError},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_rustls::TlsAcceptor;

pub(crate) fn validate_descriptor_headers(headers: &http::HeaderMap) -> Result<(), ClientError> {
    use http::header;
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers.get(header::CONTENT_TYPE).map(|v| v.as_bytes()) != Some(b"application/octet-stream".as_slice())
        || headers.get_all(header::CONTENT_LENGTH).iter().count() != 1
        || !headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|n| n > 0 && n <= descriptor::MAX_DOCUMENT)
    {
        return Err(ClientError::Protocol);
    }
    Ok(())
}

pub(crate) fn append_descriptor(bytes: &mut Vec<u8>, chunk: &[u8]) -> Result<(), ClientError> {
    if chunk.len() > descriptor::MAX_DOCUMENT - bytes.len() {
        return Err(ClientError::Protocol);
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

fn now() -> Result<u64, ClientError> {
    crate::reference_health::unix_now().map_err(|_| ClientError::Configuration)
}

pub struct PreparedFixture {
    tcp: TcpListener,
    h2: TlsAcceptor,
    h3: Option<quinn::Endpoint>,
    context: Arc<ServerContext>,
}

impl PreparedFixture {
    /// Only a prebound loopback TCP listener is allowed. No external
    /// reference is contacted; the fixture name is localhost, not a third
    /// party's domain. The identity and signed descriptor must match exactly.
    pub fn new(
        tcp: TcpListener,
        identity: &Identity,
        signed: &str,
        inbound: &Inbound,
        users: &[User],
        policy: &ServerPolicy,
    ) -> Result<Self, ServerError> {
        let local = tcp.local_addr().map_err(|_| ServerError::Io)?;
        if !local.ip().is_loopback() || identity.scope().endpoint != local.to_string()
            || identity.scope().inbound != inbound.id
        {
            return Err(ServerError::Config);
        }
        let anchor = Anchor::new(identity.scope().clone(), identity.public_key(), 1,
            ClientPolicy { transport: crate::config::Transport::Auto, xhttp_mode: crate::config::XhttpMode::Auto })
            .map_err(|_| ServerError::Config)?;
        let value = descriptor::verify(signed, &anchor).map_err(|_| ServerError::Config)?;
        let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
        value.check_time(now).map_err(|_| ServerError::Config)?;
        let context = Arc::new(ServerContext::identity_fixture(inbound, users, policy, &value, Arc::from(signed))?);
        let tls = identity.server_tls("localhost", Branch::H2).map_err(|_| ServerError::Tls)?;
        let h2 = TlsAcceptor::from(Arc::new(tls));
        let h3 = if value.descriptor().h3 {
            Some(quinn::Endpoint::server(
                identity.quic_server("localhost").map_err(|_| ServerError::Tls)?,
                local,
            ).map_err(|_| ServerError::Io)?)
        } else {
            None
        };
        Ok(Self { tcp, h2, h3, context })
    }

    pub async fn serve(self) -> Result<(), ServerError> {
        let mut tasks = JoinSet::new();
        tasks.spawn(crate::server::serve(self.tcp, self.h2, self.context.clone()));
        if let Some(h3) = self.h3 {
            tasks.spawn(crate::h3_server::serve(h3, self.context));
        }
        match tasks.join_next().await {
            Some(Ok(result)) => result,
            _ => Err(ServerError::Io),
        }
    }
}

enum Carrier {
    H2(H2Client),
    H3(H3Client),
}

pub struct FixtureClient {
    carrier: Carrier,
    value: Verified,
}

pub enum FixtureTunnel {
    H2(Tunnel),
    H3(H3Tunnel),
}

impl FixtureTunnel {
    pub async fn relay<S>(self, socket: S) -> Result<(), ClientError>
    where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        match self {
            Self::H2(tunnel) => tunnel.relay(socket).await,
            Self::H3(tunnel) => tunnel.relay(socket).await,
        }
    }
}

impl FixtureClient {
    /// Verified comes from the independent Anchor / persistent Store, not
    /// from a trust-on-first-use peer. No credentials are sent at construction.
    pub fn new(remote: SocketAddr, token: &str, value: Verified, branch: Branch) -> Result<Self, ClientError> {
        value.check_time(now()?).map_err(|_| ClientError::Tls)?;
        let carrier = match branch {
            Branch::H2 => Carrier::H2(H2Client::identity_fixture(remote, token, &value)?),
            Branch::H3 => Carrier::H3(H3Client::identity_fixture(remote, token, &value)?),
        };
        Ok(Self { carrier, value })
    }

    pub async fn open(&self, target: Address, port: u16) -> Result<FixtureTunnel, ClientError> {
        self.value.check_time(now()?).map_err(|_| ClientError::Tls)?;
        match &self.carrier {
            Carrier::H2(client) => client.open(target, port).await.map(FixtureTunnel::H2),
            Carrier::H3(client) => client.open(target, port).await.map(FixtureTunnel::H3),
        }
    }

    /// A received document is never automatically trusted or applied.
    /// The durable Store checks signature, scope, current key, revision,
    /// expiry and local mode restrictions before atomic replacement.
    pub async fn refresh(&self, store: &descriptor::Store) -> Result<descriptor::Change, ClientError> {
        self.value.check_time(now()?).map_err(|_| ClientError::Tls)?;
        let raw = match &self.carrier {
            Carrier::H2(client) => client.fetch_identity_descriptor().await?,
            Carrier::H3(client) => client.fetch_identity_descriptor().await?,
        };
        let timestamp = now()?;
        let previous = store.load(timestamp).map_err(|_| ClientError::Tls)?;
        if previous.descriptor().scope != self.value.descriptor().scope
            || previous.signer() != self.value.signer()
            || previous.descriptor().revision != self.value.descriptor().revision
        {
            return Err(ClientError::Tls);
        }
        self.value.compare(&previous).map_err(|_| ClientError::Tls)?;
        store.update_at(&raw, previous.descriptor().revision, timestamp).map_err(|_| ClientError::Tls)
    }
}
