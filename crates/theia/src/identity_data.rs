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

pub(crate) fn validate_descriptor_headers(headers: &http::HeaderMap) -> Result<usize, ClientError> {
    use http::header;
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers.get(header::CONTENT_TYPE).map(|v| v.as_bytes())
            != Some(b"application/octet-stream".as_slice())
        || headers.get_all(header::CONTENT_LENGTH).iter().count() != 1
        || headers.contains_key(header::CONTENT_ENCODING)
    {
        return Err(ClientError::Protocol);
    }
    let raw = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .ok_or(ClientError::Protocol)?;
    let len: usize = raw.parse().map_err(|_| ClientError::Protocol)?;
    if !(1..=descriptor::MAX_DOCUMENT).contains(&len) || raw != len.to_string() {
        return Err(ClientError::Protocol);
    }
    Ok(len)
}

pub(crate) fn append_descriptor(
    bytes: &mut Vec<u8>,
    chunk: &[u8],
    expected: usize,
) -> Result<(), ClientError> {
    if expected > descriptor::MAX_DOCUMENT
        || bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|len| len > expected)
    {
        return Err(ClientError::Protocol);
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

pub(crate) fn finish_descriptor(bytes: Vec<u8>, expected: usize) -> Result<String, ClientError> {
    if bytes.len() != expected {
        return Err(ClientError::Protocol);
    }
    String::from_utf8(bytes).map_err(|_| ClientError::Protocol)
}

fn now() -> Result<u64, ClientError> {
    crate::reference_health::unix_now().map_err(|_| ClientError::Configuration)
}

/// Local fixture controller. It can renew only the original identity's
/// compatible signed descriptor; it cannot activate another listener.
pub struct FixtureControl(Arc<ServerContext>);

impl FixtureControl {
    pub fn renew(&self, document: &str, expected: [u8;32]) -> Result<u64, ServerError> {
        self.0.renew_identity_fixture(document, expected)
    }
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
        Self::build(tcp, identity, signed, inbound, users, policy, None)
    }

    /// Exercise admission and identity verification with real native
    /// carriers, without contacting an external reference.
    pub fn new_admitted(
        tcp: TcpListener, identity: &Identity, signed: &str,
        inbound: &Inbound, users: &[User], policy: &ServerPolicy,
        admission: (Arc<crate::reality_admission::Secret>, Arc<crate::reality_admission::ReplayGuard>),
    ) -> Result<Self, ServerError> {
        Self::build(tcp, identity, signed, inbound, users, policy, Some(admission))
    }

    fn build(
        tcp: TcpListener, identity: &Identity, signed: &str,
        inbound: &Inbound, users: &[User], policy: &ServerPolicy,
        admission: Option<(Arc<crate::reality_admission::Secret>, Arc<crate::reality_admission::ReplayGuard>)>,
    ) -> Result<Self, ServerError> {
        let local = tcp.local_addr().map_err(|_| ServerError::Io)?;
        if !local.ip().is_loopback()
            || identity.scope().endpoint != local.to_string()
            || identity.scope().inbound != inbound.id
        {
            return Err(ServerError::Config);
        }
        let anchor = Anchor::new(
            identity.scope().clone(),
            identity.public_key(),
            1,
            ClientPolicy {
                transport: crate::config::Transport::Auto,
                xhttp_mode: crate::config::XhttpMode::Auto,
            },
        )
        .map_err(|_| ServerError::Config)?;
        let value = descriptor::verify(signed, &anchor).map_err(|_| ServerError::Config)?;
        let now = crate::reference_health::unix_now().map_err(|_| ServerError::Config)?;
        value.check_time(now).map_err(|_| ServerError::Config)?;
        let context = Arc::new(ServerContext::identity_fixture(
            inbound,
            users,
            policy,
            &value,
            Arc::from(signed),
        )?);
        let tls = match &admission {
            Some((secret, guard)) => crate::identity_tls::checked_server_tls(identity, &value, Branch::H2, secret.clone(), guard.clone()),
            None => identity.server_tls("localhost", Branch::H2),
        }.map_err(|_| ServerError::Tls)?;
        let h2 = TlsAcceptor::from(Arc::new(tls));
        let h3 = if value.descriptor().h3 {
            Some(
                quinn::Endpoint::server(
                    match &admission {
                        Some((secret, guard)) => crate::identity_tls::checked_quic_server(identity, &value, secret.clone(), guard.clone()),
                        None => identity.quic_server("localhost"),
                    }.map_err(|_| ServerError::Tls)?,
                    local,
                )
                .map_err(|_| ServerError::Io)?,
            )
        } else {
            None
        };
        Ok(Self {
            tcp,
            h2,
            h3,
            context,
        })
    }

    pub fn control(&self) -> FixtureControl {
        FixtureControl(self.context.clone())
    }

    pub async fn serve(self) -> Result<(), ServerError> {
        let mut tasks = JoinSet::new();
        tasks.spawn(crate::server::serve(
            self.tcp,
            self.h2,
            self.context.clone(),
        ));
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
    H3(Box<H3Tunnel>),
}

impl FixtureTunnel {
    pub async fn relay<S>(self, socket: S) -> Result<(), ClientError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        match self {
            Self::H2(tunnel) => tunnel.relay(socket).await,
            Self::H3(tunnel) => (*tunnel).relay(socket).await,
        }
    }
}

impl FixtureClient {
    /// Verified comes from the independent Anchor / persistent Store, not
    /// from a trust-on-first-use peer. No credentials are sent at construction.
    pub fn new(
        remote: SocketAddr,
        token: &str,
        value: Verified,
        branch: Branch,
    ) -> Result<Self, ClientError> {
        value.check_time(now()?).map_err(|_| ClientError::Tls)?;
        let carrier = match branch {
            Branch::H2 => Carrier::H2(H2Client::identity_fixture(remote, token, &value)?),
            Branch::H3 => Carrier::H3(H3Client::identity_fixture(remote, token, &value)?),
        };
        Ok(Self { carrier, value })
    }

    pub fn new_admitted(
        remote: SocketAddr, token: &str, value: Verified, branch: Branch,
        secret: Arc<crate::reality_admission::Secret>,
    ) -> Result<Self, ClientError> {
        value.check_time(now()?).map_err(|_| ClientError::Tls)?;
        let carrier = match branch {
            Branch::H2 => Carrier::H2(H2Client::admitted_fixture(remote, token, &value, secret)?),
            Branch::H3 => Carrier::H3(H3Client::admitted_fixture(remote, token, &value, secret)?),
        };
        Ok(Self { carrier, value })
    }

    pub async fn open(&self, target: Address, port: u16) -> Result<FixtureTunnel, ClientError> {
        self.value
            .check_time(now()?)
            .map_err(|_| ClientError::Tls)?;
        match &self.carrier {
            Carrier::H2(client) => client.open(target, port).await.map(FixtureTunnel::H2),
            Carrier::H3(client) => client
                .open(target, port)
                .await
                .map(|tunnel| FixtureTunnel::H3(Box::new(tunnel))),
        }
    }

    /// A received document is never automatically trusted or applied.
    /// The durable Store checks signature, scope, current key, revision,
    /// expiry and local mode restrictions before atomic replacement.
    pub async fn refresh(
        &self,
        store: &descriptor::Store,
    ) -> Result<descriptor::Change, ClientError> {
        self.value
            .check_time(now()?)
            .map_err(|_| ClientError::Tls)?;
        let raw = match &self.carrier {
            Carrier::H2(client) => client.fetch_identity_descriptor().await?,
            Carrier::H3(client) => client.fetch_identity_descriptor().await?,
        };
        let timestamp = now()?;
        store
            .update_matching(&raw, &self.value, timestamp)
            .map_err(|_| ClientError::Tls)
    }
}


/// Persistent trust-backed application-plane client for controlled loopback
/// fixtures. Re-read the verified store before every new logical operation.
/// A new signed revision (or explicitly promoted signer) replaces the
/// carrier/pool as one generation; outstanding tunnels own their leases.
pub struct ManagedFixtureClient {
    remote: SocketAddr,
    branch: Branch,
    token: zeroize::Zeroizing<String>,
    store: descriptor::Store,
    current: tokio::sync::Mutex<Option<Arc<FixtureClient>>>,
}

impl ManagedFixtureClient {
    pub fn new(
        remote: SocketAddr,
        branch: Branch,
        token: &str,
        store: descriptor::Store,
    ) -> Result<Self, ClientError> {
        if !remote.ip().is_loopback() {
            return Err(ClientError::Configuration);
        }
        let value = store.load(now()?).map_err(|_| ClientError::Tls)?;
        let first = Self::build(remote, token, value, branch)?;
        Ok(Self {
            remote,
            branch,
            token: zeroize::Zeroizing::new(token.to_owned()),
            store,
            current: tokio::sync::Mutex::new(Some(Arc::new(first))),
        })
    }

    fn build(remote: SocketAddr, token: &str, value: Verified, branch: Branch) -> Result<FixtureClient, ClientError> {
        let mut client = FixtureClient::new(remote, token, value, branch)?;
        client.carrier = match client.carrier {
            Carrier::H2(h2) => Carrier::H2(h2.with_connection_pool()),
            Carrier::H3(h3) => Carrier::H3(h3.with_connection_pool()),
        };
        Ok(client)
    }

    async fn generation(&self) -> Result<Arc<FixtureClient>, ClientError> {
        let mut slot = self.current.lock().await;
        let value = self.store.load(now()?).map_err(|_| ClientError::Tls)?;
        if let Some(previous) = slot.as_ref() {
            let old = &previous.value;
            if old.descriptor().scope != value.descriptor().scope
                || value.descriptor().revision < old.descriptor().revision
            {
                return Err(ClientError::Tls);
            }
            if old.signer() == value.signer() {
                if old.compare(&value).map_err(|_| ClientError::Tls)? == descriptor::Change::Unchanged {
                    return Ok(previous.clone());
                }
            } else if value.descriptor().revision <= old.descriptor().revision {
                return Err(ClientError::Tls);
            }
        }
        // No fallback to the previous carrier on policy, key, expiry or
        // construction errors. A separately promoted signer must already be
        // authenticated by the full persisted Store history.
        let next = Arc::new(Self::build(self.remote, &self.token, value, self.branch)?);
        *slot = Some(next.clone());
        Ok(next)
    }

    pub async fn revision(&self) -> Result<u64, ClientError> {
        Ok(self.generation().await?.value.descriptor().revision)
    }

    pub async fn open(&self, target: Address, port: u16) -> Result<FixtureTunnel, ClientError> {
        self.generation().await?.open(target, port).await
    }

    pub async fn refresh(&self) -> Result<descriptor::Change, ClientError> {
        let current = self.generation().await?;
        let change = current.refresh(&self.store).await?;
        // Rebuild before any subsequent new connection. If another local
        // operation superseded the update, the latest verified Store wins.
        self.generation().await?;
        Ok(change)
    }
}
