//! One immutable admission table per inbound, published atomically to TCP
//! and QUIC. Already established connections own their TLS and HTTP state.
//! Neither health refresh nor signer retirement resets replay windows.
#![forbid(unsafe_code)]

use crate::{
    descriptor::Verified,
    identity_publication::PublishedIdentity,
    identity_tls::Branch,
    reality_admission::{Context, ReplayGuard},
    reality_generation::Lease,
    server::{ServerContext, ServerError},
};
use std::sync::{Arc, RwLock};
use tokio_rustls::TlsAcceptor;

pub(crate) struct Route {
    lease: Arc<Lease>,
    successor: bool,
    reference: usize,
    pub(crate) context: Arc<ServerContext>,
    pub(crate) tcp: TlsAcceptor,
    pub(crate) quic: Option<Arc<quinn::ServerConfig>>,
}
impl Route {
    fn material(&self) -> &PublishedIdentity {
        let p = self.lease.publication();
        if self.successor { p.next().expect("prepared successor") } else { p.active() }
    }
    pub(crate) fn generation_id(&self)->([u8;32],u64){
        (self.lease.publication().snapshot_sha256(),self.lease.status().health_revision)
    }
    pub(crate) fn current(&self, now: u64) -> bool {
        let v = self.material().verified();
        v.check_time(now).is_ok() && self.lease.health().validate_active(v.descriptor(),now).is_ok()
    }
    fn matches(&self, guard: &ReplayGuard, branch: Branch, hello: &[u8], now: u64) -> bool {
        if !self.current(now) || (branch == Branch::H3 && self.quic.is_none()) { return false; }
        let value = self.material().verified();
        let d = value.descriptor();
        let Some(reference) = d.references.get(self.reference) else { return false; };
        guard.admit(&self.lease.admission(), &Context {
            scope: &d.scope, identity: value.signer(), reference: &reference.server_name, branch,
        }, hello, now).is_ok()
    }
}

pub(crate) struct Generation {
    pub(crate) lease: Arc<Lease>,
    routes: Vec<Arc<Route>>,
}
impl Generation {
    fn prepare(lease: Arc<Lease>, base: &ServerContext, handshake: &Arc<ReplayGuard>, now: u64)
        -> Result<Self, ServerError> {
        let publication = lease.publication();
        let mut routes = Vec::new();
        for (successor, material) in [(false, Some(publication.active())), (true, publication.next())] {
            let Some(material) = material else { continue; };
            let value = material.verified();
            if value.check_time(now).is_err() { continue; }
            lease.health().validate_active(value.descriptor(),now).map_err(|_| ServerError::Config)?;
            let d = value.descriptor();
            let next = if successor { None } else {
                publication.next().map(|m| Arc::<str>::from(m.signed()))
            };
            let context = Arc::new(base.fork_identity(value,Arc::from(material.signed()),next)?);
            // Active reference first. Other signed, operator-approved SNI
            // values allow authenticated clients with a previously signed
            // descriptor to reconnect. An invalid marker still uses only
            // the active pinned relay destination.
            // This lets a client with a still-valid pre-failover descriptor
            // authenticate and retrieve the new signed active index.
            let active = usize::from(d.active_reference);
            for index in std::iter::once(active).chain((0..d.references.len()).filter(|i| *i != active)) {
                let reference = &d.references[index];
                let mut tls = material.identity().server_tls(&reference.server_name,Branch::H2)
                    .map_err(|_| ServerError::Tls)?;
                tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
                let tcp = TlsAcceptor::from(Arc::new(tls));
                let quic = if d.h3 && reference.h3 {
                    let tls = crate::identity_tls::checked_server_tls_for_reference(
                        material.identity(),value,Branch::H3,lease.admission(),handshake.clone(),index)
                        .map_err(|_| ServerError::Tls)?;
                    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
                        .map_err(|_| ServerError::Tls)?;
                    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
                    cfg.transport_config(crate::quic_transport::transport_config());
                    cfg.migration(false);
                    Some(Arc::new(cfg))
                } else { None };
                routes.push(Arc::new(Route { lease:lease.clone(),successor,reference:index,context:context.clone(),tcp,quic }));
            }
        }
        if routes.is_empty() { return Err(ServerError::Config); }
        Ok(Self { lease,routes })
    }
    pub(crate) fn select(&self, guard: &ReplayGuard, branch: Branch, hello: &[u8], now: u64) -> Option<Arc<Route>> {
        self.routes.iter().find(|route| route.matches(guard,branch,hello,now)).cloned()
    }
    pub(crate) fn relay_value(&self,now:u64)->Option<&Verified> {
        relay_value(&self.lease,now)
    }
    pub(crate) fn default_quic(&self) -> Option<quinn::ServerConfig> {
        self.routes.iter().find_map(|r|r.quic.as_ref().map(|cfg|(**cfg).clone()))
    }
}

pub(crate) fn relay_value(lease:&Lease,now:u64)->Option<&Verified> {
    let p=lease.publication();
    [Some(p.active()),p.next()].into_iter().flatten().map(|m|m.verified()).find(|v|
        v.check_time(now).is_ok() && lease.health().validate_active(v.descriptor(),now).is_ok())
}

pub(crate) struct Live {
    base: Arc<ServerContext>,
    slot: RwLock<Option<Arc<Generation>>>,
    // A routing replay window is shared by every generation. The QUIC TLS
    // boundary has a separate equally long-lived replay window.
    pub(crate) guard: Arc<ReplayGuard>,
    handshake: Arc<ReplayGuard>,
    h3: bool,
}
impl Live {
    pub(crate) fn new(lease:Arc<Lease>,base:Arc<ServerContext>,now:u64)->Result<Arc<Self>,ServerError>{
        Self::with_guard_start(lease,base,now,now)
    }
    pub(crate) fn with_guard_start(lease:Arc<Lease>,base:Arc<ServerContext>,now:u64,guard_start:u64)->Result<Arc<Self>,ServerError>{
        let guard=Arc::new(ReplayGuard::new(65536,guard_start).map_err(|_|ServerError::Config)?);
        let handshake=Arc::new(ReplayGuard::new(65536,guard_start).map_err(|_|ServerError::Config)?);
        let initial=Arc::new(Generation::prepare(lease,&base,&handshake,now)?);
        let h3=initial.default_quic().is_some();
        Ok(Arc::new(Self{base,slot:RwLock::new(Some(initial)),guard,handshake,h3}))
    }
    pub(crate) fn current(&self)->Option<Arc<Generation>>{
        self.slot.read().ok()?.clone()
    }
    pub(crate) fn status(&self)->Option<crate::reality_generation::Status>{
        let now=crate::reference_health::unix_now().ok()?;
        let generation=self.current()?;
        if generation.relay_value(now).is_none(){return None;}
        let mut status=generation.lease.status();
        let p=generation.lease.publication();
        status.active_usable=p.active().verified().check_time(now).is_ok();
        status.successor_usable=p.next().is_some_and(|m|m.verified().check_time(now).is_ok());
        status.overlap=status.active_usable&&status.successor_usable;
        if !status.active_usable{
            status.revision=p.next()?.verified().descriptor().revision;
        }
        Some(status)
    }
    pub(crate) fn publish(&self,lease:Arc<Lease>,now:u64)->Result<(),ServerError>{
        if self.current().as_ref().is_some_and(|old| {
            let a=old.lease.status();let b=lease.status();
            a.generation==b.generation && a.health_revision==b.health_revision &&
                a.active_usable==b.active_usable && a.successor_usable==b.successor_usable
        }) { return Ok(()); }
        let candidate=Arc::new(Generation::prepare(lease,&self.base,&self.handshake,now)?);
        // A transport policy change requires structural Apply, not an
        // implicit rebind. The publication rotation/failover contract retains modes.
        if candidate.default_quic().is_some()!=self.h3 { return Err(ServerError::Config); }
        *self.slot.write().map_err(|_|ServerError::Config)?=Some(candidate);
        Ok(())
    }
    pub(crate) fn suspend(&self){
        if let Ok(mut slot)=self.slot.write(){*slot=None;}
    }
}
