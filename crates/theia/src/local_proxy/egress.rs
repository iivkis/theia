//! Unified policy classification, protected DNS and per-flow egress selection.
use super::{Carrier, DpiRoute, ProxyTunnel, RoutedTcp, RoutedUdp};
use crate::{
    client::ClientError,
    protocol::{Address, ErrorCode},
    routing::{
        client_state::{self, Cache},
        snapshot::Snapshot,
        Action,
    },
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

struct RoutePlan {
    snapshot: Arc<Snapshot>,
    action: Action,
    pinned: Option<Vec<IpAddr>>,
    authorization: crate::routing::policy_lease::PolicyLease,
}

async fn route_decision(
    carrier: &Carrier,
    cache: &Cache,
    address: &Address,
) -> Result<RoutePlan, ClientError> {
    let snapshot = cache.get(|known| carrier.fetch_routing(known)).await?;
    let authorization = cache.policy.pin(snapshot.digest())?;
    let policy = snapshot.policy();
    let denied = || ClientError::Open(ErrorCode::PolicyDenied);
    use crate::routing::Evidence;
    let mut pinned = None;
    let action = match address {
        Address::V4(ip) => policy
            .classify(
                Evidence::Absent,
                Evidence::Known(IpAddr::V4(Ipv4Addr::from(*ip))),
            )
            .map_err(|_| denied())?
            .action()
            .ok_or_else(denied)?,
        Address::V6(ip) => policy
            .classify(
                Evidence::Absent,
                Evidence::Known(IpAddr::V6(Ipv6Addr::from(*ip))),
            )
            .map_err(|_| denied())?
            .action()
            .ok_or_else(denied)?,
        Address::Dns(name) => match policy
            .classify(Evidence::Known(name), Evidence::Unknown)
            .map_err(|_| denied())?
            .action()
        {
            Some(action) => action,
            None => {
                // Resolve only over the verified control channel when an IP
                // rule can precede the domain decision. Never locally resolve
                // a potentially proxied hostname.
                let ips = carrier.resolve_routing(name, snapshot.digest()).await?;
                let mut action = None;
                for ip in &ips {
                    let selected = policy
                        .classify(Evidence::Known(name), Evidence::Known(*ip))
                        .map_err(|_| denied())?
                        .action()
                        .ok_or_else(denied)?;
                    if action.is_some_and(|old| old != selected) {
                        // Mixed route decisions are ambiguous; do not silently
                        // downgrade to direct or proxy one of the blocked IPs.
                        action = Some(Action::Blocked);
                        break;
                    }
                    action = Some(selected);
                }
                pinned = Some(ips);
                action.ok_or_else(denied)?
            }
        },
    };
    // DNS preflight may have awaited network I/O; never return a superseded
    // policy as authorization to initiate an egress.
    authorization.check()?;
    Ok(RoutePlan {
        snapshot,
        action,
        pinned,
        authorization,
    })
}

/// Protocol-specific inputs do not own routing or authorization.
#[derive(Clone, Copy)]
enum EgressRequest<'a> {
    Tcp {
        allow_dpi: bool,
    },
    Udp {
        candidate: &'a crate::routing::dpi::udp::Candidate,
        first: &'a [u8],
        observed: &'a Arc<std::sync::atomic::AtomicU8>,
    },
}
impl EgressRequest<'_> {
    fn protocol(self) -> crate::routing::flow::Protocol {
        match self {
            Self::Tcp { .. } => crate::routing::flow::Protocol::Tcp,
            Self::Udp { .. } => crate::routing::flow::Protocol::Udp,
        }
    }
    async fn direct(
        self,
        address: Address,
        port: u16,
        pinned: Option<Vec<IpAddr>>,
    ) -> Result<RoutedEgress, ClientError> {
        match self {
            Self::Tcp { .. } => Ok(RoutedEgress::Tcp(ProxyTunnel::Direct(
                client_state::dial_direct(address, port, pinned).await?,
            ))),
            Self::Udp { .. } => Ok(RoutedEgress::Udp(crate::udp_relay::Tunnel::Direct(
                crate::udp_relay::direct(address, port, pinned).await?,
            ))),
        }
    }
    async fn redirect(
        self,
        carrier: &Carrier,
        address: Address,
        port: u16,
    ) -> Result<RoutedEgress, ClientError> {
        match self {
            Self::Tcp { .. } => Ok(RoutedEgress::Tcp(carrier.open(address, port).await?)),
            Self::Udp { .. } => Ok(RoutedEgress::Udp(carrier.open_udp(address, port).await?)),
        }
    }
    fn record_fallback(self) {
        use crate::routing::dpi::udp::Candidate;
        match self {
            Self::Tcp { .. } => crate::traffic::dpi_fallback_open(),
            Self::Udp { candidate, .. } => {
                crate::traffic::udp_dpi_fallback();
                if matches!(candidate, Candidate::Stun | Candidate::StunBinding) {
                    crate::traffic::udp_stun_fallback();
                }
                if matches!(candidate, Candidate::QuicV2H3(_)) {
                    crate::traffic::udp_quic_v2_fallback();
                }
            }
        }
    }
}
enum RoutedEgress {
    Tcp(ProxyTunnel),
    Udp(crate::udp_relay::Tunnel),
}

/// Preserve one exact policy lease through classification, DNS, dialing
/// and the flow table. A revoked digest republished during DNS cannot revive it.
async fn route_egress(
    carrier: &Carrier,
    cache: &Cache,
    address: Address,
    port: u16,
    request: EgressRequest<'_>,
    diagnostic_digest: Option<[u8; 32]>,
) -> Result<(RoutedEgress, crate::routing::flow::FlowLease), ClientError> {
    use crate::routing::PacketAction;
    let RoutePlan {
        snapshot,
        action,
        pinned,
        authorization,
    } = route_decision(carrier, cache, &address).await?;
    if diagnostic_digest.is_some_and(|digest| digest != snapshot.digest() || action == Action::Blocked || (action == Action::Direct && !matches!(request, EgressRequest::Tcp { allow_dpi: true }))) {
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    if action.packet_action() == PacketAction::Drop {
        crate::traffic::blocked();
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    let flow = cache.flows.begin_pinned(
        authorization.clone(),
        request.protocol(),
        address.clone(),
        port,
        action.packet_action(),
    )?;
    authorization.check()?;
    let egress = match action.packet_action() {
        PacketAction::Pass => request.direct(address, port, pinned).await?,
        PacketAction::Redirect => request.redirect(carrier, address, port).await?,
        PacketAction::Modify => {
            match open_local_modify(
                carrier,
                cache,
                &address,
                port,
                request,
                &snapshot,
                pinned,
                &authorization,
            )
            .await?
            {
                Some(local) => local,
                None => {
                    authorization.check()?;
                    let redirected = request.redirect(carrier, address, port).await?;
                    authorization.check()?;
                    request.record_fallback();
                    redirected
                }
            }
        }
        PacketAction::Drop => return Err(ClientError::Open(ErrorCode::PolicyDenied)),
    };
    authorization.check()?;
    flow.check_pending()?;
    Ok((egress, flow))
}

/// Protected resolution and all-address policy verification are shared by TCP/UDP.
/// Only transient resolver errors for an already conclusive rule permit fallback.
async fn modify_ips(
    carrier: &Carrier,
    name: &str,
    snapshot: &Snapshot,
    pinned: Option<Vec<IpAddr>>,
    authorization: &crate::routing::policy_lease::PolicyLease,
) -> Result<Vec<IpAddr>, ClientError> {
    authorization.check()?;
    let ips = match pinned {
        Some(ips) => ips,
        None => match carrier.resolve_routing(name, snapshot.digest()).await {
            Ok(ips) => ips,
            Err(ClientError::Rejected(502 | 504)) => Vec::new(),
            Err(error) => return Err(error),
        },
    };
    authorization.check()?;
    if !ips.iter().all(|ip| {
        snapshot.policy().classify(
            crate::routing::Evidence::Known(name),
            crate::routing::Evidence::Known(*ip),
        ) == Ok(crate::routing::Classification::Matched(Action::DirectDpi))
    }) {
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    Ok(ips)
}

fn udp_strategy(
    address: &Address,
    port: u16,
    candidate: &crate::routing::dpi::udp::Candidate,
    first: &[u8],
    stun_enabled: bool,
) -> Option<crate::routing::dpi::UdpStrategy> {
    use crate::quic_core::wire::Version;
    use crate::routing::dpi::{
        udp::{BindingStrategy, Candidate},
        UdpStrategy,
    };
    // The classified name must match the explicit target, and the actual
    // first datagram must be transformable. A probe alone is not consent.
    match (address, candidate) {
        (Address::Dns(name), Candidate::QuicH3(sni))
            if port == 443
                && crate::routing::domain_name(name).as_deref() == Ok(sni.as_str())
                && crate::routing::packet_modify::quic_initial_datagrams(first, sni).is_some()
                && crate::reality_quic_wire::long(first)
                    .is_some_and(|h| h.version == Version::V1.wire()) =>
        {
            Some(UdpStrategy::Quic(Version::V1))
        }
        (Address::Dns(name), Candidate::QuicV2H3(sni))
            if port == 443
                && crate::routing::domain_name(name).as_deref() == Ok(sni.as_str())
                && crate::routing::packet_modify::quic_initial_datagrams(first, sni).is_some()
                && crate::reality_quic_wire::long(first)
                    .is_some_and(|h| h.version == Version::V2.wire()) =>
        {
            Some(UdpStrategy::Quic(Version::V2))
        }
        (Address::Dns(_), Candidate::StunBinding)
            if port == 3478
                && stun_enabled
                && crate::routing::dpi::udp::prepare_binding(
                    first,
                    BindingStrategy::Fingerprint,
                )
                .is_some_and(|bytes| bytes.as_ref() != first) =>
        {
            Some(UdpStrategy::StunBinding(BindingStrategy::Fingerprint))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_local_modify(
    carrier: &Carrier,
    cache: &Cache,
    address: &Address,
    port: u16,
    request: EgressRequest<'_>,
    snapshot: &Snapshot,
    pinned: Option<Vec<IpAddr>>,
    authorization: &crate::routing::policy_lease::PolicyLease,
) -> Result<Option<RoutedEgress>, ClientError> {
    use crate::quic_core::wire::Version;
    use crate::routing::dpi::UdpStrategy;
    let Address::Dns(name) = address else {
        return Ok(None);
    };
    if !cache.dpi.enabled() {
        return Ok(None);
    }
    let strategy = match request {
        EgressRequest::Tcp { allow_dpi: true } if matches!(port, 443 | 8443) => None,
        EgressRequest::Tcp { .. } => return Ok(None),
        EgressRequest::Udp {
            candidate, first, ..
        } => {
            let Some(strategy) =
                udp_strategy(address, port, candidate, first, cache.dpi.stun_enabled())
            else {
                return Ok(None);
            };
            if !strategy.accepted_for_proxy() {
                return Ok(None);
            }
            Some(strategy)
        }
    };
    let ips = modify_ips(carrier, name, snapshot, pinned, authorization).await?;
    if ips.is_empty() {
        return Ok(None);
    }
    match (request, strategy) {
        (EgressRequest::Tcp { .. }, None) => {
            let tunnel = carrier
                .warm_during(Box::pin(cache.dpi.open_checked_pinned(
                    name,
                    port,
                    &ips,
                    authorization,
                )))
                .await?;
            authorization.check()?;
            Ok(tunnel.map(|tunnel| {
                RoutedEgress::Tcp(ProxyTunnel::Dpi(Box::new(DpiRoute {
                    tunnel,
                    observed: None,
                    carrier: carrier.clone(),
                    address: address.clone(),
                    port,
                })))
            }))
        }
        (EgressRequest::Udp { observed, .. }, Some(strategy)) => {
            let verified = carrier
                .warm_during(cache.dpi.open_proxy_udp_pinned(
                    name,
                    port,
                    &ips,
                    authorization,
                    strategy,
                ))
                .await?;
            authorization.check()?;
            let Some(verified) = verified else {
                return Ok(None);
            };
            let carrier = carrier.clone();
            let target = address.clone();
            let observed = Arc::clone(observed);
            let authorization = (*authorization).clone();
            let fallback = Box::pin(async move {
                authorization.check()?;
                let tunnel = carrier.open_udp(target, port).await?;
                authorization.check()?;
                tunnel.record_transport(&observed);
                crate::traffic::udp_dpi_fallback();
                if matches!(strategy, UdpStrategy::StunBinding(_)) {
                    crate::traffic::udp_stun_fallback();
                }
                if strategy == UdpStrategy::Quic(Version::V2) {
                    crate::traffic::udp_quic_v2_fallback();
                }
                Ok(tunnel)
            });
            Ok(Some(RoutedEgress::Udp(
                crate::udp_relay::Tunnel::VerifiedLocal(Box::new(verified), fallback),
            )))
        }
        _ => Err(ClientError::Protocol),
    }
}

pub(super) async fn routed_open(
    carrier: &Carrier,
    cache: &Cache,
    address: Address,
    port: u16,
    allow_dpi: bool,
) -> Result<RoutedTcp, ClientError> {
    let (egress, flow) = route_egress(
        carrier,
        cache,
        address,
        port,
        EgressRequest::Tcp { allow_dpi },
        None,
    )
    .await?;
    match egress {
        RoutedEgress::Tcp(tunnel) => Ok(RoutedTcp { tunnel, flow }),
        _ => Err(ClientError::Protocol),
    }
}
pub(super) async fn routed_udp(
    carrier: &Carrier,
    cache: &Cache,
    address: Address,
    port: u16,
    candidate: &crate::routing::dpi::udp::Candidate,
    first: &[u8],
    observed: &Arc<std::sync::atomic::AtomicU8>,
) -> Result<RoutedUdp, ClientError> {
    let (egress, flow) = route_egress(
        carrier,
        cache,
        address,
        port,
        EgressRequest::Udp {
            candidate,
            first,
            observed,
        },
        None,
    )
    .await?;
    match egress {
        RoutedEgress::Udp(tunnel) => Ok(RoutedUdp { tunnel, flow }),
        _ => Err(ClientError::Protocol),
    }
}

pub(super) async fn diagnostic_target(
    carrier: &Carrier, cache: &Cache, name: &str, digest: [u8; 32],
) -> Result<(Action, Vec<IpAddr>, crate::routing::policy_lease::PolicyLease), ClientError> {
    let RoutePlan { snapshot, action, pinned, authorization } =
        route_decision(carrier, cache, &Address::Dns(name.to_owned())).await?;
    if snapshot.digest() != digest {
        return Err(ClientError::Open(ErrorCode::PolicyDenied));
    }
    let ips = if action == Action::DirectDpi && cache.dpi.enabled() {
        modify_ips(carrier, name, &snapshot, pinned, &authorization).await?
    } else { Vec::new() };
    Ok((action, ips, authorization))
}

pub(super) async fn diagnostic_open(
    carrier: &Carrier, cache: &Cache, name: &str, digest: [u8; 32], allow_dpi: bool,
) -> Result<RoutedTcp, ClientError> {
    let (egress, flow) = route_egress(carrier, cache, Address::Dns(name.to_owned()), 443,
        EgressRequest::Tcp { allow_dpi }, Some(digest)).await?;
    match egress {
        RoutedEgress::Tcp(tunnel) => Ok(RoutedTcp { tunnel, flow }),
        _ => Err(ClientError::Protocol),
    }
}

/// Explicitly consented UDP application probe. A control passes Other;
/// an automatic test passes the observed production candidate and first datagram.
pub(super) async fn diagnostic_udp(
    carrier: &Carrier, cache: &Cache, name: &str, digest: [u8; 32],
    observed: &Arc<std::sync::atomic::AtomicU8>,
    candidate: &crate::routing::dpi::udp::Candidate,
    first: &[u8],
) -> Result<RoutedUdp, ClientError> {
    let (egress, flow) = route_egress(carrier, cache, Address::Dns(name.to_owned()), 443,
        EgressRequest::Udp { candidate, first, observed }, Some(digest)).await?;
    match egress {
        RoutedEgress::Udp(tunnel) => Ok(RoutedUdp { tunnel, flow }),
        _ => Err(ClientError::Protocol),
    }
}
