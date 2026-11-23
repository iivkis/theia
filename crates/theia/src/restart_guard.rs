//! M4.2g: fail-closed, read-only restart planning on the running server.
//!
//! This tests REAL TLS material and kernel TCP/UDP bind operations while
//! every live listener, session and authorization revision stays untouched.
//! Sockets are released at return, never handed to the service. A PASS does
//! NOT reserve ports or promise atomic cutover; the caller must not treat it
//! as a restart commit or a green light to stop the old server.
use crate::{
    config::{Config, ServerDocument},
    reload_preflight::{assess_reload, IdentityHash},
    server,
};
use std::{
    collections::HashSet,
    fmt,
    net::{SocketAddr, TcpListener, UdpSocket},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartVerdict {
    /// Only authorization-compatible changes; use the existing CAS Apply.
    AuthorizationOnly,
    /// All current TCP/H3 port mappings, users and quotas remain unchanged;
    /// only strict TLS PEM identity may rotate in-place on the same sockets.
    SamePortTlsReady,
    /// A currently running listener address must be reused. A zero-downtime
    /// bind-before-close transition cannot be guaranteed with this runtime.
    RequiresMaintenance,
    /// All next-generation addresses were bound together and released again.
    /// This is a probe, NOT a port reservation or completed restart.
    FreshPortsBindable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartError {
    InvalidConfig,
    InvalidTlsIdentity,
    PortUnavailable,
    ProbeBusy,
}

impl fmt::Display for RestartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("restart candidate config invalid"),
            Self::InvalidTlsIdentity => f.write_str("restart candidate TLS identity invalid"),
            Self::PortUnavailable => f.write_str("candidate TCP or UDP listener cannot be bound"),
            Self::ProbeBusy => f.write_str("another restart readiness probe is still running"),
        }
    }
}
impl std::error::Error for RestartError {}

/// Conservative overlap policy. A wildcard listener may occupy both the
/// explicit address and, on some platforms, a dual-stack IPv4/IPv6 bind.
/// False positives only request maintenance, never an unsafe cutover.
pub(crate) fn conflicts_with_active(old: SocketAddr, candidate: SocketAddr) -> bool {
    old.port() == candidate.port()
        && (old.ip() == candidate.ip()
            || old.ip().is_unspecified()
            || candidate.ip().is_unspecified())
}

/// Call only on a blocking worker with a bounded TOML document. Never return
/// the candidate's filesystem paths, tokens or PEM data over IPC.
pub(crate) fn probe(
    active: &ServerDocument,
    loaded_identities: &[IdentityHash],
    candidate: &ServerDocument,
) -> Result<RestartVerdict, RestartError> {
    // Advisory readiness is NOT a reservation, pin, or Apply. However it
    // uses the same bounded validated PEM capture as the Apply path.
    let captured =
        server::CapturedTls::capture(candidate).map_err(|_| RestartError::InvalidTlsIdentity)?;
    probe_captured(active, loaded_identities, candidate, &captured)
}

/// Restart decisions use the SAME captured bytes that will be given to the
/// actual H2/H3 builders. No second file open is permitted after operator
/// fingerprint comparison, including for same-port classification.
pub(crate) fn probe_captured(
    active: &ServerDocument,
    loaded_identities: &[IdentityHash],
    candidate: &ServerDocument,
    captured: &server::CapturedTls,
) -> Result<RestartVerdict, RestartError> {
    Config::Server(candidate.clone())
        .validate()
        .map_err(|_| RestartError::InvalidConfig)?;
    if !candidate.server.enabled {
        return Err(RestartError::InvalidConfig);
    }
    let candidate_identities = captured.identities();
    let identities_unchanged = loaded_identities.len() == candidate_identities.len()
        && active.server.inbounds.len() == candidate.server.inbounds.len()
        && active
            .server
            .inbounds
            .iter()
            .zip(&candidate.server.inbounds)
            .zip(loaded_identities)
            .zip(&candidate_identities)
            .all(|(((before, after), original), candidate_identity)| {
                before.id == after.id && original == candidate_identity
            });
    if assess_reload(active, candidate).is_ok() && identities_unchanged {
        return Ok(RestartVerdict::AuthorizationOnly);
    }
    if same_port_tls_only(active, candidate) && !identities_unchanged {
        return Ok(RestartVerdict::SamePortTlsReady);
    }

    // When ANY candidate listener overlaps ANY old listener on the same
    // transport, don't infer SO_REUSEPORT, SCM_RIGHTS or a release/rebind
    // strategy. A real supervisor/maintenance window is required.
    let mut current_tcp = HashSet::new();
    let mut current_udp = HashSet::new();
    for inbound in &active.server.inbounds {
        current_tcp.insert(
            inbound
                .h2_listen
                .parse::<SocketAddr>()
                .map_err(|_| RestartError::InvalidConfig)?,
        );
        current_udp.insert(
            inbound
                .quic_listen
                .parse::<SocketAddr>()
                .map_err(|_| RestartError::InvalidConfig)?,
        );
    }
    let mut next_tcp = Vec::new();
    let mut next_udp = Vec::new();
    for inbound in &candidate.server.inbounds {
        let tcp: SocketAddr = inbound
            .h2_listen
            .parse()
            .map_err(|_| RestartError::InvalidConfig)?;
        let udp: SocketAddr = inbound
            .quic_listen
            .parse()
            .map_err(|_| RestartError::InvalidConfig)?;
        if current_tcp
            .iter()
            .any(|old| conflicts_with_active(*old, tcp))
            || current_udp
                .iter()
                .any(|old| conflicts_with_active(*old, udp))
        {
            return Ok(RestartVerdict::RequiresMaintenance);
        }
        next_tcp.push(tcp);
        next_udp.push(udp);
    }

    // Bind ALL next-generation TCP sockets and keep them simultaneously
    // while binding ALL UDP sockets. Failures release all previously acquired
    // sockets via RAII, leaving old listeners alive and the revision intact.
    // This is deliberately a transient OS-level probe, not an acceptance of
    // any connection or a promise of future port availability.
    let mut tcp_probes = Vec::with_capacity(next_tcp.len());
    let mut udp_probes = Vec::with_capacity(next_udp.len());
    for addr in next_tcp {
        tcp_probes.push(TcpListener::bind(addr).map_err(|_| RestartError::PortUnavailable)?);
    }
    for addr in next_udp {
        udp_probes.push(UdpSocket::bind(addr).map_err(|_| RestartError::PortUnavailable)?);
    }
    drop(udp_probes);
    drop(tcp_probes);
    Ok(RestartVerdict::FreshPortsBindable)
}

/// A TLS-only in-place rotation never rebinds a TCP/UDP port, changes
/// SNI/hostname expectations, routes users differently or touches quota.
/// Compare *every* typed field and blank only the two PEM references.
/// A PEM file changed in place also qualifies when identity digests drift.
pub(crate) fn same_port_tls_only(active: &ServerDocument, candidate: &ServerDocument) -> bool {
    if active.server.inbounds.len() != candidate.server.inbounds.len() {
        return false;
    }
    let mut normalized = candidate.clone();
    for (original, normalized_inbound) in active
        .server
        .inbounds
        .iter()
        .zip(&mut normalized.server.inbounds)
    {
        normalized_inbound.tls_cert.clone_from(&original.tls_cert);
        normalized_inbound.tls_key.clone_from(&original.tls_key);
    }
    &normalized == active
}

/// Quota-only live update. Every typed TOML field except the two
/// occupancy limits must be byte-for-byte equivalent after parsing.
pub(crate) fn quota_only(active: &ServerDocument, candidate: &ServerDocument) -> bool {
    let previous = &active.server.policy;
    let updated = &candidate.server.policy;
    if previous.max_connections_total == updated.max_connections_total
        && previous.max_connections_per_user == updated.max_connections_per_user
    {
        return false;
    }
    let mut normalized = candidate.clone();
    normalized.server.policy.max_connections_total = previous.max_connections_total;
    normalized.server.policy.max_connections_per_user = previous.max_connections_per_user;
    &normalized == active
}

/// First supervised-cutover slice must reuse the SAME global/per-user
/// semaphores for both generations until bounded drain finishes. Changing
/// quota or user inventory would silently double admission and is forbidden.
/// This check does not publish, bind listeners or stop any old session.
pub(crate) fn same_shared_limits(active: &ServerDocument, candidate: &ServerDocument) -> bool {
    if active.server.policy != candidate.server.policy
        || active.management != candidate.management
        || active.schema_version != candidate.schema_version
    {
        return false;
    }
    let before: HashSet<_> = active.server.users.iter().map(|u| u.id.as_str()).collect();
    let after: HashSet<_> = candidate
        .server
        .users
        .iter()
        .map(|u| u.id.as_str())
        .collect();
    before == after
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_only_rejects_unchanged_tls_user_or_listener_mutations() {
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(active) = crate::config::parse(&source).unwrap() else {
            panic!("example config");
        };
        let mut candidate = active.clone();
        assert!(!quota_only(&active, &candidate));
        candidate.server.policy.max_connections_total += 1;
        assert!(quota_only(&active, &candidate));
        candidate.server.users[0].disabled = true;
        assert!(!quota_only(&active, &candidate));
        candidate.server.users[0].disabled = false;
        candidate.server.inbounds[0].tls_cert = "file:new.pem".to_owned();
        assert!(!quota_only(&active, &candidate));
        candidate.server.inbounds[0].tls_cert = active.server.inbounds[0].tls_cert.clone();
        candidate.server.policy.allow_private_ips = !active.server.policy.allow_private_ips;
        assert!(!quota_only(&active, &candidate));
    }

    #[test]
    fn same_port_tls_classification_refuses_any_quota_or_binding_mutation() {
        let source = include_str!("../../../examples/server.toml")
            .replace("REPLACE_WITH_64_LOWERCASE_HEX", &"a".repeat(64));
        let crate::config::Config::Server(base) = crate::config::parse(&source).unwrap() else {
            panic!("example server fixture must parse");
        };
        let mut candidate = base.clone();
        candidate.server.inbounds[0].tls_cert = "file:new-cert.pem".into();
        candidate.server.inbounds[0].tls_key = "file:new-key.pem".into();
        assert!(same_port_tls_only(&base, &candidate));
        candidate.server.policy.max_connections_total += 1;
        assert!(!same_port_tls_only(&base, &candidate));
        candidate.server.policy = base.server.policy.clone();
        candidate.server.inbounds[0].quic_listen = "127.0.0.1:34567".into();
        assert!(!same_port_tls_only(&base, &candidate));
        candidate.server.inbounds[0].quic_listen = base.server.inbounds[0].quic_listen.clone();
        candidate.server.users[0].disabled = true;
        assert!(!same_port_tls_only(&base, &candidate));
    }

    #[test]
    fn wildcard_and_dual_stack_bind_aliases_force_maintenance_instead_of_blind_rebind() {
        let local: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let v4_wildcard: SocketAddr = "0.0.0.0:9443".parse().unwrap();
        let v6_wildcard: SocketAddr = "[::]:9443".parse().unwrap();
        let different_port: SocketAddr = "127.0.0.1:9444".parse().unwrap();
        assert!(conflicts_with_active(local, v4_wildcard));
        assert!(conflicts_with_active(v4_wildcard, local));
        assert!(conflicts_with_active(v6_wildcard, local));
        assert!(!conflicts_with_active(local, different_port));
        assert!(!conflicts_with_active(
            "127.0.0.1:9443".parse().unwrap(),
            "127.0.0.2:9443".parse().unwrap()
        ));
    }
}
