//! Typed network outcomes, independent of HTTP/2 or Anti-DPI. A class
//! describes evidence; only the owning layer may authorize a retry.
use crate::protocol::ErrorCode;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    Configuration,
    Io,
    TcpControllerUnavailable,
    Tls,
    Http2,
    Http3,
    QuicUnreachable,
    QuicEndpointNetworkRefused,
    Unauthorized,
    SystemProxy,
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
            Self::TcpControllerUnavailable => f.write_str("TCP BBR/CUBIC controller unavailable"),
            Self::Tls => f.write_str("TLS identity or ALPN verification failed"),
            Self::Http2 => f.write_str("HTTP/2 transport failed"),
            Self::Http3 => f.write_str("HTTP/3 transport failed"),
            Self::QuicUnreachable => f.write_str("quic_unreachable"),
            Self::QuicEndpointNetworkRefused => f.write_str("quic_endpoint_network_refused"),
            Self::Unauthorized => f.write_str("server rejected authentication"),
            Self::SystemProxy => f.write_str("Windows user proxy CAS/recovery failed; inspect client proxy --status and recover explicitly"),
            Self::Rejected(status) => write!(f, "server rejected request (HTTP {status})"),
            Self::Protocol => f.write_str("SmartTheia protocol violation"),
            Self::Open(code) => write!(f, "target connection rejected ({code:?})"),
            Self::Timeout => f.write_str("client operation timed out"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Sanitized, stable error categories: never format a remote-controlled value.
pub(crate) fn error_kind(error: &ClientError) -> &'static str {
    match error {
        ClientError::Configuration => "configuration",
        ClientError::Io => "io",
        ClientError::TcpControllerUnavailable => "tcp_controller_unavailable",
        ClientError::Tls => "tls",
        ClientError::Http2 => "h2",
        ClientError::Http3 => "h3",
        ClientError::QuicUnreachable => "quic_unreachable",
        ClientError::QuicEndpointNetworkRefused => "quic_endpoint_network_refused",
        ClientError::Unauthorized => "unauthorized",
        ClientError::SystemProxy => "system_proxy",
        ClientError::Rejected(_) => "http_rejected",
        ClientError::Protocol => "protocol",
        ClientError::Open(_) => "open_rejected",
        ClientError::Timeout => "timeout",
    }
}


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointUnavailable { NoResponse, Refused }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureClass {
    Configuration,
    LocalSetup,
    AmbiguousHandshake,
    AmbiguousTimeout,
    EndpointUnavailable(EndpointUnavailable),
    IdentityRejected,
    PolicyDenied,
    StrategyFailed,
    ProbeUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuicDialError {
    Configuration,
    Bind,
    Handshake,
    Timeout,
    Unreachable,
    EndpointNetworkRefused,
}


impl QuicDialError {
    pub(crate) fn class(self) -> FailureClass {
        match self {
            Self::Configuration => FailureClass::Configuration,
            Self::Bind => FailureClass::LocalSetup,
            Self::Handshake => FailureClass::AmbiguousHandshake,
            Self::Timeout => FailureClass::AmbiguousTimeout,
            Self::Unreachable => FailureClass::EndpointUnavailable(EndpointUnavailable::NoResponse),
            Self::EndpointNetworkRefused => FailureClass::EndpointUnavailable(EndpointUnavailable::Refused),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeVerdict {
    Verified,
    StrategyFailed,
    Unavailable,
    IdentityRejected,
    Denied,
}


impl ProbeVerdict {
    pub(crate) fn failure(self) -> Option<FailureClass> {
        match self {
            Self::Verified => None,
            Self::StrategyFailed => Some(FailureClass::StrategyFailed),
            Self::Unavailable => Some(FailureClass::ProbeUnavailable),
            Self::IdentityRejected => Some(FailureClass::IdentityRejected),
            Self::Denied => Some(FailureClass::PolicyDenied),
        }
    }
}

/// Carrier availability is an observed endpoint fact, not a permission
/// to change route, security mode, or retry after OPEN.
pub(crate) fn endpoint_unavailable(error: ClientError) -> Option<EndpointUnavailable> {
    match error {
        ClientError::QuicUnreachable => Some(EndpointUnavailable::NoResponse),
        ClientError::QuicEndpointNetworkRefused => Some(EndpointUnavailable::Refused),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ambiguous_and_security_failures_are_not_availability_evidence() {
        for error in [ClientError::Configuration, ClientError::Io, ClientError::Tls,
            ClientError::Timeout, ClientError::Unauthorized, ClientError::Protocol,
            ClientError::Open(ErrorCode::PolicyDenied), ClientError::Open(ErrorCode::DialTimeout)] {
            assert_eq!(endpoint_unavailable(error), None);
        }
        assert_eq!(endpoint_unavailable(ClientError::QuicUnreachable), Some(EndpointUnavailable::NoResponse));
        assert_eq!(endpoint_unavailable(ClientError::QuicEndpointNetworkRefused), Some(EndpointUnavailable::Refused));
        assert_eq!(QuicDialError::Handshake.class(), FailureClass::AmbiguousHandshake);
        assert_eq!(QuicDialError::Timeout.class(), FailureClass::AmbiguousTimeout);
        assert_eq!(ProbeVerdict::IdentityRejected.failure(), Some(FailureClass::IdentityRejected));
        assert_eq!(ProbeVerdict::Denied.failure(), Some(FailureClass::PolicyDenied));
    }
}
