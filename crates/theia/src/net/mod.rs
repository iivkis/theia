//! Shared network infrastructure; protocol-specific state remains in its owner.
pub(crate) mod evidence;
pub(crate) mod error;
pub(crate) mod tls;
pub(crate) mod probe;
