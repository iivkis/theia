//! Shared network infrastructure; protocol-specific state remains in its owner.
pub(crate) mod address;
pub(crate) mod error;
pub(crate) mod evidence;
pub(crate) mod guarded_io;
pub(crate) mod probe;
pub(crate) mod tls;
