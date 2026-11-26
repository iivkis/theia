//! HTTP/3 stream types are provided directly by Theia's native QUIC bridge.
//! No second transport adapter or backend selection at the client boundary.
pub(crate) use crate::quic_core::h3_adapter::{Opener, RecvSide as Rx, SendSide as Tx};
