//! Native QUIC foundation. Not a selectable endpoint until interoperability,
//! security and performance gates pass. Existing H3 remains on Quinn.
#![forbid(unsafe_code)]

pub mod ack;
pub mod ack_tx;
pub mod congestion;
pub mod endpoint;
pub mod flow;
pub mod frames;
pub mod handshake;
pub mod handshake_udp;
pub mod initial;
pub mod key_update;
pub mod lifecycle;
pub mod loss;
pub mod packet;
pub mod parameters;
pub mod path;
pub mod recovery;
pub mod scheduler;
pub mod send_flow;
pub mod spaces;
pub mod stream;
pub mod tls;
pub mod wire;
