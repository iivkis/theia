//! Native QUIC foundation. Not a selectable endpoint until interoperability,
//! security and performance gates pass. Existing H3 remains on Quinn.
#![forbid(unsafe_code)]

pub mod ack;
pub mod flow;
pub mod initial;
pub mod packet;
pub mod parameters;
pub mod recovery;
pub mod spaces;
pub mod stream;
pub mod tls;
pub mod wire;
