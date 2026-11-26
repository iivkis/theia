//! Internal transport-neutral H3 client boundary. Native remains explicit loopback only.
use bytes::{Buf, Bytes};
use h3::{error::Code, quic::{self, ConnectionErrorIncoming as CE, StreamErrorIncoming as SE, StreamId, WriteBuf}};
use std::task::{Context, Poll};
use crate::quic_core::h3_adapter as native;

macro_rules! dispatch {
    ($self:expr, $trait:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            Self::Quinn(s) => quic::$trait::$method(s.as_mut() $(, $arg)*),
            Self::Native(s) => quic::$trait::$method(s.as_mut() $(, $arg)*),
        }
    };
}

pub(crate) enum Connection { Quinn(Box<h3_quinn::Connection>), Native(Box<native::NativeConnection>) }
pub(crate) enum Opener { Quinn(Box<h3_quinn::OpenStreams>), Native(Box<native::Opener>) }
pub(crate) enum Bidi { Quinn(Box<h3_quinn::BidiStream<Bytes>>), Native(Box<native::Bidi>) }
pub(crate) enum Tx { Quinn(Box<h3_quinn::SendStream<Bytes>>), Native(Box<native::SendSide>) }
pub(crate) enum Rx { Quinn(Box<h3_quinn::RecvStream>), Native(Box<native::RecvSide>) }
impl Clone for Opener { fn clone(&self) -> Self { match self { Self::Quinn(s) => Self::Quinn(s.clone()), Self::Native(s) => Self::Native(s.clone()) } } }
impl quic::OpenStreams<Bytes> for Connection {
    type BidiStream = Bidi;
    type SendStream = Tx;
    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, SE>> {
        match self { Self::Quinn(s) => quic::OpenStreams::<Bytes>::poll_open_bidi(s.as_mut(), cx).map(|r| r.map(|s| Bidi::Quinn(Box::new(s)))), Self::Native(s) => quic::OpenStreams::<Bytes>::poll_open_bidi(s.as_mut(), cx).map(|r| r.map(|s| Bidi::Native(Box::new(s)))) }
    }
    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Tx, SE>> {
        match self { Self::Quinn(s) => quic::OpenStreams::<Bytes>::poll_open_send(s.as_mut(), cx).map(|r| r.map(|s| Tx::Quinn(Box::new(s)))), Self::Native(s) => quic::OpenStreams::<Bytes>::poll_open_send(s.as_mut(), cx).map(|r| r.map(|s| Tx::Native(Box::new(s)))) }
    }
    fn close(&mut self, code: Code, reason: &[u8]) { match self { Self::Quinn(s) => quic::OpenStreams::<Bytes>::close(s.as_mut(), code, reason), Self::Native(s) => quic::OpenStreams::<Bytes>::close(s.as_mut(), code, reason) } }
}
impl quic::OpenStreams<Bytes> for Opener {
    type BidiStream = Bidi;
    type SendStream = Tx;
    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, SE>> {
        match self { Self::Quinn(s) => quic::OpenStreams::<Bytes>::poll_open_bidi(s.as_mut(), cx).map(|r| r.map(|s| Bidi::Quinn(Box::new(s)))), Self::Native(s) => quic::OpenStreams::<Bytes>::poll_open_bidi(s.as_mut(), cx).map(|r| r.map(|s| Bidi::Native(Box::new(s)))) }
    }
    fn poll_open_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<Tx, SE>> {
        match self { Self::Quinn(s) => quic::OpenStreams::<Bytes>::poll_open_send(s.as_mut(), cx).map(|r| r.map(|s| Tx::Quinn(Box::new(s)))), Self::Native(s) => quic::OpenStreams::<Bytes>::poll_open_send(s.as_mut(), cx).map(|r| r.map(|s| Tx::Native(Box::new(s)))) }
    }
    fn close(&mut self, code: Code, reason: &[u8]) { match self { Self::Quinn(s) => quic::OpenStreams::<Bytes>::close(s.as_mut(), code, reason), Self::Native(s) => quic::OpenStreams::<Bytes>::close(s.as_mut(), code, reason) } }
}
impl quic::Connection<Bytes> for Connection {
    type RecvStream = Rx;
    type OpenStreams = Opener;
    fn poll_accept_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi, CE>> {
        match self { Self::Quinn(s) => quic::Connection::<Bytes>::poll_accept_bidi(s.as_mut(), cx).map(|r| r.map(|s| Bidi::Quinn(Box::new(s)))), Self::Native(s) => quic::Connection::<Bytes>::poll_accept_bidi(s.as_mut(), cx).map(|r| r.map(|s| Bidi::Native(Box::new(s)))) }
    }
    fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Rx, CE>> {
        match self { Self::Quinn(s) => quic::Connection::<Bytes>::poll_accept_recv(s.as_mut(), cx).map(|r| r.map(|s| Rx::Quinn(Box::new(s)))), Self::Native(s) => quic::Connection::<Bytes>::poll_accept_recv(s.as_mut(), cx).map(|r| r.map(|s| Rx::Native(Box::new(s)))) }
    }
    fn opener(&self) -> Opener { match self { Self::Quinn(s) => Opener::Quinn(Box::new(quic::Connection::<Bytes>::opener(s.as_ref()))), Self::Native(s) => Opener::Native(Box::new(quic::Connection::<Bytes>::opener(s.as_ref()))) } }
}
impl quic::BidiStream<Bytes> for Bidi {
    type SendStream = Tx;
    type RecvStream = Rx;
    fn split(self) -> (Tx, Rx) { match self { Self::Quinn(s) => { let (tx,rx)=quic::BidiStream::split(*s); (Tx::Quinn(Box::new(tx)),Rx::Quinn(Box::new(rx))) }, Self::Native(s) => { let (tx,rx)=quic::BidiStream::split(*s); (Tx::Native(Box::new(tx)),Rx::Native(Box::new(rx))) } } }
}
impl quic::SendStream<Bytes> for Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SE>> { dispatch!(self, SendStream, poll_ready, cx) }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), SE> { dispatch!(self, SendStream, send_data, data) }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SE>> { dispatch!(self, SendStream, poll_finish, cx) }
    fn reset(&mut self, code: u64) { dispatch!(self, SendStream, reset, code) }
    fn send_id(&self) -> StreamId { match self { Self::Quinn(s) => quic::SendStream::send_id(s.as_ref()), Self::Native(s) => quic::SendStream::send_id(s.as_ref()) } }
}
impl quic::SendStreamUnframed<Bytes> for Bidi {
    fn poll_send<D: Buf>(&mut self, cx: &mut Context<'_>, buf: &mut D) -> Poll<Result<usize, SE>> { dispatch!(self, SendStreamUnframed, poll_send, cx, buf) }
}
impl quic::SendStream<Bytes> for Tx {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SE>> { dispatch!(self, SendStream, poll_ready, cx) }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), SE> { dispatch!(self, SendStream, send_data, data) }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), SE>> { dispatch!(self, SendStream, poll_finish, cx) }
    fn reset(&mut self, code: u64) { dispatch!(self, SendStream, reset, code) }
    fn send_id(&self) -> StreamId { match self { Self::Quinn(s) => quic::SendStream::send_id(s.as_ref()), Self::Native(s) => quic::SendStream::send_id(s.as_ref()) } }
}
impl quic::SendStreamUnframed<Bytes> for Tx {
    fn poll_send<D: Buf>(&mut self, cx: &mut Context<'_>, buf: &mut D) -> Poll<Result<usize, SE>> { dispatch!(self, SendStreamUnframed, poll_send, cx, buf) }
}
impl quic::RecvStream for Bidi {
    type Buf = Bytes;
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, SE>> { dispatch!(self, RecvStream, poll_data, cx) }
    fn stop_sending(&mut self, code: u64) { dispatch!(self, RecvStream, stop_sending, code) }
    fn recv_id(&self) -> StreamId { match self { Self::Quinn(s) => quic::RecvStream::recv_id(s.as_ref()), Self::Native(s) => quic::RecvStream::recv_id(s.as_ref()) } }
}
impl quic::RecvStream for Rx {
    type Buf = Bytes;
    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, SE>> { dispatch!(self, RecvStream, poll_data, cx) }
    fn stop_sending(&mut self, code: u64) { dispatch!(self, RecvStream, stop_sending, code) }
    fn recv_id(&self) -> StreamId { match self { Self::Quinn(s) => quic::RecvStream::recv_id(s.as_ref()), Self::Native(s) => quic::RecvStream::recv_id(s.as_ref()) } }
}
