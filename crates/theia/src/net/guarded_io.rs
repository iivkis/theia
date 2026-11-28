//! Guard a socket at every I/O poll. The owner still supplies the deadline,
//! cancellation wakeup, scope and policy. Dropping the future drops its socket.
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct GuardedIo<'a, T> {
    inner: T,
    live: &'a (dyn Fn() -> bool + Sync),
    written: Option<&'a std::sync::atomic::AtomicU64>,
}

impl<'a, T> GuardedIo<'a, T> {
    pub(crate) fn new(inner: T, live: &'a (dyn Fn() -> bool + Sync)) -> Self {
        Self { inner, live, written: None }
    }

    #[cfg(windows)]
    pub(crate) fn counted(mut self, counter: &'a std::sync::atomic::AtomicU64) -> Self {
        self.written = Some(counter);
        self
    }

    fn check(&self) -> io::Result<()> {
        if (self.live)() {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for GuardedIo<'_, T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>)
        -> Poll<io::Result<()>>
    {
        let this = self.get_mut();
        if let Err(error) = this.check() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Err(error) = this.check() {
            return Poll::Ready(Err(error));
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for GuardedIo<'_, T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8])
        -> Poll<io::Result<usize>>
    {
        let this = self.get_mut();
        if let Err(error) = this.check() {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            if let Some(counter) = this.written {
                counter.fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check() {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// A blocked socket may not wake itself when permission changes.
pub(crate) async fn revoked(live: &(dyn Fn() -> bool + Sync)) {
    while live() {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn revoked_socket_refuses_next_write_and_read() {
        let (socket, mut peer) = tokio::io::duplex(16);
        let allowed = AtomicBool::new(true);
        let live = || allowed.load(Ordering::Acquire);
        let mut guarded = GuardedIo::new(socket, &live);
        guarded.write_all(b"first").await.unwrap();
        allowed.store(false, Ordering::Release);
        assert!(guarded.write_all(b"second").await.is_err());
        assert!(guarded.read_u8().await.is_err());
        let mut data = [0; 5];
        peer.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"first");
        drop(guarded);
        assert_eq!(peer.read(&mut data).await.unwrap(), 0);
    }
}
