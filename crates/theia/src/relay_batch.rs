//! Bounded ready-only relay read. No timer, idle cover traffic or lookahead
//! that waits for the next payload. Used only after successful OPEN_OK.
//! This is an unmeasured I/O candidate; not evidence of privacy or DPI parity.
use std::{future::poll_fn, io, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

pub(crate) const MAX_BATCH: usize = 4096;

#[derive(Default)]
pub(crate) struct ReadyBatch {
    eof: bool,
    deferred: Option<io::Error>,
}

impl ReadyBatch {
    /// Wait for the first actual byte or EOF, then try at most one additional
    /// read of already-available data. Pending returns the first bytes now.
    /// EOF and errors after progress are delivered on the next call.
    pub(crate) async fn read<R: AsyncRead + Unpin>(
        &mut self,
        source: &mut R,
        buffer: &mut [u8; MAX_BATCH],
    ) -> io::Result<usize> {
        if let Some(error) = self.deferred.take() {
            return Err(error);
        }
        if self.eof {
            return Ok(0);
        }
        let used = source.read(buffer).await?;
        if used == 0 {
            self.eof = true;
            return Ok(0);
        }
        if used == buffer.len() {
            return Ok(used);
        }
        let mut tail = ReadBuf::new(&mut buffer[used..]);
        // This future always completes during its first poll. No cancellation
        // point is introduced after bytes have been consumed.
        let result = poll_fn(|cx| {
            Poll::Ready(match Pin::new(&mut *source).poll_read(cx, &mut tail) {
                Poll::Pending => None,
                Poll::Ready(Ok(())) => Some(Ok(tail.filled().len())),
                Poll::Ready(Err(error)) => Some(Err(error)),
            })
        })
        .await;
        match result {
            None => Ok(used),
            Some(Ok(0)) => {
                self.eof = true;
                Ok(used)
            }
            Some(Ok(n)) => Ok(used + n),
            Some(Err(error)) => {
                self.deferred = Some(error);
                Ok(used)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, task::Context};
    use tokio::{io::AsyncWriteExt, time::Instant};

    struct Source {
        items: VecDeque<io::Result<Vec<u8>>>,
        polls: usize,
    }

    impl AsyncRead for Source {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.polls += 1;
            match self.items.pop_front() {
                Some(Ok(bytes)) => {
                    assert!(bytes.len() <= buffer.remaining());
                    buffer.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
                Some(Err(error)) => Poll::Ready(Err(error)),
                None => Poll::Pending,
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn short_interactive_read_returns_while_peer_waits_for_reply() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(b"first").await.unwrap();
        let mut batch = ReadyBatch::default();
        let mut bytes = [0; MAX_BATCH];
        let start = Instant::now();
        assert_eq!(batch.read(&mut reader, &mut bytes).await.unwrap(), 5);
        assert_eq!(&bytes[..5], b"first");
        assert_eq!(Instant::now(), start);
        writer.write_all(b"second").await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(batch.read(&mut reader, &mut bytes).await.unwrap(), 6);
        assert_eq!(&bytes[..6], b"second");
        assert_eq!(batch.read(&mut reader, &mut bytes).await.unwrap(), 0);
        assert_eq!(batch.read(&mut reader, &mut bytes).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn ready_only_coalescing_is_byte_exact_and_poll_bounded() {
        let mut batch = ReadyBatch::default();
        let mut bytes = [0; MAX_BATCH];
        let mut source = Source {
            items: VecDeque::from([Ok(vec![1, 2]), Ok(vec![3]), Ok(vec![4]), Ok(vec![])]),
            polls: 0,
        };
        let start = Instant::now();
        assert_eq!(batch.read(&mut source, &mut bytes).await.unwrap(), 3);
        assert_eq!(&bytes[..3], &[1, 2, 3]);
        assert_eq!(source.polls, 2);
        assert_eq!(batch.read(&mut source, &mut bytes).await.unwrap(), 1);
        assert_eq!(bytes[0], 4);
        assert_eq!(batch.read(&mut source, &mut bytes).await.unwrap(), 0);
        assert_eq!(source.polls, 4);
        assert_eq!(Instant::now(), start);
    }

    #[tokio::test]
    async fn full_reads_do_not_poll_ahead_and_errors_do_not_discard_data() {
        let mut batch = ReadyBatch::default();
        let mut bytes = [0; MAX_BATCH];
        let mut source = Source {
            items: VecDeque::from([
                Ok(vec![7; MAX_BATCH]), Ok(vec![8]),
                Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            ]),
            polls: 0,
        };
        assert_eq!(batch.read(&mut source, &mut bytes).await.unwrap(), MAX_BATCH);
        assert_eq!(source.polls, 1);
        assert_eq!(batch.read(&mut source, &mut bytes).await.unwrap(), 1);
        assert_eq!(bytes[0], 8);
        assert_eq!(batch.read(&mut source, &mut bytes).await.unwrap_err().kind(),
                   io::ErrorKind::BrokenPipe);
        assert_eq!(source.polls, 3);
    }
}
