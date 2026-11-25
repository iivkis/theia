//! Bound the time and bytes spent coalescing short application reads after
//! OPEN_OK. No payload inspection, extra traffic, handshake changes, or
//! cross-stream buffering. This is an unmeasured performance candidate;
//! neither throughput improvements nor classification resistance are assumed.
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time::{timeout_at, Instant},
};

const MAX_WAIT: Duration = Duration::from_millis(1);
const MAX_BATCH: usize = 4096;

/// A single direction owns its reader and buffer for the life of a tunnel.
/// The first read is not delayed; only a nonempty short read can enter the
/// bounded coalescing window. A deferred EOF or error is observed after all
/// previously read bytes have been returned to the caller.
pub(crate) struct BatchReader {
    eof: bool,
    deferred: Option<io::Error>,
}

impl BatchReader {
    pub(crate) fn new() -> Self {
        Self {
            eof: false,
            deferred: None,
        }
    }

    pub(crate) async fn read<R: AsyncRead + Unpin>(
        &mut self,
        source: &mut R,
        buffer: &mut [u8],
    ) -> io::Result<usize> {
        if buffer.is_empty() || buffer.len() > MAX_BATCH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay batch bound",
            ));
        }
        if let Some(error) = self.deferred.take() {
            return Err(error);
        }
        if self.eof {
            return Ok(0);
        }
        let mut used = source.read(buffer).await?;
        if used == 0 {
            self.eof = true;
            return Ok(0);
        }
        let deadline = Instant::now() + MAX_WAIT;
        while used < buffer.len() && Instant::now() < deadline {
            // AsyncReadExt::read is cancellation safe; the one absolute
            // deadline is not restarted by later short reads.
            match timeout_at(deadline, source.read(&mut buffer[used..])).await {
                Ok(Ok(0)) => {
                    self.eof = true;
                    break;
                }
                Ok(Ok(n)) => used += n,
                Ok(Err(error)) => {
                    self.deferred = Some(error);
                    break;
                }
                Err(_) => break,
            }
        }
        Ok(used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncWriteExt, ReadBuf};

    struct Source(VecDeque<io::Result<Vec<u8>>>);
    impl AsyncRead for Source {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.0.pop_front() {
                Some(Ok(bytes)) => {
                    assert!(bytes.len() <= buf.remaining());
                    buf.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
                Some(Err(error)) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(())),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn joins_only_available_bytes_and_preserves_eof() {
        let mut reader = BatchReader::new();
        let mut source = Source(VecDeque::from([Ok(vec![1, 2]), Ok(vec![3]), Ok(vec![])]));
        let mut data = [0; MAX_BATCH];
        assert_eq!(reader.read(&mut source, &mut data).await.unwrap(), 3);
        assert_eq!(&data[..3], &[1, 2, 3]);
        assert_eq!(reader.read(&mut source, &mut data).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn never_holds_a_short_read_past_the_single_deadline() {
        let (mut writer, mut source) = tokio::io::duplex(32);
        writer.write_all(b"a").await.unwrap();
        let start = Instant::now();
        let mut reader = BatchReader::new();
        let mut data = [0; MAX_BATCH];
        assert_eq!(reader.read(&mut source, &mut data).await.unwrap(), 1);
        let elapsed = Instant::now() - start;
        assert!(elapsed >= MAX_WAIT);
        // Tokio timers have millisecond granularity and may round the deadline.
        assert!(elapsed <= MAX_WAIT + Duration::from_millis(1));
        writer.write_all(b"b").await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(reader.read(&mut source, &mut data).await.unwrap(), 1);
        assert_eq!(data[0], b'b');
        assert_eq!(reader.read(&mut source, &mut data).await.unwrap(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn full_buffer_returns_without_wait_and_never_discards_read_data_on_error() {
        let mut reader = BatchReader::new();
        let mut source = Source(VecDeque::from([
            Ok(vec![7; MAX_BATCH]),
            Ok(vec![8]),
            Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        ]));
        let mut data = [0; MAX_BATCH];
        let start = Instant::now();
        assert_eq!(
            reader.read(&mut source, &mut data).await.unwrap(),
            MAX_BATCH
        );
        assert_eq!(Instant::now(), start);
        assert_eq!(reader.read(&mut source, &mut data).await.unwrap(), 1);
        assert_eq!(data[0], 8);
        assert_eq!(
            reader
                .read(&mut source, &mut data)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert!(reader.read(&mut source, &mut []).await.is_err());
    }
}
