//! Shared post-OPEN_OK data-plane liveness for H2/H3.
//! An idle direction is not a stalled tunnel. Only actual forwarded bytes
//! and successful half-closes refresh the per-tunnel progress deadline.
use std::{future::Future, sync::Mutex, time::Duration};
use tokio::{
    sync::oneshot,
    time::{sleep_until, timeout, Instant},
};

pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct Activity {
    last: Mutex<Instant>,
}

impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            last: Mutex::new(Instant::now()),
        }
    }

    pub(crate) fn data(&self, bytes: usize) {
        if bytes != 0 {
            self.fin();
        }
    }

    pub(crate) fn fin(&self) {
        // Never hold this small synchronous lock across an await.
        *self.last.lock().unwrap_or_else(|error| error.into_inner()) = Instant::now();
    }

    fn deadline(&self) -> Instant {
        *self.last.lock().unwrap_or_else(|error| error.into_inner()) + IDLE_TIMEOUT
    }

    async fn idle(&self) {
        loop {
            sleep_until(self.deadline()).await;
            if Instant::now() >= self.deadline() {
                return;
            }
        }
    }

    pub(crate) async fn run<E>(
        &self,
        upload: impl Future<Output = Result<(), E>>,
        download: impl Future<Output = Result<(), E>>,
        idle_error: E,
    ) -> Result<(), E> {
        tokio::select! {
            biased;
            result = async { tokio::try_join!(upload, download).map(|_| ()) } => result,
            () = self.idle() => Err(idle_error),
        }
    }
}

/// While the opposite direction is active, FIN is only a half-close. Once
/// both FINs have been forwarded, require HTTP EOF promptly. Keep polling
/// the SAME decoder future if the opposite FIN arrives mid-frame/trailers.
pub(crate) async fn receive_tail<T, E>(
    tail: impl Future<Output = Result<T, E>>,
    mut opposite_finished: oneshot::Receiver<()>,
    timeout_error: E,
) -> Result<T, E> {
    tokio::pin!(tail);
    tokio::select! {
        result = &mut tail => result,
        _ = &mut opposite_finished => {
            timeout(CLOSE_TIMEOUT, &mut tail).await.map_err(|_| timeout_error)?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn forwarded_bytes_extend_shared_idle_but_empty_frames_do_not() {
        let activity = Activity::new();
        tokio::time::advance(Duration::from_secs(20)).await;
        activity.data(1);
        tokio::time::advance(Duration::from_secs(20)).await;
        activity.data(0);
        assert!(timeout(Duration::from_secs(9), activity.idle()).await.is_err());
        assert!(timeout(Duration::from_secs(2), activity.idle()).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn fin_extends_idle_and_tail_waits_for_opposite_fin() {
        let activity = Activity::new();
        tokio::time::advance(Duration::from_secs(20)).await;
        activity.fin();
        assert!(timeout(Duration::from_secs(20), activity.idle()).await.is_err());

        let (done, finished) = oneshot::channel();
        let tail = async {
            tokio::time::sleep(Duration::from_secs(20)).await;
            Ok::<(), &'static str>(())
        };
        let (result, ()) = tokio::join!(
            receive_tail(tail, finished, "close timeout"),
            async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                done.send(()).unwrap();
            }
        );
        assert_eq!(result, Err("close timeout"));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_direction_does_not_override_other_direction_progress() {
        let activity = Activity::new();
        let result = activity.run(
            std::future::pending::<Result<(), &'static str>>(),
            async {
                for _ in 0..5 {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    activity.data(1);
                }
                Err("peer error")
            },
            "idle",
        ).await;
        assert_eq!(result, Err("peer error"));
    }
}
