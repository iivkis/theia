//! Privacy-preserving, process-local application DATA accounting.
//! Counts complete relay writes/accepted frames, not IP/wire bytes or peer ACKs.
//! No per-destination state, payload, credentials, unbounded history or I/O.
use crate::Role;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub active: u64,
    pub opened: u64,
    pub upload: u64,
    pub download: u64,
}

struct Counters {
    active: AtomicU64,
    opened: AtomicU64,
    upload: AtomicU64,
    download: AtomicU64,
}
impl Counters {
    const fn new() -> Self {
        Self {
            active: AtomicU64::new(0),
            opened: AtomicU64::new(0),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
        }
    }

    fn enter(&self) -> Relay<'_> {
        self.opened.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        Relay(self)
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            active: self.active.load(Ordering::Relaxed),
            opened: self.opened.load(Ordering::Relaxed),
            upload: self.upload.load(Ordering::Relaxed),
            download: self.download.load(Ordering::Relaxed),
        }
    }
}

pub(crate) struct Relay<'a>(&'a Counters);
impl Relay<'_> {
    pub(crate) fn upload(&self, bytes: usize) {
        self.0.upload.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub(crate) fn download(&self, bytes: usize) {
        self.0.download.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}
impl Drop for Relay<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

static SERVER_H2: Counters = Counters::new();
static SERVER_H3: Counters = Counters::new();
static CLIENT_H2: Counters = Counters::new();
static CLIENT_H3: Counters = Counters::new();

fn counters(role: Role, h3: bool) -> &'static Counters {
    match (role, h3) {
        (Role::Server, false) => &SERVER_H2,
        (Role::Server, true) => &SERVER_H3,
        (Role::Client, false) => &CLIENT_H2,
        (Role::Client, true) => &CLIENT_H3,
    }
}
pub(crate) fn enter(role: Role, h3: bool) -> Relay<'static> {
    counters(role, h3).enter()
}
pub(crate) fn snapshot(role: Role) -> [Snapshot; 2] {
    [counters(role, false).snapshot(), counters(role, true).snapshot()]
}

fn bytes(n: u64) -> String {
    if n >= 1024 * 1024 * 1024 {
        format!("{:.2} ГиБ", n as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if n >= 1024 * 1024 {
        format!("{:.2} МиБ", n as f64 / (1024.0 * 1024.0))
    } else if n >= 1024 {
        format!("{:.1} КиБ", n as f64 / 1024.0)
    } else {
        format!("{n} Б")
    }
}

/// Refresh no faster than once a second, with a fixed-size sample.
pub(crate) struct Monitor {
    role: Role,
    previous: [Snapshot; 2],
    current: [Snapshot; 2],
    rate: [(u64, u64); 2],
    sampled: Instant,
}
impl Monitor {
    pub(crate) fn new(role: Role) -> Self {
        let current = snapshot(role);
        Self {
            role, previous: current, current, rate: [(0, 0); 2], sampled: Instant::now(),
        }
    }
    pub(crate) fn poll(&mut self) {
        let elapsed = self.sampled.elapsed().as_secs_f64();
        if elapsed < 1.0 { return; }
        self.current = snapshot(self.role);
        for (i, (now, old)) in self.current.iter().zip(self.previous.iter()).enumerate() {
            self.rate[i] = (
                (now.upload.saturating_sub(old.upload) as f64 / elapsed) as u64,
                (now.download.saturating_sub(old.download) as f64 / elapsed) as u64,
            );
        }
        self.previous = self.current;
        self.sampled = Instant::now();
    }
    pub(crate) fn body(&self) -> String {
        let mut result = String::from("Только трафик текущего процесса Theia; внешние сервисы не измеряются.\nDATA после OPEN_OK, без TLS/HTTP/QUIC overhead. Не подтверждение доставки peer.\n");
        for (i, s) in self.current.iter().enumerate() {
            let transport = if i == 0 { "H2" } else { "H3" };
            let (up, down) = self.rate[i];
            result.push_str(&format!(
                "\n{transport} • открыто сейчас: {} • всего relay: {}\n↑ {} ({} /с)   ↓ {} ({} /с)\n",
                s.active, s.opened, bytes(s.upload), bytes(up), bytes(s.download), bytes(down)
            ));
        }
        result.push_str("\nОбновление 1 с • Esc: назад");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_two_directions_and_cancellation_without_leaking_active() {
        let c = Counters::new();
        {
            let a = c.enter();
            let b = c.enter();
            a.upload(12);
            b.download(23);
            assert_eq!(c.snapshot(), Snapshot { active: 2, opened: 2, upload: 12, download: 23 });
            drop(a);
            assert_eq!(c.snapshot().active, 1);
        }
        assert_eq!(c.snapshot(), Snapshot { active: 0, opened: 2, upload: 12, download: 23 });
    }
    #[test]
    fn monitor_has_two_transports_and_truthful_scope() {
        let mut m = Monitor::new(Role::Client);
        m.poll();
        let body = m.body();
        assert!(body.contains("H2") && body.contains("H3"));
        assert!(body.contains("внешние сервисы не измеряются"));
        assert_eq!(bytes(1024), "1.0 КиБ");
    }
}
