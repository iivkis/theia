//! Bounded, privacy-preserving diagnostics for both roles and CI binaries.
//!
//! Only compile-time event names and explicitly typed numeric/boolean/static
//! fields enter the logger. Never pass credentials, target hosts, user IDs,
//! paths, HTTP headers, config text, or packet contents to this module.

use std::{
    env, fs, io::{self, Write}, path::{Path, PathBuf},
    sync::{atomic::{AtomicU64, Ordering}, mpsc::{self, SyncSender, TrySendError}, OnceLock},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// One process retains at most two 25 MiB segments (50 MiB total).
pub const MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;
const SEGMENT_BYTES: u64 = MAX_LOG_BYTES / 2;
const QUEUE_CAPACITY: usize = 4096;
static LOGGER: OnceLock<Option<Logger>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();
static SEQUENCE: AtomicU64 = AtomicU64::new(1);
static OPERATIONS: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    const fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

/// Deliberately excludes arbitrary strings and Debug-formatted objects.
#[derive(Clone, Copy)]
pub enum Value {
    Count(u64),
    Flag(bool),
    Label(&'static str),
}

enum Message {
    Line(String),
    Flush(mpsc::Sender<()>),
}

struct Logger {
    sender: SyncSender<Message>,
    dropped: std::sync::Arc<AtomicU64>,
}

pub fn init() {
    let _ = LOGGER.get_or_init(start_logger);
}

/// Operation IDs correlate events inside one process without exposing peers.
pub fn next_id() -> u64 {
    OPERATIONS.fetch_add(1, Ordering::Relaxed)
}

/// Never log a formatted error, network destination, config path or input.
pub fn emit(
    level: Level,
    component: &'static str,
    event: &'static str,
    fields: &[(&'static str, Value)],
    source: &'static str,
    line: u32,
) {
    let Some(logger) = LOGGER.get_or_init(start_logger) else {
        return;
    };
    let epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let since_start_ms = START.get_or_init(Instant::now).elapsed().as_millis();
    let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut record = format!(
        "unix_ms={epoch_ms} elapsed_ms={since_start_ms} seq={seq} pid={} thread={:?} level={} component={component} event={event} at={source}:{line}",
        std::process::id(),
        thread::current().id(),
        level.label(),
    );
    for (key, value) in fields {
        use std::fmt::Write as _;
        match value {
            Value::Count(value) => { let _ = write!(record, " {key}={value}"); }
            Value::Flag(value) => { let _ = write!(record, " {key}={value}"); }
            Value::Label(value) => { let _ = write!(record, " {key}={value}"); }
        }
    }
    record.push('\n');
    match logger.sender.try_send(Message::Line(record)) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            logger.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Wait for pending diagnostics at normal CLI exit; never run on Tokio workers.
pub fn flush() {
    if let Some(Some(logger)) = LOGGER.get() {
        let (sender, receiver) = mpsc::channel();
        if logger.sender.try_send(Message::Flush(sender)).is_ok() {
            let _ = receiver.recv_timeout(Duration::from_secs(3));
        }
    }
}

fn start_logger() -> Option<Logger> {
    if env::var_os("THEIA_TRACE_OFF").is_some_and(|value| value == "1") {
        return None;
    }
    match open_logger() {
        Ok(logger) => Some(logger),
        Err(error) => {
            // Paths are deliberately omitted, even when the path itself is the error.
            eprintln!("theia: file trace unavailable ({:?}); diagnostics are incomplete", error.kind());
            None
        }
    }
}

fn log_directory() -> PathBuf {
    if let Some(path) = env::var_os("THEIA_TRACE_DIR").filter(|path| !path.is_empty()) {
        return PathBuf::from(path);
    }
    #[cfg(windows)]
    {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir);
        base.join("Theia").join("logs")
    }
    #[cfg(not(windows))]
    {
        let base = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("state")))
            .unwrap_or_else(env::temp_dir);
        base.join("theia").join("logs")
    }
}

fn private_directory(path: &Path) -> io::Result<()> {
    let existed = fs::symlink_metadata(path).is_ok();
    if !existed {
        fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe trace directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "trace directory not private"));
        }
    }
    Ok(())
}

fn open_logger() -> io::Result<Logger> {
    let directory = log_directory();
    private_directory(&directory)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = format!("theia-{}-{stamp}.trace.log", std::process::id());
    let mut sink = RotatingFile::new(directory.join(name), SEGMENT_BYTES)?;
    let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
    let dropped = std::sync::Arc::new(AtomicU64::new(0));
    let lost = dropped.clone();
    thread::Builder::new()
        .name("theia-trace-writer".into())
        .spawn(move || {
            while let Ok(message) = receiver.recv() {
                let count = lost.swap(0, Ordering::Relaxed);
                if count != 0 {
                    let warning = format!(
                        "unix_ms={} level=WARN component=diagnostics event=queue_overflow dropped={count}\n",
                        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
                    );
                    if sink.write(&warning).is_err() {
                        eprintln!("theia: trace write failed; diagnostics are incomplete");
                        break;
                    }
                }
                match message {
                    Message::Line(line) => {
                        if sink.write(&line).is_err() {
                            eprintln!("theia: trace write failed; diagnostics are incomplete");
                            break;
                        }
                    }
                    Message::Flush(reply) => {
                        let _ = sink.file.flush();
                        let _ = reply.send(());
                    }
                }
            }
        })?;
    Ok(Logger { sender, dropped })
}

struct RotatingFile {
    active: PathBuf,
    previous: PathBuf,
    file: fs::File,
    size: u64,
    segment_bytes: u64,
}

impl RotatingFile {
    fn new(active: PathBuf, segment_bytes: u64) -> io::Result<Self> {
        if segment_bytes == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero segment limit"));
        }
        let previous = active.with_extension("log.1");
        let file = new_file(&active)?;
        Ok(Self { active, previous, file, size: 0, segment_bytes })
    }

    fn write(&mut self, record: &str) -> io::Result<()> {
        let bytes = record.as_bytes();
        let length = u64::try_from(bytes.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record too large"))?;
        if length > self.segment_bytes {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "record exceeds segment"));
        }
        if self.size + length > self.segment_bytes {
            self.file.flush()?;
            // On Windows, renaming a still-open file is unreliable. Replace
            // the handle before rotating, and never follow a prior symlink.
            let pending = self.active.with_extension("log.next");
            let next = new_file(&pending)?;
            let old = std::mem::replace(&mut self.file, next);
            drop(old);
            if fs::symlink_metadata(&self.previous).is_ok() {
                fs::remove_file(&self.previous)?;
            }
            fs::rename(&self.active, &self.previous)?;
            fs::rename(&pending, &self.active)?;
            self.size = 0;
        }
        self.file.write_all(bytes)?;
        self.file.flush()?;
        self.size += length;
        Ok(())
    }
}

fn new_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[macro_export]
macro_rules! diag {
    ($level:ident, $component:literal, $event:literal $(, $key:literal = $value:expr)* $(,)?) => {
        $crate::diagnostics::emit(
            $crate::diagnostics::Level::$level, $component, $event,
            &[$(($key, $value)),*], file!(), line!()
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> PathBuf {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = env::temp_dir().join(format!("theia-trace-test-{}-{stamp}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn two_segments_never_exceed_total_budget_and_keep_recent_context() {
        let dir = directory();
        let mut writer = RotatingFile::new(dir.join("trace.log"), 128).unwrap();
        for index in 0..100 {
            writer.write(&format!("sequence={index:03} payload=static\n")).unwrap();
        }
        let active = fs::read_to_string(dir.join("trace.log")).unwrap();
        let previous = fs::read_to_string(dir.join("trace.log.1")).unwrap();
        assert!(active.contains("sequence=099"));
        assert!(previous.contains("sequence=09"));
        assert!(active.len() <= 128);
        assert!(previous.len() <= 128);
        assert!(active.len() + previous.len() <= 256);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_oversized_record_and_preserves_existing_file() {
        let dir = directory();
        let mut writer = RotatingFile::new(dir.join("trace.log"), 10).unwrap();
        writer.write("ok\n").unwrap();
        assert!(writer.write("very-long-record\n").is_err());
        assert_eq!(fs::read_to_string(dir.join("trace.log")).unwrap(), "ok\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_public_directory_and_protects_created_log_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = directory();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_directory(&dir).is_err());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        private_directory(&dir).unwrap();
        let writer = RotatingFile::new(dir.join("trace.log"), 100).unwrap();
        assert_eq!(writer.file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        drop(writer);
        fs::remove_dir_all(dir).unwrap();
    }
}
