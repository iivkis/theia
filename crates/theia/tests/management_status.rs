//! M4.2a native Linux local management IPC acceptance tests.
//! All sockets are isolated filesystem paths; no Internet, OS proxy or reload.
#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use theia::management::{query_in, ManagementError, StatusCommand, StatusReply, StatusServer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn private_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "theia-m4-2a-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("isolated private runtime dir");
    path
}

#[tokio::test]
async fn health_and_status_reflect_real_running_socket_without_reloading() {
    let dir = private_dir();
    let server = StatusServer::bind_in(&dir, 2).expect("private socket bind");
    let socket = server.path().to_owned();
    assert!(socket.exists());
    assert_eq!(
        fs::symlink_metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let task = tokio::spawn(server.serve());
    assert_eq!(
        query_in(&dir, StatusCommand::Health).await,
        Ok(StatusReply::Healthy)
    );
    assert_eq!(
        query_in(&dir, StatusCommand::Status).await,
        Ok(StatusReply::Running { inbounds: 2 })
    );
    assert_eq!(
        query_in(&dir, StatusCommand::Reload).await,
        Ok(StatusReply::Unsupported)
    );
    // Verify the compiled executable, not just the library protocol.
    let cli_dir = dir.clone();
    let cli = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_theia"))
            .args(["server", "status"])
            .env("THEIA_CONTROL_DIR", cli_dir)
            .output()
            .expect("compiled CLI")
    })
    .await
    .unwrap();
    assert!(cli.status.success(), "{:?}", cli.stderr);
    assert_eq!(
        std::str::from_utf8(&cli.stdout).unwrap(),
        "server running; 2 inbounds; reload not available\n"
    );
    task.abort();
    let _ = task.await;
    assert!(!socket.exists(), "owned socket removed on cancellation");
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn world_accessible_runtime_directory_is_rejected_without_creating_socket() {
    let dir = private_dir();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        StatusServer::bind_in(&dir, 1),
        Err(ManagementError::UnsafeDirectory)
    ));
    assert!(!dir.join("theia-server.sock").exists());
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn symlink_directory_and_existing_file_are_never_unlinked_or_followed() {
    let real = private_dir();
    let symlink = real.with_extension("alias");
    std::os::unix::fs::symlink(&real, &symlink).unwrap();
    assert!(matches!(
        StatusServer::bind_in(&symlink, 1),
        Err(ManagementError::UnsafeDirectory)
    ));
    fs::remove_file(&symlink).unwrap();

    let target = real.join("theia-server.sock");
    fs::write(&target, b"keep this original file").unwrap();
    assert!(matches!(
        StatusServer::bind_in(&real, 1),
        Err(ManagementError::SocketUnavailable)
    ));
    assert_eq!(fs::read(&target).unwrap(), b"keep this original file");
    fs::remove_file(target).unwrap();
    fs::remove_dir(real).unwrap();
}

#[tokio::test]
async fn invalid_or_oversized_messages_cannot_trigger_reload_or_hang() {
    let dir = private_dir();
    let server = StatusServer::bind_in(&dir, 1).unwrap();
    let task = tokio::spawn(server.serve());
    for message in [b"GET / HTTP/1.1\n".as_slice(), &[b'x'; 128][..]] {
        let mut stream = UnixStream::connect(dir.join("theia-server.sock"))
            .await
            .unwrap();
        stream.write_all(message).await.unwrap();
        let mut response = Vec::new();
        let result = timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
            .await
            .expect("bounded server must close invalid input");
        if message.len() > 64 {
            // Linux can reset the connection when a bounded server closes
            // with unread bytes; both RST and ERR are safe refusals.
            match result {
                Ok(_) => assert_eq!(response, b"ERR unsupported\n"),
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
            }
        } else {
            result.unwrap();
            assert_eq!(response, b"ERR unsupported\n");
        }
    }
    task.abort();
    let _ = task.await;
    fs::remove_dir(&dir).unwrap();
}

#[tokio::test]
async fn fake_unsupported_reply_cannot_masquerade_as_running_status() {
    let dir = private_dir();
    let listener = tokio::net::UnixListener::bind(dir.join("theia-server.sock")).unwrap();
    let responder = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 7];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"status\n");
        stream.write_all(b"ERR unsupported\n").await.unwrap();
    });
    assert_eq!(
        query_in(&dir, StatusCommand::Status).await,
        Err(ManagementError::InvalidReply)
    );
    responder.await.unwrap();
    fs::remove_file(dir.join("theia-server.sock")).unwrap();
    fs::remove_dir(&dir).unwrap();
}

#[tokio::test]
async fn failed_connect_never_claims_running_or_applied() {
    let dir = private_dir();
    assert_eq!(
        query_in(&dir, StatusCommand::Status).await,
        Err(ManagementError::SocketUnavailable)
    );
    fs::remove_dir(&dir).unwrap();
}
