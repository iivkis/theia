//! M4.2e: cross-logon kernel ACL regression for the actual WindowsServer.
//! The test is CI-only and never opens a network listener or OS proxy.
#![cfg(target_os = "windows")]

use std::{
    env, ffi::c_void, mem::size_of, path::PathBuf, process::Command, ptr::null_mut, time::Duration,
};
use theia::{
    management::{StatusCommand, StatusReply},
    windows_control::{current_user_sid, pipe_name, query_pipe, WindowsServer},
};
use tokio::{
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    time::{sleep, timeout},
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW, SECURITY_ATTRIBUTES,
    },
};

// This deliberately open *test-only* local pipe is a positive control: a
// different Windows logon must be able to open a kernel pipe on this runner.
// Otherwise a denial against the production DACL would prove nothing.
fn test_only_everyone_pipe(name: &str) -> NamedPipeServer {
    let sddl = "D:P(A;;GA;;;WD)";
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: valid NUL-terminated SDDL and writable output pointer.
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        },
        0,
        "test-only positive-control DACL must be created"
    );
    assert!(!descriptor.is_null());
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options.first_pipe_instance(true);
    options.reject_remote_clients(true);
    // SAFETY: descriptor and attributes live through synchronous CreateNamedPipeW.
    let result = unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
        )
    };
    // SAFETY: descriptor was returned by Windows LocalAlloc API.
    unsafe { LocalFree(descriptor) };
    result.expect("must bind local positive-control pipe")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI-only: requires a disposable local account with a different Windows SID"]
async fn different_windows_sid_is_denied_by_kernel_dacl() {
    assert!(env::var_os("CI").is_some(), "only run on isolated CI");
    assert!(
        env::var_os("THEIA_CROSS_SID_USERNAME").is_some()
            && env::var_os("THEIA_CROSS_SID_PASSWORD").is_some(),
        "CI must provision a separate unprivileged Windows logon"
    );

    let id = format!("crosssid{}", std::process::id());
    let owner_sid = current_user_sid().expect("real OS TokenUser SID");
    let manager = WindowsServer::bind(&id, 1).expect("real protected Named Pipe");
    let protected_name = pipe_name(&id).expect("canonical protected pipe name");
    let positive_name = format!(r"\\.\pipe\theia-cross-sid-positive-{}", std::process::id());
    let _positive = test_only_everyone_pipe(&positive_name);
    let task = tokio::spawn(manager.serve());

    timeout(Duration::from_secs(8), async {
        loop {
            if query_pipe(&id, StatusCommand::Status).await
                == Ok(StatusReply::Running { inbounds: 1 })
            {
                break;
            }
            assert!(
                !task.is_finished(),
                "the actual pipe server must remain alive"
            );
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("same-SID status must succeed before cross-logon negative test");

    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/windows-cross-sid-probe.ps1");
    let run = tokio::task::spawn_blocking(move || {
        Command::new("pwsh")
            .args(["-NoProfile", "-NonInteractive", "-File"])
            .arg(script)
            .env("THEIA_CROSS_SID_OWNER", owner_sid)
            .env("THEIA_CROSS_SID_TARGET_PIPE", protected_name)
            .env("THEIA_CROSS_SID_POSITIVE_PIPE", positive_name)
            .output()
    });
    let result = timeout(Duration::from_secs(70), run)
        .await
        .expect("cross-user probe timed out")
        .expect("cross-user probe thread panicked")
        .expect("could not run native Windows cross-user probe");
    task.abort();
    assert!(
        result.status.success(),
        "kernel SID isolation failed; stdout: {}; stderr: {}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("CROSS_SID_KERNEL_DENY_OK"),
        "probe must emit positive proof, not merely exit zero"
    );
}
