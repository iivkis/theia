use std::path::Path;
use theia::{
    diagnostics, help, local_proxy, management, parse, server, tui, validate_config, version,
    CliError, Command,
};

fn main() {
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    // Windows' small default stacks are insufficient for the debug and
    // instrumented async carrier call chains. Reserve, do not commit, 8 MiB
    // per worker; ordinary allocation and queue limits remain unchanged.
    #[cfg(windows)]
    runtime.thread_stack_size(8 * 1024 * 1024);
    runtime
        .build()
        .expect("create Theia runtime")
        .block_on(Box::pin(run()));
}

async fn run() {
    diagnostics::init();
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        if let Some(location) = panic.location() {
            diagnostics::emit(
                diagnostics::Level::Error,
                "process",
                "panic",
                &[(
                    "line",
                    diagnostics::Value::Count(u64::from(location.line())),
                )],
                location.file(),
                location.line(),
            );
        } else {
            theia::diag!(Error, "process", "panic_without_location");
        }
        diagnostics::flush();
        previous_hook(panic);
    }));
    theia::diag!(
        Info,
        "process",
        "started",
        "argv_count" =
            diagnostics::Value::Count(std::env::args_os().len().saturating_sub(1) as u64)
    );
    let args: Result<Vec<String>, CliError> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string().map_err(|_| CliError::NonUtf8Argument))
        .collect();
    let result: Result<String, CliError> = match args.and_then(|args| parse(&args)) {
        Ok(Command::Tui { role }) => tui::run(role, None)
            .map(|_| "tui closed".to_owned())
            .map_err(|error| CliError::Tui(error.message())),
        Ok(Command::TuiEdit { role, config }) => tui::run(Some(role), Some(Path::new(&config)))
            .map(|_| "tui closed".to_owned())
            .map_err(|error| CliError::Tui(error.message())),
        Ok(Command::ServerRun { config }) => Box::pin(server::run_file(Path::new(&config)))
            .await
            .map(|_| "server stopped".to_owned())
            .map_err(CliError::Server),
        Ok(Command::ClientRun { config }) => Box::pin(local_proxy::run_file(Path::new(&config)))
            .await
            .map(|_| "client stopped".to_owned())
            .map_err(CliError::Client),
        Ok(Command::ClientRunSystemProxy { config }) => {
            #[cfg(windows)]
            {
                Box::pin(local_proxy::run_file_with_system_proxy(Path::new(&config)))
                    .await
                    .map(|_| "client stopped; conditional WinINet proxy restore completed".to_owned())
                    .map_err(CliError::Client)
            }
            #[cfg(not(windows))]
            {
                let _ = config;
                Err(CliError::NotImplemented("Windows user proxy"))
            }
        }
        Ok(Command::WinDivertGuardHolder) => {
            // The parent duplicates exactly one already-open lab handle
            // into this bounded fixture. No driver or network access here.
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            Ok("WinDivert handle holder exited".to_owned())
        }
        Ok(Command::ClientWinDivertScopeDropLab { directory,dll_sha256,sys_sha256,interface,seconds }) => {
            #[cfg(all(windows,target_arch="x86_64"))]
            {
                theia::routing::windivert::scope_drop_acceptance(directory.into(),dll_sha256,sys_sha256,interface,seconds).await
                    .map(|s|format!("WinDivert scope drop lab finished; observed={} tcp4={} tcp6={} udp4={} udp6={} unsupported_or_malformed={} distinct_tuples={}; all captured packets discarded; no persistent protection or application identity asserted",s.observed(),s.tcp_v4,s.tcp_v6,s.udp_v4,s.udp_v6,s.unsupported_or_malformed,s.distinct_tuples))
                    .map_err(|_|CliError::Client(theia::client::ClientError::Io))
            }
            #[cfg(not(all(windows,target_arch="x86_64")))]
            {
                let _=(directory,dll_sha256,sys_sha256,interface,seconds);
                Err(CliError::NotImplemented("WinDivert x64 Windows backend"))
            }
        }
        Ok(Command::ClientWinDivertRedirectLab { config,directory,dll_sha256,sys_sha256,targets,seconds }) => {
            #[cfg(all(windows,target_arch="x86_64"))]
            {
                local_proxy::NativeIngress::run_windows_redirect_lab(Path::new(&config),directory.into(),dll_sha256,sys_sha256,targets,seconds).await
                    .map(|_|"WinDivert scoped TCP/UDP redirect laboratory ended; capture inactive; no production readiness or successful application exchange asserted".to_owned())
                    .map_err(CliError::Client)
            }
            #[cfg(not(all(windows,target_arch="x86_64")))]
            {
                let _=(config,directory,dll_sha256,sys_sha256,targets,seconds);
                Err(CliError::NotImplemented("WinDivert x64 Windows backend"))
            }
        }
        Ok(Command::ClientWinDivertTcpRelayLab { config,directory,dll_sha256,sys_sha256,target }) => {
            #[cfg(all(windows,target_arch="x86_64"))]
            {
                local_proxy::NativeIngress::run_windows_tcp_relay_lab(Path::new(&config),directory.into(),dll_sha256,sys_sha256,target).await
                    .map(|_|"WinDivert authorized TCP echo through the configured authenticated carrier verified; capture inactive".to_owned())
                    .map_err(CliError::Client)
            }
            #[cfg(not(all(windows,target_arch="x86_64")))]
            {
                let _=(config,directory,dll_sha256,sys_sha256,target);
                Err(CliError::NotImplemented("WinDivert x64 Windows backend"))
            }
        }
        Ok(Command::ClientWinDivertUdpRelayLab { config,directory,dll_sha256,sys_sha256,target,flows }) => {
            #[cfg(all(windows,target_arch="x86_64"))]
            {
                local_proxy::NativeIngress::run_windows_udp_relay_lab(Path::new(&config),directory.into(),dll_sha256,sys_sha256,target,flows).await
                    .map(|_|"WinDivert authorized UDP echo through the configured authenticated carrier verified; capture inactive".to_owned())
                    .map_err(CliError::Client)
            }
            #[cfg(not(all(windows,target_arch="x86_64")))]
            {
                let _=(config,directory,dll_sha256,sys_sha256,target,flows);
                Err(CliError::NotImplemented("WinDivert x64 Windows backend"))
            }
        }
        Ok(Command::ClientWinDivertLoopback { directory, dll_sha256, sys_sha256 }) => {
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                theia::routing::windivert::loopback_acceptance(directory.into(),dll_sha256,sys_sha256).await
                    .map(|_| "WinDivert isolated IPv4/IPv6 TCP redirect, UDP receive/send/reverse socket lifecycle and scoped crash guard verified; capture inactive".to_owned())
                    .map_err(|_| CliError::Client(theia::client::ClientError::Io))
            }
            #[cfg(not(all(windows, target_arch = "x86_64")))]
            {
                let _ = (directory,dll_sha256,sys_sha256);
                Err(CliError::NotImplemented("WinDivert x64 Windows backend"))
            }
        }
        Ok(Command::ClientWinDivertCheck { directory, dll_sha256, sys_sha256, install_lab }) => {
            #[cfg(all(windows, target_arch = "x86_64"))]
            {
                theia::routing::windivert::probe(Path::new(&directory), dll_sha256, sys_sha256, install_lab)
                    .map(|_| "WinDivert 2.2 API available; capture inactive; loaded driver hash not attested".to_owned())
                    .map_err(|_| CliError::Client(theia::client::ClientError::Io))
            }
            #[cfg(not(all(windows, target_arch = "x86_64")))]
            {
                let _ = (directory, dll_sha256, sys_sha256, install_lab);
                Err(CliError::NotImplemented("WinDivert x64 Windows backend"))
            }
        }
        Ok(Command::ClientStatus)=>{
            match management::query_client_environment(management::StatusCommand::ClientStatus).await{
                Ok(management::StatusReply::ClientRunning{revision,config_sha256,descriptor_revision,transport,xhttp,fallback,routing_revision,routing_state,routing_totals,flow_counts,capture_state})=>{
                    let digest=config_sha256.iter().map(|b|format!("{b:02x}")).collect::<String>();
                    let capture = match capture_state { 0=>"inactive", 1=>"preparing", 2=>"isolated_lab", _=>"recovery_required" };
                    Ok(format!("client running; revision={revision}; config_sha256={digest}; descriptor_revision={descriptor_revision}; last_open_transport={transport}; last_open_xhttp={xhttp}; h3_negative_cache={fallback}; routing_revision={routing_revision}; routing_state={routing_state}; routing_totals={routing_totals:?}; flow_counts={flow_counts:?}; packet_interception={capture}"))
                }
                Ok(_)=>Err(CliError::Management(management::ManagementError::InvalidReply)),
                Err(error)=>Err(CliError::Management(error)),
            }
        }
        Ok(Command::ClientApply{expected_revision,candidate_sha256,apply})=>{
            let command=if apply{management::StatusCommand::ClientApply{expected_revision,candidate_sha256}}
                else{management::StatusCommand::ClientPreview{expected_revision,candidate_sha256}};
            match management::query_client_environment(command).await{
                Ok(management::StatusReply::ClientReady{revision})=>Ok(format!("client candidate ready; revision={revision}; nothing applied")),
                Ok(management::StatusReply::ClientApplied{revision})=>Ok(format!("client carrier applied; revision={revision}; existing tunnels retained")),
                Ok(_)=>Err(CliError::Management(management::ManagementError::InvalidReply)),
                Err(error)=>Err(CliError::Management(error)),
            }
        }
        Ok(Command::ClientProxyStatus) => {
            #[cfg(windows)]
            {
                theia::windows_system_proxy::status()
                    .map(|state| format!("Windows user proxy recovery status: {state:?}; no changes"))
                    .map_err(CliError::SystemProxy)
            }
            #[cfg(not(windows))]
            {
                Err(CliError::NotImplemented("Windows user proxy"))
            }
        }
        Ok(Command::ClientProxyRecover) => {
            #[cfg(windows)]
            {
                theia::windows_system_proxy::recover_explicit()
                    .map(|state| format!("Windows user proxy recovery: {state:?}; no foreign edits overwritten"))
                    .map_err(CliError::SystemProxy)
            }
            #[cfg(not(windows))]
            {
                Err(CliError::NotImplemented("Windows user proxy"))
            }
        }
        Ok(Command::ServerStatus) => {
            match management::query_environment(management::StatusCommand::Status).await {
                Ok(management::StatusReply::Running { inbounds }) => Ok(format!(
                    "server running; {inbounds} inbounds; reload not available"
                )),
                Ok(management::StatusReply::RunningRevision { inbounds, revision }) => Ok(format!(
                    "server running; {inbounds} inbounds; authorization revision={revision}"
                )),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerApplyReloadBound{expected_revision,candidate_sha256})=>{
            match management::query_environment(management::StatusCommand::ApplyReloadBound{expected_revision,candidate_sha256}).await{
                Ok(management::StatusReply::Applied{revision})=>Ok(format!("authorization applied; revision={revision}; existing tunnels retained")),
                Ok(_)=>Err(CliError::Management(management::ManagementError::InvalidReply)),
                Err(error)=>Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerRestartRollbackCheck)=>{
            match management::query_environment(management::StatusCommand::CheckRestartRollback).await{
                Ok(management::StatusReply::RestartRollbackReady{revision,remaining_seconds})=>Ok(format!("structural rollback ready; revision={revision}; remaining_seconds={remaining_seconds}; no change applied")),
                Ok(_)=>Err(CliError::Management(management::ManagementError::InvalidReply)),Err(error)=>Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerRestartRollbackApply{expected_revision})=>{
            match management::query_environment(management::StatusCommand::ApplyRestartRollback{expected_revision}).await{
                Ok(management::StatusReply::RestartRollbackApplied{revision})=>Ok(format!("structural rollback applied; revision={revision}; saved TOML unchanged; latest rooted identity retained")),
                Ok(_)=>Err(CliError::Management(management::ManagementError::InvalidReply)),Err(error)=>Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerAuthRollbackCheck)=>{
            match management::query_environment(management::StatusCommand::CheckAuthRollback).await{
                Ok(management::StatusReply::AuthRollbackReady{revision,remaining_seconds})=>Ok(format!("authorization rollback ready; revision={revision}; remaining_seconds={remaining_seconds}; no change applied")),
                Ok(_)=>Err(CliError::Management(management::ManagementError::InvalidReply)),
                Err(error)=>Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerAuthRollbackApply{expected_revision})=>{
            match management::query_environment(management::StatusCommand::ApplyAuthRollback{expected_revision}).await{
                Ok(management::StatusReply::AuthRollbackApplied{revision})=>Ok(format!("authorization rollback applied; revision={revision}; slot consumed; saved TOML unchanged")),
                Ok(_)=>Err(CliError::Management(management::ManagementError::InvalidReply)),
                Err(error)=>Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerApplyReload { expected_revision }) => {
            match management::query_environment(management::StatusCommand::ApplyReload {
                expected_revision,
            })
            .await
            {
                Ok(management::StatusReply::Applied { revision }) => Ok(format!(
                    "authorization applied; revision={revision}; existing tunnels retained"
                )),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerCheckQuota) => {
            match management::query_environment(management::StatusCommand::CheckQuota).await {
                Ok(management::StatusReply::QuotaReady) => Ok(
                    "quota-only candidate ready: live session/connection limits may change under CAS; existing tunnels UNCHANGED; nothing applied".to_owned(),
                ),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerApplyQuota {
            expected_revision,
            candidate_sha256,
        }) => {
            match management::query_environment(
                management::StatusCommand::ApplyQuotaBound {
                    expected_revision,
                    candidate_sha256,
                },
            )
            .await
            {
                Ok(management::StatusReply::QuotaApplied { revision }) => Ok(format!(
                    "quota caps applied live; revision={revision}; old tunnels retained; cap contraction blocks new admission until occupancy drops"
                )),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerTlsRollbackCheck) => {
            match management::query_environment(management::StatusCommand::CheckTlsRollback).await {
                Ok(management::StatusReply::TlsRollbackReady {
                    revision,
                    remaining_seconds,
                }) => Ok(format!(
                    "last same-port TLS identity rollback ready; revision={revision}; remaining_seconds={remaining_seconds}; no change applied"
                )),
                Ok(_) => Err(CliError::Management(management::ManagementError::InvalidReply)),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerTlsRollbackApply { expected_revision }) => {
            match management::query_environment(management::StatusCommand::ApplyTlsRollback {
                expected_revision,
            }).await {
                Ok(management::StatusReply::TlsRollbackApplied { revision }) => Ok(format!(
                    "previous same-port H2/H3 TLS identity restored from memory; revision={revision}; current tunnels and auth retained; rollback slot consumed"
                )),
                Ok(_) => Err(CliError::Management(management::ManagementError::InvalidReply)),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerTlsFingerprint { config }) => {
            match server::tls_fingerprint_file(Path::new(&config)) {
                Ok(digest) => Ok(format!(
                    "theia-tls-pem-v1 sha256={}",
                    digest
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                )),
                Err(error) => Err(CliError::Server(error)),
            }
        }
        Ok(Command::ServerApplyRestart {
            expected_revision,
            candidate_sha256,
            tls_sha256,
        }) => {
            match management::query_environment(
                management::StatusCommand::ApplyRestartBound {
                    expected_revision,
                    candidate_sha256,
                    tls_sha256,
                },
            )
            .await
            {
                Ok(management::StatusReply::RestartApplied { revision }) => Ok(format!(
                    "supervised H2/H3 restart applied; revision={revision}; same-port TLS keeps old tunnels, fresh-port cutover drains old up to 20s; no automatic rollback"
                )),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerCheckRestart) => {
            match management::query_environment(management::StatusCommand::CheckRestart).await {
                Ok(management::StatusReply::RestartAuthorizationOnly) => Ok(
                    "restart not needed for compatible authorization changes; use CAS auth Apply; runtime UNCHANGED".to_owned(),
                ),
                Ok(management::StatusReply::RestartSamePortTlsReady) => Ok(
                    "same-port TLS rotation ready: original H2/H3 bind addresses retained; explicit --apply --expected-revision N --sha256 HEX --confirm required; runtime UNCHANGED".to_owned(),
                ),
                Ok(management::StatusReply::RestartRequiresMaintenance) => Ok(
                    "restart requires controlled maintenance: active listener addresses overlap; runtime UNCHANGED".to_owned(),
                ),
                Ok(management::StatusReply::RestartFreshPortsBindable) => Ok(
                    "restart readiness probe passed: new TCP/UDP ports temporarily bound then released; runtime UNCHANGED; NOT reserved or applied".to_owned(),
                ),
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::ServerCheckReload) => {
            match management::query_environment(management::StatusCommand::CheckReload).await {
                Ok(management::StatusReply::Compatible) => {
                    Ok("candidate compatible with running listener; runtime UNCHANGED".to_owned())
                }
                Ok(_) => Err(CliError::Management(
                    management::ManagementError::InvalidReply,
                )),
                Err(error) => Err(CliError::Management(error)),
            }
        }
        Ok(Command::Trust(command)) => theia::descriptor_cli::run(command).map_err(CliError::Trust),
        Ok(Command::Reference(command)) => theia::reference_cli::run(command)
            .await
            .map_err(CliError::Reference),
        Ok(Command::Reality(command)) => theia::reality_cli::run(command).map_err(CliError::Reality),
        Ok(Command::Help(topic)) => help(topic).map(str::to_owned),
        Ok(Command::Version) => Ok(version().to_owned()),
        Ok(Command::ConfigValidate { config }) => {
            validate_config(Path::new(&config)).map(str::to_owned)
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(message) => {
            theia::diag!(Info, "process", "completed");
            println!("{message}");
        }
        Err(error) => {
            let class = match &error {
                CliError::InvalidArguments => "invalid_arguments",
                CliError::InvalidRole => "invalid_role",
                CliError::InvalidConfigPath => "invalid_config_path",
                CliError::NonUtf8Argument => "non_utf8_argument",
                CliError::NotImplemented(_) => "not_implemented",
                CliError::Config(_) => "config",
                CliError::Trust(_) => "offline_trust",
                CliError::Reference(_) => "reference_health",
                CliError::Reality(_) => "reality_provisioning",
                CliError::Server(_) => "server",
                CliError::Management(_) => "management",
                CliError::Client(_) => "client",
                #[cfg(windows)]
                CliError::SystemProxy(_) => "system_proxy",
                CliError::Tui(_) => "tui",
            };
            theia::diag!(
                Error,
                "process",
                "failed",
                "error_class" = diagnostics::Value::Label(class)
            );
            eprintln!("theia: {error}");
            diagnostics::flush();
            std::process::exit(error.exit_code());
        }
    }
    diagnostics::flush();
}
