//! M4.2b0 TDD: preflight only; no config mutation or live reload.
//! The check is deliberately narrower than full transactional Apply.
use theia::{
    config::{Config, Inbound, Management, ServerDocument, ServerPolicy, ServerSettings, Ui, User},
    reload_preflight::{assess_reload, ReloadCheckError},
};

fn baseline() -> ServerDocument {
    ServerDocument {
        schema_version: 1,
        server: ServerSettings {
            enabled: true,
            inbounds: vec![Inbound {
                id: "edge".into(),
                allowed_user_ids: vec!["a".into()],
                quic_listen: "0.0.0.0:8443".into(),
                h2_listen: "0.0.0.0:8443".into(),
                server_name: "edge.example.org".into(),
                tls_cert: "file:/etc/theia/fullchain.pem".into(),
                tls_key: "file:/etc/theia/private.pem".into(),
            }],
            users: vec![
                User {
                    id: "a".into(),
                    token_sha256: "a".repeat(64),
                    disabled: false,
                },
                User {
                    id: "b".into(),
                    token_sha256: "b".repeat(64),
                    disabled: false,
                },
            ],
            policy: ServerPolicy {
                allow_private_ips: false,
                max_connections_per_user: 2,
                max_connections_total: 16,
                connect_timeout_ms: 1000,
            },
        },
        management: Management {
            ipc: "auto".into(),
            log_level: "info".into(),
        },
        ui: Ui {
            language: "ru".into(),
        },
    }
}

#[test]
fn unchanged_candidate_is_accepted_without_reporting_applied() {
    let before = baseline();
    assert_eq!(Config::Server(before.clone()).validate(), Ok(()));
    assert_eq!(assess_reload(&before, &before), Ok(()));
}

#[test]
fn token_rotation_disabling_user_and_inbound_grant_change_are_only_allowed_delta() {
    let before = baseline();
    let mut candidate = before.clone();
    candidate.server.users[0].token_sha256 = "c".repeat(64);
    candidate.server.users[1].disabled = true;
    candidate.server.inbounds[0].allowed_user_ids = vec!["b".into()];
    assert_eq!(Config::Server(candidate.clone()).validate(), Ok(()));
    assert_eq!(assess_reload(&before, &candidate), Ok(()));
}

#[test]
fn listener_cert_and_identity_changes_require_restart_even_if_structurally_valid() {
    let before = baseline();
    let changes: [fn(&mut ServerDocument); 5] = [
        |doc| doc.server.inbounds[0].h2_listen = "0.0.0.0:8444".into(),
        |doc| doc.server.inbounds[0].quic_listen = "0.0.0.0:8444".into(),
        |doc| doc.server.inbounds[0].server_name = "new.example.org".into(),
        |doc| doc.server.inbounds[0].tls_cert = "file:/etc/theia/other.pem".into(),
        |doc| doc.server.inbounds[0].tls_key = "file:/etc/theia/other.key".into(),
    ];
    for change in changes {
        let mut candidate = before.clone();
        change(&mut candidate);
        assert_eq!(
            assess_reload(&before, &candidate),
            Err(ReloadCheckError::RequiresRestart)
        );
    }
}

#[test]
fn changing_policy_quota_log_level_or_user_registry_is_not_claimed_compatible() {
    let before = baseline();
    let mut changes = Vec::new();
    let mut doc = before.clone();
    doc.server.policy.allow_private_ips = true;
    changes.push(doc);
    let mut doc = before.clone();
    doc.server.policy.max_connections_total = 32;
    changes.push(doc);
    let mut doc = before.clone();
    doc.management.log_level = "warn".into();
    changes.push(doc);
    let mut doc = before.clone();
    doc.server.users.swap(0, 1);
    changes.push(doc);
    let mut doc = before.clone();
    doc.server.users[0].id = "renamed".into();
    doc.server.inbounds[0].allowed_user_ids = vec!["renamed".into()];
    changes.push(doc);
    let mut doc = before.clone();
    doc.ui.language = "en".into();
    changes.push(doc);
    let mut doc = before.clone();
    let mut added = doc.server.inbounds[0].clone();
    added.id = "second".into();
    added.h2_listen = "0.0.0.0:8444".into();
    added.quic_listen = "0.0.0.0:8444".into();
    doc.server.inbounds.push(added);
    changes.push(doc);
    for candidate in changes {
        assert_eq!(
            assess_reload(&before, &candidate),
            Err(ReloadCheckError::RequiresRestart)
        );
    }
}

#[test]
fn invalid_grants_and_disabled_server_fail_before_compatibility_check() {
    let before = baseline();
    let mut candidate = before.clone();
    candidate.server.inbounds[0].allowed_user_ids = vec!["missing".into()];
    assert_eq!(
        assess_reload(&before, &candidate),
        Err(ReloadCheckError::InvalidConfig)
    );

    let mut candidate = before.clone();
    candidate.server.enabled = false;
    assert_eq!(
        assess_reload(&before, &candidate),
        Err(ReloadCheckError::RequiresRestart)
    );
}
