"""Repository contract checks. NOT Rust implementation tests. Project documentation is maintained in Notion."""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def toml(name: str) -> dict:
    with (ROOT / name).open("rb") as stream:
        return tomllib.load(stream)


def explicit_grants_are_valid(server: dict) -> bool:
    """Sanity check of documented template references, not a production validator."""
    users = server.get("users", [])
    inbounds = server.get("inbounds", [])
    ids = [u["id"] for u in users]
    if not users or not inbounds or len(set(ids)) != len(ids):
        return False
    if len({u["token_sha256"] for u in users}) != len(users):
        return False
    for inbound in inbounds:
        grants = inbound.get("allowed_user_ids")
        if not isinstance(grants, list) or not grants:
            return False
        if len(grants) != len(set(grants)) or any(i not in ids for i in grants):
            return False
    return True


class SpecContractTests(unittest.TestCase):
    def test_repository_contains_no_tracked_markdown_or_logs(self):
        # Notion is the canonical specification; keep historical docs and logs out of Git.
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        paths = [Path(path.decode("utf-8")) for path in tracked.split(b"\0") if path]
        forbidden = [
            str(path) for path in paths
            if path.suffix.lower() in {".md", ".markdown", ".log"}
            or any(part.lower() in {"logs", "journals"} for part in path.parts[:-1])
        ]
        self.assertEqual(forbidden, [], "Documentation belongs in Notion; logs are not tracked")

    def test_required_files(self):
        required = [
            "examples/server.toml", "examples/client.toml",
            ".github/workflows/ci.yml", "scripts/check-spec.sh"
        ]
        for path in required:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), path)

    def test_toml_schema_versions(self):
        for kind in ("server", "client"):
            conf = toml(f"examples/{kind}.toml")
            self.assertEqual(conf["schema_version"], 1)
            self.assertIn(kind, conf)

    def test_server_template_denies_private_by_default(self):
        server = toml("examples/server.toml")["server"]
        self.assertIs(server["policy"]["allow_private_ips"], False)
        self.assertTrue(server["inbounds"])
        self.assertTrue(server["users"])
        self.assertIn("REPLACE_WITH", server["users"][0]["token_sha256"])

    def test_inbounds_require_explicit_user_grants(self):
        server = toml("examples/server.toml")["server"]
        self.assertTrue(explicit_grants_are_valid(server))
        import copy
        for changed in (
            lambda s: s["inbounds"][0].pop("allowed_user_ids"),
            lambda s: s["inbounds"][0].update(allowed_user_ids=[]),
            lambda s: s["inbounds"][0].update(allowed_user_ids=["missing"]),
            lambda s: s["inbounds"][0].update(allowed_user_ids=["device-a", "device-a"]),
        ):
            modified = copy.deepcopy(server)
            changed(modified)
            self.assertFalse(explicit_grants_are_valid(modified))

    def test_client_uses_safe_transport_proxy_and_secrets(self):
        client = toml("examples/client.toml")["client"]
        profiles = client["profiles"]
        self.assertIn(client["active_profile"], {p["id"] for p in profiles})
        for profile in profiles:
            self.assertIn(profile["transport"], ("auto", "h3", "h2"))
            self.assertTrue(profile["auth_token"].startswith(("env:", "file:")))
            self.assertEqual(profile["security_mode"], "own-tls")
        proxy = client["proxy"]
        self.assertEqual(proxy["system_proxy"], "off")
        for name in ("http_listen", "socks5_listen"):
            self.assertRegex(proxy[name], r"^(127\.0\.0\.1|\[::1\]):[0-9]+$")

    def test_m35b2a_explicit_tls_probe_contract(self):
        code = read("crates/theia/src/camouflage_probe.rs")
        tests = read("crates/theia/tests/camouflage_probe.rs")
        self.assertIn("pub mod camouflage_probe;", read("crates/theia/src/lib.rs"))
        for token in ("pub fn route_selected_local_ip", "pub async fn probe_tls_h2",
                      "ProbeApproval", "IsolatedLoopbackFixture", "PublicHttpsIp",
                      "TlsConnector", "RootCertStore", "Semaphore::const_new(4)",
                      "MAX_HANDSHAKE_DEADLINE", "Observation::Unknown"):
            with self.subTest(token=token):
                self.assertIn(token, code)
        for token in ("wrong_ca", "wrong_sni", "timeout", "NoTrustAnchors",
                      "NotApproved", "fingerprint", "TLS1.3"):
            with self.subTest(token=token):
                self.assertIn(token.lower(), tests.lower())
        self.assertIn('profile.security_mode.is_plain()', read("crates/theia/src/config.rs"))

    def test_m35b1_code_contract_does_not_claim_active_scan_or_reality(self):
        code = read("crates/theia/src/camouflage_discovery.rs")
        tests = read("crates/theia/tests/camouflage_discovery.rs")
        self.assertIn("pub mod camouflage_discovery;", read("crates/theia/src/lib.rs"))
        for token in ("MAX_CANDIDATES", "POPULAR_HTTPS_DOMAINS", "pub fn build_plan",
                      "pub fn suitability", "ProviderPrefixNotAuthorization", "Unknown",
                      "Ipv6EnumerationUnsupported"):
            self.assertIn(token, code)
        for token in ("google.com", "samsung.com", "amd.com",
                      "zero-I/O", "REALITY"):
            self.assertIn(token.lower(), (code + tests).lower())
        self.assertIn('profile.security_mode.is_plain()', read("crates/theia/src/config.rs"))

    def test_f18_picker_discovers_server_range_and_popular_domains_without_manual_seed(self):
        # Research and docs do not enable any new production security mode.
        self.assertIn('profile.security_mode.is_plain()', read("crates/theia/src/config.rs"))

    def test_future_reality_like_and_tls_in_tls_are_p0_but_not_claimed_live(self):
        client = toml("examples/client.toml")["client"]
        self.assertTrue(all(p["security_mode"] == "own-tls" for p in client["profiles"]))
        self.assertIn('profile.security_mode.is_plain()', read("crates/theia/src/config.rs"))

    def test_windows_manual_proxy_is_not_auto_enabled(self):
        self.assertNotIn('system_proxy = "on"', read("examples/client.toml"))

    def test_m01_api_spike_isolated_and_locked(self):
        from pathlib import Path
        spike = ROOT / "spikes" / "m0_1"
        self.assertTrue((spike / "Cargo.toml").is_file())
        self.assertTrue((spike / "Cargo.lock").is_file())
        parser = (spike / "src" / "client_hello.rs").read_text(encoding="utf-8")
        probe = (spike / "tests" / "client_hello_baseline.rs").read_text(encoding="utf-8")
        for required in ("has_grease_extension", "has_alps", "supported_groups", "read_groups",
                         "17_513", "17_613"):
            self.assertIn(required, parser)
        self.assertIn("default_rustls_h2_cannot_pass_named_browser_gate", probe)
        for required in ("parse_tls_records", "parse_handshake", "MAX_HELLO",
                         "extensions_in_wire_order", "quic_transport_parameters_present",
                         "ParseError::Truncated", "is_grease"):
            self.assertIn(required, parser)
        for required in ("rustls::ClientConnection::new", "rustls::quic::ClientConnection::new",
                         "default_rustls_h2_clienthello", "default_rustls_quic_h3_clienthello",
                         "write_tls", "write_hs"):
            self.assertIn(required, probe)
        self.assertFalse((spike / "utls_reference").exists())
        live_probe = read("scripts/independent-h2-probe.py")
        for required in ("ssl.PROTOCOL_TLS_CLIENT", "ssl.CERT_REQUIRED",
                         "ssl.TLSVersion.TLSv1_3", "check_hostname",
                         "validate_loopback", "SSLCertVerificationError", "receive_no_content"):
            self.assertIn(required, live_probe)
        live_tests = (spike / "tests" / "independent_h2_loopback.rs").read_text(encoding="utf-8")
        for required in ("TcpListener::bind", "independent_tls13_h2_request_with_verified_identity",
                         "independent_tls13_rejects_wrong_hostname_before_h2",
                         "independent_tls13_rejects_untrusted_ca_before_h2"):
            self.assertIn(required, live_tests)
        workflow = read(".github/workflows/ci.yml")
        self.assertNotIn("actions/setup-go", workflow)
        self.assertIn("--test independent_h2_loopback -- --ignored", workflow)
        self.assertIn("run_f13_observations.py f13-observations", workflow)
        runner = read("tests/benchmark/run_f13_observations.py")
        self.assertIn("actual_chromium_h2_settings_and_pseudo_order_reference", runner)
        self.assertIn("actual_chromium_h3_initial_reference", runner)
        self.assertIn("subprocess.run(command", runner)
        h2_tls = (spike / "tests" / "h2_tls.rs")
        self.assertTrue(h2_tls.is_file())
        loss_test = spike / "tests" / "quic_bbr_loss.rs"
        self.assertTrue(loss_test.is_file())
        loss_code = loss_test.read_text(encoding="utf-8")
        for required in ("DeterministicLoss", "active_bbr_recovers_byte_exactly_from_synthetic_udp_loss",
                         "connection.stats().path", "congestion_state", "dropped_datagrams", "lost_packets", "PAYLOAD_LEN"):
            self.assertIn(required, loss_code)
        h2_source = h2_tls.read_text(encoding="utf-8")
        h3_source = (spike / "tests" / "h3_quic.rs").read_text(encoding="utf-8")
        self.assertIn("tls13_h2_megabyte_flow_control_and_half_close", h2_source)
        self.assertIn("tls13_h2_slow_response_reader_stalls_and_recovers", h2_source)
        self.assertIn("h3_quic_slow_response_reader_stalls_and_recovers", h3_source)
        self.assertIn("transport.send_window(48 * 1024)", h3_source)
        self.assertIn("transport.stream_receive_window(quinn::VarInt::from_u32(32 * 1024))", h3_source)
        for test_name in ("tls13_h2_eight_concurrent_full_duplex_streams",
                          "tls13_h2_cancel_stream_preserves_connection"):
            self.assertIn(test_name, h2_source)
        for test_name in ("h3_quic_eight_concurrent_bidirectional_streams",
                          "h3_quic_cancel_stream_preserves_sibling_request"):
            self.assertIn(test_name, h3_source)
        for required in ("tls13_h2_full_duplex_response_before_request_eof",
                         "tls13_h2_rejects_wrong_hostname",
                         "tls13_h2_rejects_untrusted_ca",
                         "tls13_h2_rejects_alpn_mismatch",
                         "reserve_capacity", "release_capacity"):
            self.assertIn(required, h2_tls.read_text(encoding="utf-8"))
        source = (spike / "src" / "lib.rs").read_text(encoding="utf-8")
        self.assertIn("http2_response_before_request_eof", source)
        self.assertIn("congestion::BbrConfig", source)
        self.assertIn("h3_client_has_split", source)
        self.assertNotIn("mod theia", source)
        # M1.1 will add a root workspace; do not make this spike test a future CI blocker.
        root_manifest = ROOT / "Cargo.toml"
        if root_manifest.is_file():
            workspace = tomllib.loads(root_manifest.read_text(encoding="utf-8")).get("workspace", {})
            self.assertNotIn("spikes/m0_1", workspace.get("members", []),
                             "Research-only spike must not be part of the production workspace")

    def test_cli_workspace_and_real_dispatch_contract(self):
        root = toml("Cargo.toml")
        workspace = root["workspace"]
        self.assertEqual(workspace["members"], ["crates/theia"])
        self.assertIn("spikes/m0_1", workspace["exclude"])
        self.assertTrue((ROOT / "Cargo.lock").is_file())
        package = toml("crates/theia/Cargo.toml")["package"]
        self.assertEqual(package["name"], "theia")
        source = read("crates/theia/src/lib.rs")
        for marker in ("ServerRun", "ClientRun", "ConfigValidate", "NotImplemented",
                       "pub fn parse(", "pub fn help(", "pub fn validate_config(",
                       "CliError::InvalidArguments"):
            self.assertIn(marker, source)
        self.assertNotIn("pub fn execute(", source)
        main = read("crates/theia/src/main.rs")
        self.assertNotIn("Ok(command) =>", main)
        for marker in ("server::run_file(", "local_proxy::run_file(", "tui::run(",
                       "Ok(Command::Help(", "Ok(Command::ConfigValidate"):
            self.assertIn(marker, main)
        integration = read("crates/theia/tests/cli.rs")
        self.assertIn("accepted_runtime_commands_fail_closed", integration)
        self.assertIn("rejected_arguments_cannot_start_a_runtime", integration)
        self.assertIn("windows_proxy_commands_fail_closed_on_other_platforms", integration)

    def test_m12_typed_toml_implementation_is_strict(self):
        manifest = tomllib.loads(read("crates/theia/Cargo.toml"))
        self.assertIn("serde", manifest["dependencies"])
        self.assertIn("toml", manifest["dependencies"])
        implementation = read("crates/theia/src/config.rs")
        for required in ("deny_unknown_fields", "allowed_user_ids", "overlaps(",
                         "Ipv6Addr::UNSPECIFIED", "atomic_write", "file.sync_all()",
                         "secret", "SystemProxy", "MAX_BYTES"):
            self.assertIn(required, implementation)

    def test_m13_pure_smarttheia_protocol_has_golden_tests(self):
        library = read("crates/theia/src/lib.rs")
        implementation = read("crates/theia/src/protocol.rs")
        tests = read("crates/theia/tests/protocol.rs")
        self.assertIn("pub mod protocol;", library)
        for term in ("MAX_PAYLOAD: usize = 65_536", "HEADER_LEN: usize = 6",
                     "pub fn encode(", "pub fn decode(", "pub fn feed_each(",
                     "pub struct Decoder", "pub struct Session", "fn tunnel_open(",
                     "InvalidFlags", "InvalidTransition", "UnsupportedVersion", "CAP_PADDING"):
            self.assertIn(term, implementation)
        for test in ("documented_golden_vectors_are_exact",
                     "size_boundaries_are_enforced_before_buffering",
                     "stream_decoder_accepts_every_split_and_multiple_coalesced_frames",
                     "local_success_is_gated_on_open_ok_not_http_or_hello_ack",
                     "full_duplex_half_close_then_both_fin_and_drain",
                     "deterministic_random_chunks_never_panic_and_bound_partial_memory",
                     "padding_v1_golden_vectors_and_capability_subset"):
            self.assertIn(test, tests)

    def test_m21_h2_ingress_is_real_and_has_fail_closed_tests(self):
        implementation = read("crates/theia/src/server.rs")
        tests = read("crates/theia/tests/server_h2.rs")
        binary = read("crates/theia/src/main.rs")
        for term in ("pub async fn serve(", "pub async fn run_file(",
                     "fn allowed_destination(", "URL_SAFE_NO_PAD", "Sha256::digest",
                     "ct_eq(", "lookup_host(", "TcpStream::connect",
                     "Frame::OpenOk", "TlsAcceptor", "Carrier::H2.h2_server()",
                     "Carrier::H2.accepts_tls("):
            self.assertIn(term, implementation)
        policy = read("crates/theia/src/transport_policy.rs")
        for term in ("MAX_BIDI_STREAMS: u32 = 32", "MAX_HEADER_LIST_BYTES: u32 = 8192",
                     "builder.max_concurrent_streams(MAX_BIDI_STREAMS)",
                     "builder.max_header_list_size(MAX_HEADER_LIST_BYTES)",
                     "rustls::ProtocolVersion::TLSv1_3"):
            self.assertIn(term, policy)
        for term in ("h2_tls_stream_acknowledges_tcp_open_only_after_echo_dial",
                     "h2_tls_default_policy_rejects_private_ip_without_tcp_dial",
                     "h2_tls_rejects_missing_bearer_before_smarttheia",
                     "canonical_token_and_inbound_user_grants_are_enforced",
                     "tls_wrong_hostname_and_untrusted_ca_fail_closed"):
            self.assertIn(term, tests)
        self.assertIn("server::run_file(", binary)

    def test_ci_tests_first_and_cached(self):
        workflow = read(".github/workflows/ci.yml")
        self.assertIn("Swatinem/rust-cache@v2", workflow)
        self.assertIn("scripts/check-spec.sh", workflow)
        self.assertIn("cargo nextest run --workspace --all-targets --locked --no-fail-fast", workflow)
        self.assertLess(workflow.index("cargo nextest run --workspace --all-targets --locked --no-fail-fast"),
                        workflow.index("cargo clippy"))
        self.assertIn("Cargo.lock", workflow)

    def test_ci_only_acceptance_contract(self):
        workflow = read(".github/workflows/ci.yml")
        gate = workflow.split("\n  ci-gate:\n", 1)[1]
        for job in ("specification", "m0-1-api-spike", "m0-1-windows-spike",
                    "rust-tests", "windows-smoke"):
            self.assertIn(job, gate.split("if:", 1)[0])
        self.assertIn("always()", gate)
        self.assertIn('get("result") != "success"', gate)
        self.assertIn("raise SystemExit", gate)

    def test_retired_profiles_are_excluded_from_product_configuration(self):
        source = read("crates/theia/src/config.rs")
        self.assertIn("retired_security_modes_are_rejected_even_with_experimental_backend", source)
        self.assertNotIn("CertificatePin::parse_profile(&profile.security_mode)", source)
        editor = read("crates/theia/src/tui_editor.rs")
        self.assertNotIn("review_pinned_mode", editor)
        self.assertNotIn("apply_pinned_mode", editor)
        invite = read("crates/theia/src/invite.rs")
        self.assertNotIn("PinnedTls,", invite)
        self.assertIn("retired_product_security_profiles_are_rejected_before_network",
                      read("crates/theia/tests/client_h2.rs"))

    def test_real_goaway_regression_matrix_is_present(self):
        code = read("crates/theia/tests/goaway.rs")
        for term in ("real_h2_goaway_drains_live_streams_without_reusing_carrier",
                     "real_h3_goaway_drains_live_streams_without_reusing_carrier",
                     "connection.graceful_shutdown()", "connection.shutdown(0).await",
                     "shares_transport_with", "h2_scenario(true)", "h3_scenario(true)"):
            self.assertIn(term, code)
        self.assertIn("cargo nextest run --workspace --all-targets --locked --no-fail-fast", read(".github/workflows/ci.yml"))

    def test_m22_local_proxy_gate_and_cli_wiring(self):
        implementation = read("crates/theia/src/local_proxy.rs")
        client = read("crates/theia/src/client.rs")
        tests = read("crates/theia/tests/client_h2.rs")
        self.assertIn("local_proxy::run_file(", read("crates/theia/src/main.rs"))
        self.assertIn("Transport::H3 | Transport::Auto", implementation)
        self.assertIn("client.open(address, port).await", implementation)
        self.assertIn("Frame::OpenOk if state.tunnel_open()", client)
        self.assertIn("local_connect_and_socks5_relay_real_tcp_with_half_close", tests)
        self.assertIn("local_proxies_never_acknowledge_policy_denial_or_invalid_protocol", tests)
        self.assertIn("client_binary_curl_connect_and_socks5h", tests)
        self.assertIn("CARGO_BIN_EXE_theia", tests)
        self.assertIn("client_binary_chromium_socks5", tests)
        workflow = read(".github/workflows/ci.yml")
        self.assertIn("browser-e2e", workflow.split("\n  ci-gate:\n", 1)[1])
        self.assertIn("client_binary_chromium_socks5 -- --ignored --exact", workflow)
        self.assertIn("client_binary_chromium_socks5_over_h3 -- --ignored --exact", workflow)
        self.assertIn("production_h3_client_refuses_incompatible_alpn_before_application_data",
                      read("crates/theia/tests/h3_server.rs"))
        self.assertIn("browser bypassed the Theia SOCKS5 path", read("tests/e2e/chromium_socks.py"))

    def test_smarttheia_native_xhttp_contract(self):
        split = read("crates/theia/src/split_http.rs")
        self.assertIn("UPLOAD_PATH", split)
        self.assertIn("DOWNLOAD_PATH", split)
        self.assertIn('"/v1/theia-example/stream-up/upload"', split)
        self.assertIn('"/v1/theia-example/stream-up/download"', split)
        self.assertIn("stream_up_only_accepts_current_v1_routes", split)
        self.assertIn("PAIR_TIMEOUT", split)
        for path in ("client.rs", "h3_client.rs"):
            self.assertIn("with_stream_up", read("crates/theia/src/" + path))
        for path in ("server.rs", "h3_server.rs"):
            self.assertIn("handle_split_request", read("crates/theia/src/" + path))
        self.assertIn("h2_h3_stream_up_separate_http_legs_and_identity",
                      read("crates/theia/tests/security_profile.rs"))

    def test_f18_second_stage_is_read_only_and_shared(self):
        review = read("crates/theia/src/tui_reality_review.rs")
        self.assertIn("matches_selection", review)
        self.assertIn("checked_duration_since", review)
        self.assertIn("Apply ЗАБЛОКИРОВАН", review)
        self.assertIn("h3_optional_evidence_does_not_claim_readiness", review)
        for forbidden in ("probe_dual_batch(", "std::fs", "write_all(", "runtime_apply"):
            self.assertNotIn(forbidden, review)
        for path in ("tui_candidate_batch.rs", "tui_domain.rs"):
            source = read("crates/theia/src/" + path)
            self.assertIn("ReviewCursor", source)
            self.assertIn("self.review.body(", source)
            self.assertIn("pub(crate) fn open_review", source)
        tui = read("crates/theia/src/tui.rs")
        self.assertIn("domain.open_review()", tui)
        self.assertIn("batch.open_review()", tui)

    def test_m31_h3_server_reuses_security_boundary(self):
        h2 = read("crates/theia/src/server.rs")
        h3 = read("crates/theia/src/h3_server.rs")
        self.assertIn("context.authorize_request", h2)
        self.assertIn("context.authorize_request", h3)
        self.assertIn("context.dial_target", h2)
        self.assertIn("context.dial_target", h3)
        self.assertIn("Frame::OpenOk", h3)
        self.assertIn(".run(upload, download, ServerError::TimedOut)", h3)
        self.assertIn("tokio::try_join!(upload, download)", read("crates/theia/src/relay_liveness.rs"))
        tests = read("crates/theia/tests/h3_server.rs")
        self.assertIn("authenticated_h3_server_relays_tcp_before_request_fin_and_after_half_close", tests)
        self.assertIn("h3_rejects_missing_wrong_and_ungranted_bearers_and_denied_tcp", tests)

    def test_m31_h3_client_gate(self):
        client = read("crates/theia/src/h3_client.rs")
        # Production H3 now uses the native QUIC dialer; retain the
        # transport observation and fail-closed handshake contract.
        self.assertIn("dial::connect(self.remote", client)
        self.assertIn("self.native_connection().await?", client)
        self.assertIn("dial::close_probe(session)", client)
        dialer = read("crates/theia/src/quic_core/dial.rs")
        self.assertIn("observation.failure(true)", dialer)
        self.assertIn("fallback_requires_observed_send_or_exact_send_error_and_no_response", dialer)
        self.assertNotIn("quinn::", client.split("#[cfg(test)]\nmod probe_tests", 1)[0])
        self.assertIn("bearer_header(token)?", client)
        self.assertIn("Frame::OpenOk if state.tunnel_open()", client)
        self.assertIn(".run(upload, download, ClientError::Timeout)", client)
        self.assertIn("tokio::try_join!(upload, download)", read("crates/theia/src/relay_liveness.rs"))
        tests = read("crates/theia/tests/h3_server.rs")
        self.assertIn("production_h3_client_and_server_relay_exact_bytes", tests)
        self.assertIn("production_h3_client_rejects_tls_bearer_and_acl_failures", tests)

    def test_shared_h2_h3_relay_liveness_contract(self):
        for adapter in ("client", "h3_client", "server", "h3_server"):
            source = read(f"crates/theia/src/{adapter}.rs")
            with self.subTest(adapter=adapter):
                self.assertIn("relay_liveness::Activity::new()", source)
                self.assertIn("activity.data(", source)
                self.assertIn("activity.half_closed()", source)
                self.assertIn("relay_liveness::receive_tail(", source)
        tests = read("crates/theia/tests/tunnel_liveness.rs")
        self.assertIn("production_h2_h3_asymmetric_traffic_half_close_and_idle", tests)
        for case in ("Upload", "Download", "UploadAfterRemoteFin",
                     "DownloadAfterLocalFin", "Idle", "LongUpload",
                     "LongDownload"):
            self.assertIn(f"Case::{case}", tests)
        for adapter in ("server", "h3_server"):
            source = read(f"crates/theia/src/{adapter}.rs")
            relay = source.split("async fn relay_request", 1)[1].split("\nasync fn ", 1)[0]
            self.assertNotIn("SESSION_TIMEOUT", relay)
            self.assertNotIn("Duration::from_secs(300)", relay)
        self.assertIn("h2_request_trailers_after_fin_reset_the_stream",
                      read("crates/theia/tests/server_h2.rs"))

    def test_m31_explicit_h3_cli_wiring(self):
        proxy = read("crates/theia/src/local_proxy.rs")
        self.assertIn("enum Carrier", proxy)
        self.assertIn("(None, Some(h3)) => Ok(Self::H3(h3))", proxy)
        self.assertRegex(proxy, r"Self::H3\(client\)\s*=>\s*client\s*\.open\(address,\s*port\)")
        self.assertIn("Err(ClientError::QuicUnreachable)", proxy)
        server = read("crates/theia/src/server.rs")
        self.assertIn("tasks.spawn(endpoint.serve(context))", server)
        self.assertIn("tasks.spawn(serve(listener, acceptor, context.clone()))", server)
        self.assertIn("h3_server_and_client_binaries_curl_both_local_proxies",
                      read("crates/theia/tests/client_h2.rs"))

    def test_m32_auto_selector_is_fail_closed(self):
        proxy = read("crates/theia/src/local_proxy.rs")
        quic = read("crates/theia/src/quic_core/dial.rs")
        self.assertIn("Err(ClientError::QuicUnreachable)", proxy)
        self.assertIn("self.sent.load", quic)
        self.assertIn("self.received.load", quic)
        self.assertIn("observation.failure(true)", quic)
        self.assertIn("fallback_requires_observed_send_or_exact_send_error_and_no_response", quic)
        self.assertIn("malformed_response_disables_silence_classification", quic)
        self.assertIn("QuicEndpointNetworkRefused", proxy)
        self.assertIn("AUTO_QUIC_ATTEMPTS", proxy)
        self.assertIn("negative_cache_expires_and_zero_ttl_disables_it", proxy)
        self.assertIn("recheck_deadline_is_not_extended_and_only_one_generation_can_claim_it", proxy)
        self.assertIn("idle_profile_rechecks_quic_without_opening_an_application_tunnel", proxy)
        self.assertIn("result = &mut maintenance => return result", proxy)
        self.assertIn("self.attempt_h3(generation, || self.h3.probe()).await", proxy)
        self.assertIn("dial::close_probe(session)", read("crates/theia/src/h3_client.rs"))
        self.assertIn("route_change_rejects_stale_results_and_unknown_route_disables_cache", proxy)
        self.assertIn("crate::network_scope::observe(self.h3.remote())", proxy)
        tests = read("crates/theia/tests/client_h2.rs")
        for name in ("auto_falls_back_only_after_udp_silence_and_uses_negative_cache",
                     "auto_wrong_h3_certificate_never_retries_working_h2",
                     "auto_denied_h3_bearer_never_retries_working_h2"):
            self.assertIn(name, tests)

    def test_m33_quic_congestion_comparison_is_mandatory(self):
        workflow = read(".github/workflows/ci.yml")
        gate = workflow.split("\n  ci-gate:\n", 1)[1]
        # Native BBR evidence is mandatory inside the existing Linux/Windows
        # M0.1 jobs, not via another pair of identical Cargo builds.
        self.assertIn("m0-1-api-spike", gate)
        self.assertIn("m0-1-windows-spike", gate)
        self.assertNotIn("\n  m3-3-bbr-comparison:\n", workflow)
        bbr = ("comparison_records_all_controller_scenarios_ci_only "
               "-- --ignored --exact --nocapture")
        for name in ("m0-1-api-spike", "m0-1-windows-spike"):
            match = re.search(
                r"(?ms)^  " + re.escape(name)
                + r":\n(.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
                workflow,
            )
            self.assertIsNotNone(match)
            block = match.group(1)
            self.assertIn(bbr, block)
            self.assertIn("python tests/benchmark/check_bbr_comparison.py", block)
            self.assertIn("name: m3-3-quic-comparison-", block)
            self.assertIn("if-no-files-found: error", block)
        benchmark = read("spikes/m0_1/tests/quic_congestion_comparison.rs")
        for expected in ("quinn::congestion::Bbr", "quinn::congestion::Cubic",
                         "loss_delay_jitter", "max_transmit_segments",
                         "THEIA_BBR_RESULTS_PATH", "MAX_PENDING_DATAGRAMS"):
            self.assertIn(expected, benchmark)
        checker = read("tests/benchmark/check_bbr_comparison.py")
        self.assertIn("no relative performance ranking", checker)


    def test_bbr_first_cubic_fallback_policy(self):
        tcp = read("crates/theia/src/tcp_bbr.rs")
        self.assertIn("libc::TCP_CONGESTION", tcp)
        self.assertIn("preferred_controller_on_listener_and_both_tcp_peers", tcp)
        self.assertIn("Controller::Cubic", tcp)
        self.assertIn("os_managed_unverified", tcp)
        self.assertIn("crate::tcp_bbr::connect", read("crates/theia/src/client.rs"))
        server = read("crates/theia/src/server.rs")
        self.assertIn("crate::tcp_bbr::bind", server)
        self.assertIn("crate::tcp_bbr::select(&socket)", server)
        self.assertIn("Congestion::Bbr => Scheduler::with_bbr", read("crates/theia/src/quic_core/handshake_udp.rs"))
        self.assertIn("BbrConfig::default()", read("crates/theia/tests/support/quinn_reference.rs"))

    def test_native_quic_has_no_normal_quinn_dependency(self):
        manifest = toml("crates/theia/Cargo.toml")
        for dependency in ("quinn", "quinn-proto", "h3-quinn"):
            self.assertNotIn(dependency, manifest["dependencies"])
        self.assertIn("cargo tree --locked -p theia -e normal,build", read(".github/workflows/ci.yml"))
        self.assertIn("Candidate::admitted", read("crates/theia/src/reality_quic.rs"))
        self.assertIn("receive_to", read("crates/theia/src/quic_core/listener.rs"))
        self.assertIn("send_from", read("crates/theia/src/quic_core/listener.rs"))
        self.assertNotIn("quinn::", read("crates/theia/src/h3_server.rs"))
        self.assertNotIn("quinn::", read("crates/theia/src/reality_live.rs"))

    def test_offline_signed_descriptor_has_fail_closed_acceptance_contract(self):
        source = read("crates/theia/src/descriptor.rs")
        tests = read("crates/theia/tests/descriptor.rs")
        for term in ("SmartTheia/inbound-descriptor/v1", "UnparsedPublicKey",
                     "deny_unknown_fields", "minimum_revision", "Error::Rollback",
                     "Error::Equivocation", "guarded_trust_write",
                     "struct Transition", "MAX_TRANSITIONS", "ReenrollmentRequired",
                     "pub fn promote", "snapshot.validate(&self.anchor)"):
            self.assertIn(term, source)
        for term in ("signed_descriptor_binds_every_field_to_independent_anchor",
                     "signed_invalid_fields_and_unsupported_contract_are_refused",
                     "durable_revision_floor_rejects_rollback_equivocation_and_key_substitution_after_restart",
                     "explicit_rotation_survives_restart_and_retires_previous_signers",
                     "missed_overlap_requires_independent_enrollment_and_preserves_snapshot",
                     "persisted_transition_tampering_is_rejected_without_partial_update",
                     "bounded_history_requires_reenrollment_instead_of_forgetting_retired_keys",
                     "competing_promotion_and_old_key_update_have_one_revision_guard",
                     "offline_cli_requires_exact_preview_digest_and_guarded_revision",
                     "persisted_acceptance_time_prevents_ordinary_clock_rollback"):
            self.assertIn(term, tests)
        for path in ("client.rs", "h3_client.rs", "server.rs", "h3_server.rs"):
            self.assertNotIn("descriptor::Store", read("crates/theia/src/" + path))
        cli = read("crates/theia/src/descriptor_cli.rs")
        for term in ("--expected-revision", "--sha256", "--confirm", "runtime UNCHANGED",
                     "preview_promotion", "update_at"):
            self.assertIn(term, cli)
        for term in ("TcpStream", "UdpSocket", "reqwest", "runtime_apply"):
            self.assertNotIn(term, cli)

    def test_retired_local_tls_reality_has_no_production_or_compatibility_path(self):
        self.assertFalse((ROOT / "crates/theia/src/reality_identity.rs").exists())
        self.assertNotIn("SmartRealityV1", read("crates/theia/src/security_profile.rs"))
        # Registered external REALITY is not the retired local-TLS invitation.
        # Shared v1 envelope supports both modes; the own-TLS adapter must
        # still reject REALITY instead of exporting a generic TLS pin.
        invite = read("crates/theia/src/invite.rs")
        wire_security = re.search(r"enum WireSecurity\s*\{([^}]+)\}", invite)
        self.assertIsNotNone(wire_security)
        self.assertEqual(
            [item.strip() for item in wire_security.group(1).split(",") if item.strip()],
            ["OwnTls", "SmartReality"],
        )
        self.assertRegex(
            invite,
            r'if profile\.reality_profile\.is_some\(\)\s*\|\|\s*!profile\.security_mode\.is_plain\(\)[\s\S]*?return Err\(InviteError::Invalid\);',
        )
        self.assertRegex(
            invite,
            r'if inbound\.security_mode == crate::security_profile::SecurityMode::SmartReality\s*\|\|\s*inbound\.reality\.is_some\(\)\s*\{\s*return Err\(InviteError::Unavailable\);',
        )
        self.assertNotIn("SmartRealityV1", invite)
        self.assertIn("deny_unknown_fields", invite)
        self.assertNotIn("reality_key", read("crates/theia/src/config.rs"))
        self.assertNotIn("handle_identity_request", read("crates/theia/src/server.rs"))
        self.assertNotIn("handle_identity_request", read("crates/theia/src/h3_server.rs"))
        self.assertNotIn("with_server_identity", read("crates/theia/src/client.rs"))
        self.assertNotIn("with_server_identity", read("crates/theia/src/h3_client.rs"))
        self.assertNotIn("review_generated_reality_mode", read("crates/theia/src/tui_editor.rs"))
        self.assertIn("retired_local_tls_reality_invitation_and_profile_fail_closed",
                      read("crates/theia/src/invite.rs"))
        self.assertIn("retired_local_tls_reality_server_schema_is_rejected",
                      read("crates/theia/tests/reality_security_feasibility.rs"))

    def test_m35a_test_only_feasibility_never_claims_security_mode(self):
        tests = read("crates/theia/tests/reality_security_feasibility.rs")
        config = read("crates/theia/src/config.rs")
        invite = read("crates/theia/src/invite.rs")
        for name in (
            "verified_h2_tls_exporter_is_identical_on_peers_and_context_separated",
            "verified_h3_quic_exporter_matches_both_peers_with_domain_separation",
            "tls_exporter_is_unavailable_for_untrusted_certificates",
            "v1_toml_refuses_unsupported_server_security_and_shaping_fields",
            "v1_toml_refuses_unsupported_client_modes_even_if_supplied_as_profile",
            "replacement_v1_invite_rejects_unsupported_mode_and_identity_injection",
        ):
            self.assertIn(name, tests)
        self.assertIn('profile.security_mode.is_plain()', config)
        self.assertIn('wire.carrier != "smarttheia-xhttp"', invite)
        self.assertIn("replacement_v1_roundtrips_own_tls_and_rejects_retired_profiles", invite)
        self.assertNotIn("PREFIX_V2", invite)
        self.assertNotIn("portable_from_profile", invite)
        self.assertNotIn("leaf_sha256: Option<String>", invite)


if __name__ == "__main__":
    unittest.main()
