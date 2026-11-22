"""Specification-only contract checks. NOT Rust implementation tests."""
from __future__ import annotations

from pathlib import Path
import re
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
    def test_required_files(self):
        required = [
            "README.md", "AGENTS.md",
            "docs/IMPLEMENTATION_SPEC.md", "docs/ARCHITECTURE.md",
            "docs/SMARTTHEIA_PROTOCOL.md", "docs/CONFIGURATION.md",
            "docs/TUI_UX.md", "docs/IMPLEMENTATION_PLAN.md",
            "docs/STEALTH_REALITY.md",
            "docs/adr/0020-reality-like-and-tls-in-tls.md",
            "docs/TESTING_CI.md", "docs/SPEC_REVIEW.md",
            "docs/adr/0001-standard-h3-h2-embedding.md",
            "docs/adr/0002-inbound-authorization-and-tcp-ack.md",
            "docs/adr/0003-mvp-bbr-and-fingerprint.md",
            "examples/server.toml", "examples/client.toml",
            ".github/workflows/ci.yml", "scripts/check-spec.sh"
        ]
        for path in required:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file(), path)

    def test_local_markdown_links(self):
        docs = [ROOT / "README.md", ROOT / "AGENTS.md"]
        docs += list((ROOT / "docs").rglob("*.md"))
        for file in docs:
            text = file.read_text(encoding="utf-8")
            with self.subTest(file=file):
                self.assertGreater(len(text), 200)
            for link in re.findall(r"\]\(([^)]+)\)", text):
                path = link.split("#", 1)[0].strip()
                if not path or path.startswith(("https://", "http://", "mailto:")):
                    continue
                if path.startswith("<") or " " in path:
                    continue
                with self.subTest(file=file, link=path):
                    self.assertTrue((file.parent / path).exists(), f"{file}: {path}")

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
            self.assertEqual(profile["tls_profile"], "default")
        proxy = client["proxy"]
        self.assertEqual(proxy["system_proxy"], "off")
        for name in ("http_listen", "socks5_listen"):
            self.assertRegex(proxy[name], r"^(127\.0\.0\.1|\[::1\]):[0-9]+$")

    def test_product_mvp_gates(self):
        text = read("docs/IMPLEMENTATION_SPEC.md")
        for feature in ("F-06", "F-11", "F-13", "F-16", "F-17"):
            with self.subTest(feature=feature):
                self.assertRegex(text, rf"(?m)^\| {feature} \| P0 \|")
        self.assertIn("BBR", text)
        self.assertIn("browser-like", text)

    def test_future_reality_like_and_tls_in_tls_are_p0_but_not_claimed_live(self):
        spec = read("docs/IMPLEMENTATION_SPEC.md")
        plan = read("docs/IMPLEMENTATION_PLAN.md")
        model = read("docs/STEALTH_REALITY.md")
        adr = read("docs/adr/0020-reality-like-and-tls-in-tls.md")
        for feature in ("F-18", "F-19"):
            with self.subTest(feature=feature):
                self.assertIn(f"| {feature} | P0 |", spec)
                self.assertIn(feature, model)
                self.assertIn(feature, plan)
                self.assertIn(feature, adr)
        for text in (
            "REALITY", "TLS-in-TLS", "не реализовано", "Проверить и подобрать",
            "Применить", "score", "confidence", "SSRF", "FPR", "OPEN_OK",
            "Linux/Windows", "H2", "H3", "theia://v1",
        ):
            with self.subTest(token=text):
                self.assertIn(text.lower(), model.lower())
        self.assertIn("M3.5a", plan)
        self.assertIn("M3.5d", plan)
        self.assertIn("M4.5", plan)
        self.assertIn("off/optional/required", model)
        self.assertIn("не реализовано", read("README.md"))
        client = toml("examples/client.toml")["client"]
        self.assertTrue(all(p["tls_profile"] == "default" for p in client["profiles"]))
        self.assertIn('profile.tls_profile == "default"', read("crates/theia/src/config.rs"))
        self.assertIn("REALITY", read("docs/TUI_UX.md"))
        self.assertIn("TLS-in-TLS", read("docs/TESTING_CI.md"))
        self.assertIn("schema_version=1", read("docs/CONFIGURATION.md"))

    def test_smarttheia_protocol_and_ack_contract(self):
        text = read("docs/SMARTTHEIA_PROTOCOL.md")
        for token in ("0x01", "0x02", "0x03", "0x04", "0x05", "0x10", "0x11", "0x12",
                      "65 536", "OPEN_OK", "full-duplex", "h3", "h2"):
            self.assertIn(token, text)
        self.assertNotIn("client_nonce", text)
        self.assertIn("ровно 6 байт", text)

    def test_windows_manual_proxy_is_not_auto_enabled(self):
        config = read("docs/CONFIGURATION.md")
        self.assertIn("только `off` и `manual`", config)
        self.assertNotIn("`on` — явный opt-in", config)
        self.assertNotIn('system_proxy = "on"', read("examples/client.toml"))
        self.assertIn("CAS", read("docs/TUI_UX.md") + config)  # compare-and-swap restoration documented

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
        self.assertIn("P0 BLOCKER", read("docs/adr/0005-tls-fingerprint-baseline.md"))
        go_ref = spike / "utls_reference"
        self.assertTrue((go_ref / "go.mod").is_file())
        self.assertTrue((go_ref / "go.sum").is_file())
        mod = (go_ref / "go.mod").read_text(encoding="utf-8")
        self.assertIn("github.com/refraction-networking/utls v1.8.2", mod)
        source = (go_ref / "main.go").read_text(encoding="utf-8")
        self.assertIn("utls.HelloChrome_133", source)
        self.assertIn("BuildHandshakeState", source)
        self.assertIn("os.O_EXCL", source)
        fixture_test = (spike / "tests" / "utls_reference.rs").read_text(encoding="utf-8")
        self.assertIn("go_utls_chrome133_is_a_reference_but_not_rustls_or_quic", fixture_test)
        self.assertIn("THEIA_UTLS_HELLO_PATH", fixture_test)
        live_probe = (spike / "utls_reference" / "cmd" / "h2_probe" / "main.go").read_text(encoding="utf-8")
        for required in ("utls.HelloChrome_133", "Handshake()", "VerifiedChains",
                         "utls.VersionTLS13", "sendMinimalH2Request", "receiveH2NoContent",
                         "validateLoopback", "modeWrongName", "modeUntrustedCA"):
            self.assertIn(required, live_probe)
        live_tests = (spike / "tests" / "utls_h2_loopback.rs").read_text(encoding="utf-8")
        for required in ("inspect_real_wire_client_hello", "TcpListener::bind",
                         "utls_chrome133_real_tcp_tls13_h2_request_with_verified_identity",
                         "utls_chrome133_real_tcp_rejects_wrong_hostname_before_h2",
                         "utls_chrome133_real_tcp_rejects_untrusted_ca_before_h2"):
            self.assertIn(required, live_tests)
        workflow = read(".github/workflows/ci.yml")
        self.assertIn("go build -o", workflow)
        self.assertIn("--test utls_h2_loopback -- --ignored", workflow)
        self.assertIn("go test ./...", workflow)
        self.assertIn("refraction-networking/utls v1.8.2", read("docs/adr/0005-tls-fingerprint-baseline.md"))
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

    def test_m11_cli_workspace_is_real_but_runtime_is_not(self):
        root = toml("Cargo.toml")
        workspace = root["workspace"]
        self.assertEqual(workspace["members"], ["crates/theia"])
        self.assertIn("spikes/m0_1", workspace["exclude"])
        self.assertTrue((ROOT / "Cargo.lock").is_file())
        package = toml("crates/theia/Cargo.toml")["package"]
        self.assertEqual(package["name"], "theia")
        source = read("crates/theia/src/lib.rs")
        for marker in ("ServerRun", "ClientRun", "ConfigValidate", "NotImplemented",
                       "pub fn parse(", "pub fn execute(", "CliError::InvalidArguments"):
            self.assertIn(marker, source)
        integration = read("crates/theia/tests/cli.rs")
        self.assertIn("accepted_runtime_commands_fail_closed", integration)
        self.assertIn("rejected_arguments_cannot_start_a_runtime", integration)

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
                     "InvalidFlags", "InvalidTransition", "UnsupportedVersion"):
            self.assertIn(term, implementation)
        for test in ("documented_golden_vectors_are_exact",
                     "size_boundaries_are_enforced_before_buffering",
                     "stream_decoder_accepts_every_split_and_multiple_coalesced_frames",
                     "local_success_is_gated_on_open_ok_not_http_or_hello_ack",
                     "full_duplex_half_close_then_both_fin_and_drain",
                     "deterministic_random_chunks_never_panic_and_bound_partial_memory"):
            self.assertIn(test, tests)

    def test_m21_h2_ingress_is_real_and_has_fail_closed_tests(self):
        implementation = read("crates/theia/src/server.rs")
        tests = read("crates/theia/tests/server_h2.rs")
        binary = read("crates/theia/src/main.rs")
        for term in ("pub async fn serve(", "pub async fn run_file(",
                     "fn allowed_destination(", "URL_SAFE_NO_PAD", "Sha256::digest",
                     "ct_eq(", "lookup_host(", "TcpStream::connect",
                     "Frame::OpenOk", "TlsAcceptor", "max_concurrent_streams"):
            self.assertIn(term, implementation)
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
        self.assertIn("cargo test --workspace --all-targets --locked", workflow)
        self.assertLess(workflow.index("cargo test --workspace --all-targets --locked"),
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
        self.assertIn("CI-only", read("AGENTS.md"))
        self.assertIn("CI-only", read("docs/TESTING_CI.md"))
        self.assertNotIn("manual Windows smoke tests", read("docs/IMPLEMENTATION_PLAN.md"))
        self.assertNotIn("ручным smoke-тестом", read("docs/IMPLEMENTATION_SPEC.md"))
        self.assertNotIn("## 3. Локальная проверка", read("docs/TESTING_CI.md"))

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
        self.assertIn("browser bypassed the Theia SOCKS5 path", read("tests/e2e/chromium_socks.py"))

    def test_m31_h3_server_reuses_security_boundary(self):
        h2 = read("crates/theia/src/server.rs")
        h3 = read("crates/theia/src/h3_server.rs")
        self.assertIn("context.authorize_request", h2)
        self.assertIn("context.authorize_request", h3)
        self.assertIn("context.dial_target", h2)
        self.assertIn("context.dial_target", h3)
        self.assertIn("Frame::OpenOk", h3)
        self.assertIn("tokio::try_join!(upload, download)", h3)
        tests = read("crates/theia/tests/h3_server.rs")
        self.assertIn("authenticated_h3_server_relays_tcp_before_request_fin_and_after_half_close", tests)
        self.assertIn("h3_rejects_missing_wrong_and_ungranted_bearers_and_denied_tcp", tests)

    def test_m31_h3_client_gate(self):
        client = read("crates/theia/src/h3_client.rs")
        self.assertIn("ObservedEndpoint::new", client)
        self.assertIn("bearer_header(token)?", client)
        self.assertIn("Frame::OpenOk if state.tunnel_open()", client)
        self.assertIn("tokio::try_join!(upload, download)", client)
        tests = read("crates/theia/tests/h3_server.rs")
        self.assertIn("production_h3_client_and_server_relay_exact_bytes", tests)
        self.assertIn("production_h3_client_rejects_tls_bearer_and_acl_failures", tests)

    def test_m31_explicit_h3_cli_wiring(self):
        proxy = read("crates/theia/src/local_proxy.rs")
        self.assertIn("ProxyClient::H3", proxy)
        self.assertIn("Err(ClientError::QuicUnreachable)", proxy)
        server = read("crates/theia/src/server.rs")
        self.assertIn("crate::h3_server::serve(endpoint, context)", server)
        self.assertIn("tasks.spawn(serve(listener, acceptor, context.clone()))", server)
        self.assertIn("h3_server_and_client_binaries_curl_both_local_proxies",
                      read("crates/theia/tests/client_h2.rs"))

    def test_m32_auto_selector_is_fail_closed(self):
        proxy = read("crates/theia/src/local_proxy.rs")
        quic = read("crates/theia/src/quic_transport.rs")
        self.assertIn("Err(ClientError::QuicUnreachable)", proxy)
        self.assertIn("self.observation.sent.load", quic)
        self.assertIn("!self.observation.received.load", quic)
        self.assertIn("negative_cache_expires_and_zero_ttl_disables_it", proxy)
        self.assertIn("route_change_rejects_stale_results_and_unknown_route_disables_cache", proxy)
        self.assertIn("route_source(self.h3.remote())", proxy)
        tests = read("crates/theia/tests/client_h2.rs")
        for name in ("auto_falls_back_only_after_udp_silence_and_uses_negative_cache",
                     "auto_wrong_h3_certificate_never_retries_working_h2",
                     "auto_denied_h3_bearer_never_retries_working_h2"):
            self.assertIn(name, tests)

    def test_m33_quic_congestion_comparison_is_mandatory(self):
        workflow = read(".github/workflows/ci.yml")
        gate = workflow.split("\n  ci-gate:\n", 1)[1]
        self.assertIn("m3-3-bbr-comparison", gate)
        self.assertIn("m3-3-bbr-comparison", workflow.split("\n  ci-gate:\n")[0])
        benchmark = read("spikes/m0_1/tests/quic_congestion_comparison.rs")
        for expected in ("quinn::congestion::Bbr", "quinn::congestion::Cubic",
                         "loss_delay_jitter", "max_transmit_segments",
                         "THEIA_BBR_RESULTS_PATH", "MAX_PENDING_DATAGRAMS"):
            self.assertIn(expected, benchmark)
        checker = read("tests/benchmark/check_bbr_comparison.py")
        self.assertIn("no relative performance ranking", checker)


    def test_m35a_test_only_feasibility_never_claims_security_mode(self):
        spec = read("docs/STEALTH_REALITY.md")
        adr = read("docs/adr/0021-m3-5a-rustls-quic-auth-feasibility.md")
        tests = read("crates/theia/tests/reality_security_feasibility.rs")
        config = read("crates/theia/src/config.rs")
        invite = read("crates/theia/src/invite.rs")
        self.assertIn("M3.5a0", spec)
        self.assertIn("M3.5a1", adr)
        for name in (
            "verified_h2_tls_exporter_is_identical_on_peers_and_context_separated",
            "verified_h3_quic_exporter_matches_both_peers_with_domain_separation",
            "tls_exporter_is_unavailable_for_untrusted_certificates",
            "v1_toml_refuses_unsupported_server_security_and_shaping_fields",
            "v1_toml_refuses_unsupported_client_modes_even_if_supplied_as_profile",
            "v1_invite_rejects_new_mode_and_identity_injection_without_a_version_bump",
        ):
            self.assertIn(name, tests)
        self.assertIn('profile.tls_profile == "default"', config)
        self.assertIn('wire.tls_profile != "default"', invite)
        self.assertIn("Никакой REALITY-подобный режим", adr)
        self.assertIn("F-18/F-19", read("docs/IMPLEMENTATION_PLAN.md"))


if __name__ == "__main__":
    unittest.main()
