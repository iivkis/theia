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
            "docs/TESTING_CI.md", "docs/STATUS.md",
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

    def test_live_readme_and_status_are_not_stale_preimplementation_notes(self):
        readme = read("README.md")
        status = read("docs/STATUS.md")
        self.assertLess(len(readme), 14_000, "README must not regrow into PR-by-PR history")
        self.assertIn("Experimental / unreleased", readme)
        self.assertIn("M4.4b2a", readme)
        self.assertNotIn("M4.4a (in review)", readme)
        self.assertNotIn("Windows пока только Unsupported", readme)
        self.assertNotIn("реализация ядра по-прежнему **отсутствует**", readme)
        self.assertIn("docs/STATUS.md", readme)
        self.assertIn("PR #83", readme)
        self.assertIn("PR #83", status)
        for live_path in ("README.md", "docs/STATUS.md", "docs/CONFIGURATION.md", "docs/INVITATIONS.md"):
            with self.subTest(live_path=live_path):
                live = read(live_path)
                self.assertNotIn("CI pending", live)
                self.assertNotIn("PR/CI", live)
        self.assertIn("13/13 SUCCESS", status)
        self.assertIn("только после", status)
        for item in ("F-13", "F-14", "F-18", "F-19", "M4.3"):
            with self.subTest(item=item):
                self.assertIn(item, readme)
                self.assertIn(item, status)
        self.assertFalse((ROOT / "docs/SPEC_REVIEW.md").exists())
        archive = read("docs/archive/spec-review-2026-11-22.md")
        self.assertIn("Исторический документ", archive)
        self.assertIn("устарели", archive)

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

    def test_m35b2a_explicit_tls_probe_contract(self):
        code = read("crates/theia/src/camouflage_probe.rs")
        tests = read("crates/theia/tests/camouflage_probe.rs")
        adr = read("docs/adr/0023-m3-5b2a-explicit-tls-probe.md")
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
                self.assertIn(token.lower(), (tests + adr).lower())
        self.assertIn("M3.5b2a", read("docs/STEALTH_REALITY.md"))
        self.assertIn("M3.5b2a", read("docs/IMPLEMENTATION_PLAN.md"))
        self.assertIn("M3.5b2a", read("README.md"))
        self.assertIn('profile.tls_profile == "default"', read("crates/theia/src/config.rs"))

    def test_m35b1_code_contract_does_not_claim_active_scan_or_reality(self):
        code = read("crates/theia/src/camouflage_discovery.rs")
        tests = read("crates/theia/tests/camouflage_discovery.rs")
        adr = read("docs/adr/0022-m3-5b1-offline-discovery-and-evidence.md")
        self.assertIn("pub mod camouflage_discovery;", read("crates/theia/src/lib.rs"))
        for token in ("MAX_CANDIDATES", "POPULAR_HTTPS_DOMAINS", "pub fn build_plan",
                      "pub fn suitability", "ProviderPrefixNotAuthorization", "Unknown",
                      "Ipv6EnumerationUnsupported"):
            self.assertIn(token, code)
        for token in ("google.com", "samsung.com", "amd.com",
                      "zero-I/O", "не", "REALITY"):
            self.assertIn(token.lower(), (code + tests + adr).lower())
        self.assertIn("M3.5b1", read("docs/IMPLEMENTATION_PLAN.md"))
        self.assertIn("M3.5b1", read("docs/STEALTH_REALITY.md"))
        self.assertIn("M3.5b1", read("README.md"))
        self.assertIn('profile.tls_profile == "default"', read("crates/theia/src/config.rs"))

    def test_f18_picker_discovers_server_range_and_popular_domains_without_manual_seed(self):
        model = read("docs/STEALTH_REALITY.md")
        spec = read("docs/IMPLEMENTATION_SPEC.md")
        plan = read("docs/IMPLEMENTATION_PLAN.md")
        ui = read("docs/TUI_UX.md")
        ci = read("docs/TESTING_CI.md")
        adr = read("docs/adr/0020-reality-like-and-tls-in-tls.md")
        for needle in (
            "Автоматическое обнаружение", "назначенные префиксы IPv4/IPv6",
            "NAT", "RDAP/BGP", "без SNI", "TLS1.3", "SAN",
            "ALPN", "серверная подсеть", "популярные домены",
            "google.com", "samsung.com", "amd.com", "microsoft.com",
            "cloudflare.com", "github.com", "mozilla.org", "wikipedia.org",
            "лишь с согласия", "приватного ключа",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle.lower(), model.lower())
        self.assertIn("вручную вводить список не нужно", spec)
        self.assertIn("M3.5b", plan)
        self.assertIn("google.com", plan)
        self.assertIn("google.com", ui)
        self.assertIn("CIDR", ci)
        self.assertIn("google.com", adr)
        self.assertIn("не реализовано", read("README.md"))
        # Research and docs do not enable any new production security mode.
        self.assertIn('profile.tls_profile == "default"', read("crates/theia/src/config.rs"))

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
        self.assertIn("actual_chromium_h2_settings_and_pseudo_order_reference", workflow)
        self.assertIn("ADR-0074", read("AGENTS.md"))
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

    def test_documented_toml_examples_parse(self):
        config = read("docs/CONFIGURATION.md")
        examples = re.findall(r"```toml\n(.*?)\n```", config, re.DOTALL)
        self.assertGreaterEqual(len(examples), 2)
        for example in examples:
            with self.subTest(example=example.splitlines()[0]):
                tomllib.loads(example)


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
        self.assertIn("client_binary_chromium_socks5_over_h3 -- --ignored --exact", workflow)
        self.assertIn("production_h3_client_refuses_incompatible_alpn_before_application_data",
                      read("crates/theia/tests/h3_server.rs"))
        self.assertIn("browser bypassed the Theia SOCKS5 path", read("tests/e2e/chromium_socks.py"))

    def test_pinned_identity_is_additional_and_mode_is_explicit(self):
        security = read("crates/theia/src/security_profile.rs")
        self.assertIn("pinned-cert-v1:", security)
        self.assertIn("ConstantTimeEq", security)
        for path in ("client.rs", "h3_client.rs"):
            source = read("crates/theia/src/" + path)
            self.assertIn("pin.verify(", source)
            self.assertIn("PINNED_PATH", source)
            self.assertIn("with_certificate_pin", source)
        server = read("crates/theia/src/server.rs")
        self.assertIn("self.security_mode.path()", server)
        self.assertIn("before.security_mode != after.security_mode",
                      read("crates/theia/src/reload_preflight.rs"))
        editor = read("crates/theia/src/tui_editor.rs")
        self.assertIn("review_pinned_mode", editor)
        self.assertIn("apply_pinned_mode", editor)
        self.assertIn("h2_h3_pinned_identity_and_mode_are_fail_closed",
                      read("crates/theia/tests/security_profile.rs"))
        self.assertIn("pinned_auto_rejects_wrong_trusted_h3_pin_and_falls_back_only_on_udp_silence",
                      read("crates/theia/tests/client_h2.rs"))

    def test_smarttheia_native_xhttp_contract(self):
        spec = read("docs/IMPLEMENTATION_SPEC.md")
        self.assertIn("SmartTheia XHTTP", spec)
        self.assertIn("не реализуем полную копию Xray REALITY или Xray XHTTP", spec)
        self.assertIn("0.6 (проектная)", spec)
        self.assertIn("не смена протокола или транспорта SmartTheia", spec)
        self.assertIn("параметров единственного XHTTP", spec)
        self.assertIn("Xray XHTTP и Xray REALITY — только источники идей", spec)
        self.assertIn("полное копирование реализации Xray не является целью", spec)
        self.assertIn("воспроизведение Xray first flight", spec)
        adr = read("docs/adr/0086-custom-xhttp-and-reality-design-authority.md")
        self.assertIn("inspiration only", adr)
        self.assertIn("not a clone", adr)
        for document in ("AGENTS.md", "README.md", "docs/SMARTTHEIA_PROTOCOL.md", "docs/ARCHITECTURE.md", "docs/STEALTH_REALITY.md", "docs/TUI_UX.md"):
            with self.subTest(document=document):
                source = read(document)
                self.assertIn("Xray XHTTP", source)
                self.assertIn("Xray REALITY", source)
                self.assertIn("не копия", source)
        self.assertIn("единственный транспорт протокола SmartTheia", spec)
        self.assertIn("Собственный TLS: исключительно ручная настройка", spec)
        self.assertIn("SmartTheia REALITY: настройка через двухшаговый мастер", spec)
        self.assertIn("QUIC-first является штатной политикой клиента", spec)
        self.assertIn("не являются третьим режимом безопасности", spec)
        adr = read("docs/adr/0085-single-xhttp-inbound-security-choice.md")
        self.assertIn("one transport", adr)
        self.assertIn("manual only", adr)
        split = read("crates/theia/src/split_http.rs")
        self.assertIn("UPLOAD_PATH", split)
        self.assertIn("DOWNLOAD_PATH", split)
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
        self.assertIn("ObservedEndpoint::new", client)
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
                self.assertIn("activity.fin()", source)
                self.assertIn("relay_liveness::receive_tail(", source)
        tests = read("crates/theia/tests/tunnel_liveness.rs")
        self.assertIn("production_h2_h3_asymmetric_traffic_half_close_and_idle", tests)
        for case in ("Upload", "Download", "UploadAfterRemoteFin",
                     "DownloadAfterLocalFin", "Idle"):
            self.assertIn(f"Case::{case}", tests)
        self.assertIn("h2_request_trailers_after_fin_reset_the_stream",
                      read("crates/theia/tests/server_h2.rs"))

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
        self.assertIn("BbrConfig::default()", read("crates/theia/src/quic_transport.rs"))
        self.assertIn("not configurable", read("docs/adr/0090-mandatory-bbr-for-h2-and-h3.md"))

    def test_reality_identity_before_bearer_and_no_new_invitation_version(self):
        identity = read("crates/theia/src/reality_identity.rs")
        self.assertIn("signature::ED25519", identity)
        self.assertIn("from_pkcs8_maybe_unchecked", identity)
        self.assertIn("theia-server-identity", identity)
        for name in ("client.rs", "h3_client.rs"):
            client = read("crates/theia/src/" + name)
            self.assertLess(client.index("identity.verify(key, &response)?"), client.index("let (response, mut"))
        for name in ("server.rs", "h3_server.rs"):
            self.assertIn("handle_identity_request", read("crates/theia/src/" + name))
        invite = read("crates/theia/src/invite.rs")
        self.assertIn("server_public_key: Option<String>", invite)
        self.assertNotIn("PREFIX_V2", invite)
        self.assertIn("reality_key", read("crates/theia/src/reload_preflight.rs"))
        self.assertIn("active probing", read("docs/adr/0089-independent-ed25519-xhttp-identity.md"))

    def test_f18_independent_native_acceptance_contract(self):
        guest = read("scripts/f14-wsl-server.py")
        host = read("scripts/f14-cross-os-ci.py")
        cross = read("crates/theia/tests/f14_cross_host.rs")
        self.assertIn("independent_identity", guest)
        self.assertIn('security_mode = "smart-reality-v1"', guest)
        self.assertIn("reality-public.txt", host)
        self.assertNotIn('"reality.der"', host)
        self.assertIn("reality_client_scenario(&fixture, transport)", cross)
        self.assertIn("THEIA_F18_XHOST_WRONG_PUBLIC", cross)
        self.assertIn("independent_wire_identity_h2_h3_signature_scope_and_one_response",
                      read("crates/theia/tests/security_profile.rs"))
        self.assertIn("material_fingerprint", read("crates/theia/src/tui_editor.rs"))
        self.assertIn("theia-reality-local-review-v1", read("crates/theia/src/server.rs"))

    def test_f18_generated_local_identity_uses_guarded_manual_validator(self):
        editor = read("crates/theia/src/tui_editor.rs")
        storage = read("crates/theia/src/client_import.rs")
        self.assertIn("review_generated_reality_mode", editor)
        self.assertIn("self.review_reality_mode(&reference)?", editor)
        self.assertIn("generated_reality_key_preview_cancel_drift_and_commit", editor)
        self.assertIn("generated_reality_storage_is_private_distinct_and_guarded", storage)
        self.assertIn('Self::create_payload(config_path, "reality", "identity.der"', storage)
        self.assertIn("start_generated_reality_review", read("crates/theia/src/tui.rs"))

    def test_f18_owned_endpoint_http_application_and_guarded_review(self):
        own = read("crates/theia/src/owned_endpoint.rs")
        self.assertIn("Request::head", own)
        self.assertIn("pin.verify", own)
        self.assertIn("recv_response()", own)
        self.assertIn("tokio::try_join!", own)
        self.assertNotIn("lookup_host", own)
        self.assertNotIn("AUTHORIZATION", own)
        editor = read("crates/theia/src/tui_editor.rs")
        self.assertIn("review_owned_candidate", editor)
        self.assertIn("collect_assigned_interfaces()", editor)
        self.assertIn("self.check_owned_candidate(candidate)?", editor)
        self.assertIn("self.review_generated_reality_mode()?", editor)
        self.assertIn("CandidateSource::ServerAddress", read("crates/theia/src/tui_candidate_batch.rs"))
        self.assertIn("owned_readiness_requires_real_http_on_both_transports_and_exact_leaf",
                      read("crates/theia/src/owned_endpoint_tests.rs"))

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
            "replacement_v1_invite_rejects_unsupported_mode_and_identity_injection",
        ):
            self.assertIn(name, tests)
        self.assertIn('profile.tls_profile == "default"', config)
        self.assertIn('wire.carrier != "smarttheia-xhttp"', invite)
        self.assertIn("replacement_v1_roundtrips_all_supported_profiles_and_refuses_legacy", invite)
        self.assertNotIn("PREFIX_V2", invite)
        self.assertNotIn("portable_from_profile", invite)
        self.assertIn("leaf_sha256: Option<String>", invite)
        self.assertIn("Никакой REALITY-подобный режим", adr)
        self.assertIn("F-18/F-19", read("docs/IMPLEMENTATION_PLAN.md"))


if __name__ == "__main__":
    unittest.main()
