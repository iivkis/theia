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

    def test_ci_tests_first_and_cached(self):
        workflow = read(".github/workflows/ci.yml")
        self.assertIn("Swatinem/rust-cache@v2", workflow)
        self.assertIn("scripts/check-spec.sh", workflow)
        self.assertIn("cargo test --workspace --all-targets --locked", workflow)
        self.assertLess(workflow.index("cargo test --workspace --all-targets --locked"),
                        workflow.index("cargo clippy"))
        self.assertIn("Cargo.lock", workflow)


if __name__ == "__main__":
    unittest.main()
