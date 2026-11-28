import importlib.util
from contextlib import ExitStack
from pathlib import Path
import socket
import tempfile
import tomllib
import unittest

spec = importlib.util.spec_from_file_location(
    "loopback_performance", Path(__file__).resolve().parents[1] / "benchmark" / "run_loopback_performance.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class BenchmarkPortsTests(unittest.TestCase):
    def test_concurrent_reservations_and_handoff(self):
        for _ in range(40):
            with ExitStack() as stack:
                ports = runner.TrialPorts(stack)
                self.assertEqual(len({ports.h2, ports.http, ports.socks}), 3)
                self.assertEqual(ports.h3_socket.type, socket.SOCK_DGRAM)
                for sock, port in ((ports.h2_socket, ports.h2), (ports.h3_socket, ports.h3),
                                   (ports.http_socket, ports.http), (ports.socks_socket, ports.socks)):
                    self.assertEqual(sock.getsockname(), (runner.LOOP, port))
                    with socket.socket(socket.AF_INET, sock.type) as competing:
                        with self.assertRaises(OSError):
                            competing.bind((runner.LOOP, port))
                ports.release_server()
                with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    tcp.bind((runner.LOOP, ports.h2))
                    udp.bind((runner.LOOP, ports.h3))
                    self.assertEqual(ports.http_socket.getsockname()[1], ports.http)
                ports.release_client()
                with socket.socket() as http, socket.socket() as socks:
                    http.bind((runner.LOOP, ports.http))
                    socks.bind((runner.LOOP, ports.socks))

    def test_explicit_carrier_endpoint_and_distinct_server_listeners(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for carrier in ("h2", "h3"):
                runner.config_files(path, path / "cert.pem", path / "key.pem",
                                    31001, 31002, 31003, 31004, 31005, carrier, b"test", "0" * 40)
                server = tomllib.loads((path / "server.toml").read_text(encoding="utf-8"))
                client = tomllib.loads((path / "client.toml").read_text(encoding="utf-8"))
                inbound = server["server"]["inbounds"][0]
                self.assertEqual(inbound["h2_listen"], "127.0.0.1:31001")
                self.assertEqual(inbound["quic_listen"], "127.0.0.1:31002")
                self.assertEqual(client["client"]["profiles"][0]["server"], "127.0.0.1:31003")
                self.assertEqual(client["client"]["profiles"][0]["transport"], carrier)

    def test_exact_legacy_reference_configurations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for revision in ("abbb89834a406b4c53be0f1ac0b3ab1a65e66f8d",
                             "917417b09f209334939c38551112081c480eb958", "0" * 40):
                runner.config_files(path, path / "cert.pem", path / "key.pem",
                                    31001, 31002, 31003, 31004, 31005, "h2", b"test", revision)
                client = tomllib.loads((path / "client.toml").read_text(encoding="utf-8"))["client"]
                self.assertEqual(client["proxy"]["http_listen"], "127.0.0.1:31004")
                if revision == "0" * 40:
                    self.assertEqual(client["ingress_mode"], "system_proxy")
                    self.assertNotIn("system_proxy", client["proxy"])
                else:
                    self.assertNotIn("ingress_mode", client)
                    self.assertEqual(client["proxy"]["system_proxy"], "off")


if __name__ == "__main__":
    unittest.main()
