#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
from pathlib import Path
import re
import tomllib

root = Path(".")
required = [
    "README.md", "AGENTS.md",
    "docs/IMPLEMENTATION_SPEC.md", "docs/ARCHITECTURE.md",
    "docs/SMARTTHEIA_PROTOCOL.md", "docs/CONFIGURATION.md",
    "docs/TUI_UX.md", "docs/IMPLEMENTATION_PLAN.md",
    "docs/TESTING_CI.md", "examples/server.toml",
    "examples/client.toml", ".github/workflows/ci.yml",
]
missing = [name for name in required if not (root / name).is_file()]
assert not missing, f"Missing required spec files: {missing}"

for file in [Path("README.md"), Path("AGENTS.md"), *Path("docs").glob("*.md")]:
    text = file.read_text(encoding="utf-8")
    assert len(text) > 200, f"Spec file too small: {file}"
    # Validate relative Markdown links, ignoring anchors and external destinations.
    for link in re.findall(r'\]\(([^)]+)\)', text):
        target = link.split("#", 1)[0].strip()
        if not target or target.startswith(("https://", "http://", "mailto:")):
            continue
        if target.startswith("<") or " " in target:
            continue
        assert (file.parent / target).exists(), f"Broken link in {file}: {target}"

for name in ["server", "client"]:
    with open(root / "examples" / f"{name}.toml", "rb") as file:
        conf = tomllib.load(file)
    assert conf["schema_version"] == 1
    assert name in conf, f"Missing [{name}] in {name}.toml"

with open("examples/server.toml", "rb") as file:
    server = tomllib.load(file)["server"]
assert server["inbounds"], "At least one template inbound"
assert server["users"], "At least one template user"
assert server["policy"]["allow_private_ips"] is False, "Fail-closed public relay"
assert "REPLACE_WITH" in server["users"][0]["token_sha256"], "Template must NOT ship usable credentials"

with open("examples/client.toml", "rb") as file:
    client = tomllib.load(file)["client"]
assert client["active_profile"] in {p["id"] for p in client["profiles"]}
assert client["profiles"][0]["transport"] == "auto"
assert client["profiles"][0]["auth_token"].startswith(("env:", "file:"))
assert client["proxy"]["http_listen"].startswith("127.0.0.1:")
assert client["proxy"]["socks5_listen"].startswith("127.0.0.1:")
assert client["proxy"]["system_proxy"] == "off", "Template must not mutate OS settings"

readme = Path("README.md").read_text(encoding="utf-8")
for label in ("Для сервера", "Для клиента", "SmartTheia", "TOML"):
    assert label in readme, f"Missing product invariant in README: {label}"

protocol = Path("docs/SMARTTHEIA_PROTOCOL.md").read_text(encoding="utf-8")
for token in ("0x01", "0x02", "0x03", "0x04", "0x05", "0x10", "0x11", "0x12", "65 536", "h3", "h2"):
    assert token in protocol, f"Protocol missing required v1 element: {token}"

print("OK: specification files, relative links, TOML syntax and baseline invariants")
PY
