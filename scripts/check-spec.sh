#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# No third-party Python dependencies: standard library unittest + tomllib (Python 3.11+).
python3 -m unittest discover -s tests/spec -p 'test_*.py' -v
