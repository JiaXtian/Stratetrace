#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$ROOT/src"
export PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/stratatrace-pycache"
exec python3 -m unittest discover -s "$ROOT/tests" -v

