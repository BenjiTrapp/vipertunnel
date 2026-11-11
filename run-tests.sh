#!/usr/bin/env bash
#
# The tests, which need no arguments and touch no network but loopback.
#
# Four files, and what each is for:
#
#   test_tunnel.py     both halves in one process, speaking the real dialect
#                      to each other. The one bug class that would quietly
#                      invalidate a measurement rather than break it.
#   test_dashboard.py  the cadence arithmetic an operator will quote, and the
#                      routes that change the run being measured.
#   test_supervise.py  the restart policy, on a fake clock so nothing sleeps.
#   test_client.py     what the client does with a proxy that refuses.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"

cd "$HERE"
exec "$PYTHON" -m unittest discover -s tests -t . "$@"
