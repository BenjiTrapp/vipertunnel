#!/usr/bin/env bash
#
# Start the tunnel server for a Beacon Reaper measurement.
#
# The one thing to decide before you run this is KEEPALIVE, because its
# effect is a step rather than a slope:
#
#   KEEPALIVE=60   -> one held TCP connection. The proxy logs a single
#                     CONNECT and a byte count. There is no cadence for a
#                     periodicity detection to find, and that is a result
#                     worth having rather than a failed run.
#   KEEPALIVE=0    -> never send one. The client's 120-second read deadline
#                     expires, it tears the connection down and builds a new
#                     one, and the proxy log shows a reconnect every ~120s.
#                     This is the shape the Reaper hunts.
#
# There is no third option from this side: if this server closes a command
# connection, the original client exits rather than reconnecting. A cadence
# other than ~120s has to come from the client's --timeout, which is a
# deviation from the family and is labelled as one.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIND="${BIND:-0.0.0.0}"
PORT="${PORT:-443}"
SOCKS="${SOCKS:-1080}"
KEEPALIVE="${KEEPALIVE:-0}"
LEDGER="${LEDGER:-$HERE/server-ledger.log}"

PYTHON="${PYTHON:-python3}"

if [ "$PORT" -lt 1024 ] && [ "$(id -u)" -ne 0 ]; then
    echo "Port $PORT needs root. Either:" >&2
    echo "  sudo -E $0" >&2
    echo "  PORT=8443 $0     # but see the note below" >&2
    echo >&2
    echo "443 is the family's port and worth keeping: the proxy allowlist" >&2
    echo "you are measuring through may permit CONNECT to 443 and nothing" >&2
    echo "else, in which case a different port measures the proxy instead" >&2
    echo "of the tunnel." >&2
    exit 2
fi

case "$KEEPALIVE" in
    0) SHAPE="a reconnect every ~120s -- the cadence the Reaper hunts" ;;
    *) if [ "${KEEPALIVE%.*}" -lt 120 ] 2>/dev/null; then
           SHAPE="one held connection -- no cadence to find"
       else
           SHAPE="a reconnect every ~120s (keep-alive is above the client's timeout)"
       fi ;;
esac

cat <<BANNER
tunnel server
  implants   ${BIND}:${PORT}
  operator   127.0.0.1:${SOCKS}   (RFC 1928, drive it with curl --socks5 or proxychains)
  keep-alive ${KEEPALIVE}s
  expect     ${SHAPE}
  ledger     ${LEDGER}

Ground truth goes to the ledger. Compare the Reaper's report against it
rather than against the Reaper's own timestamps -- the fields in these
alerts have been found to mean something other than their names.
BANNER

exec "$PYTHON" "$HERE/server.py" \
    --bind "$BIND" \
    --port "$PORT" \
    --socks "$SOCKS" \
    --keepalive "$KEEPALIVE" \
    --ledger "$LEDGER" \
    "$@"
