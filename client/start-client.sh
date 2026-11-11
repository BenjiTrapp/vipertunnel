#!/usr/bin/env bash
#
# Start the implant for a traffic measurement.
#
# PROXY is not optional for this measurement, even though it is a deviation
# from the family: a detection that reads proxy logs sees nothing at all from
# a host with direct egress. Point this at whatever CONNECT proxy the host
# would really use.
#
# Where a host reaches its proxy through a local relay -- an authenticating
# corporate proxy usually needs one -- that relay is the address to give:
#
#   PROXY=127.0.0.1:3128 ./start-client.sh c2.example.com
#
# The bytes between this process and the server are unchanged by the proxy
# leg -- it is transport only, which is what keeps this faithful where the
# measurement cares.
#
# To restart the client when a proxy ends the tunnel, and to record how long
# each run lived, run it under supervise.py instead; see the README.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$#" -lt 1 ]; then
    cat >&2 <<USAGE
usage: [PROXY=host:port] [TIMEOUT=120] $0 SERVER[:PORT]

  SERVER   the tunnel server. Port defaults to 443, the family's.
  PROXY    the HTTP CONNECT proxy to reach it through. Required for a
           measurement that reads proxy logs; omit it only to test the
           two halves against each other on one host.
  TIMEOUT  the command connection's read deadline. 120 is the original's
           value and sets the reconnect cadence. Changing it is a
           deviation and the client will say so.
USAGE
    exit 2
fi

SERVER="$1"
shift

PROXY="${PROXY:-}"
TIMEOUT="${TIMEOUT:-120}"
JITTER="${JITTER:-0}"
LEDGER="${LEDGER:-$HERE/client-ledger.log}"
PYTHON="${PYTHON:-python3}"

ARGS=("$HERE/client.py" "$SERVER" --timeout "$TIMEOUT" --ledger "$LEDGER")
if [ -n "$PROXY" ]; then
    ARGS+=(--proxy "$PROXY")
    EGRESS="through $PROXY"
else
    EGRESS="DIRECT -- a proxy-log detection will see nothing"
fi
case "$JITTER" in
    0|0.0|"") CADENCE="flat" ;;
    *) ARGS+=(--jitter "$JITTER"); CADENCE="spread by +-${JITTER} -- a deviation" ;;
esac

cat <<BANNER
tunnel client
  server   ${SERVER}
  egress   ${EGRESS}
  timeout  ${TIMEOUT}s
  cadence  ${CADENCE}
  ledger   ${LEDGER}

A server quieter than ${TIMEOUT}s makes this reconnect on that period, and
that is the cadence being measured. A server that CLOSES the connection
makes this exit instead -- the original does not reconnect from a close,
and neither does this.
BANNER

exec "$PYTHON" "${ARGS[@]}" "$@"
