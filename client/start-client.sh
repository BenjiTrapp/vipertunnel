#!/usr/bin/env bash
#
# Start the implant for a Beacon Reaper measurement.
#
# PROXY is not optional for this measurement, even though it is a deviation
# from the family: the Reaper reads proxy logs, so a host with direct egress
# produces nothing for it to see. Point this at whatever CONNECT proxy the
# victim would really use.
#
# In the CSIRT lab that is the local NTLM relay rather than the corporate
# proxy directly:
#
#   PROXY=127.0.0.1:3128 ./start-client.sh 10.104.20.134
#
# The bytes between this process and the server are unchanged by the proxy
# leg -- it is transport only, which is what keeps this faithful where the
# measurement cares.

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
LEDGER="${LEDGER:-$HERE/client-ledger.log}"
PYTHON="${PYTHON:-python3}"

ARGS=("$HERE/client.py" "$SERVER" --timeout "$TIMEOUT" --ledger "$LEDGER")
if [ -n "$PROXY" ]; then
    ARGS+=(--proxy "$PROXY")
    EGRESS="through $PROXY"
else
    EGRESS="DIRECT -- a proxy-log detection will see nothing"
fi

cat <<BANNER
tunnel client
  server   ${SERVER}
  egress   ${EGRESS}
  timeout  ${TIMEOUT}s
  ledger   ${LEDGER}

A server quieter than ${TIMEOUT}s makes this reconnect on that period, and
that is the cadence being measured. A server that CLOSES the connection
makes this exit instead -- the original does not reconnect from a close,
and neither does this.
BANNER

exec "$PYTHON" "${ARGS[@]}" "$@"
