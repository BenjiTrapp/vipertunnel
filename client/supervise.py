#!/usr/bin/env python3
"""Keep the client running, and date every time it stops.

The client does not reconnect after a close. It reads zero bytes, treats that
as the server hanging up, and returns -- the original does the same, and this
is reproduced rather than fixed. The cost is that anything which resets the
connection mid-tunnel, a CONNECT proxy that ends tunnels after a fixed time
being the likeliest, ends the process and nothing brings it back.

So supervision lives out here, not inside `client.py`. That is also closer to
the original, which relies on an outside trigger to start it again rather than
on reconnect logic of its own.

It is also a measurement. Every restart records how long the previous run
lived, which turns "the channel died" into a dated number: a lifetime that
comes out the same every time is a limit somebody imposed, and a scatter is
not.
"""

import argparse
import logging
import os
import subprocess
import sys
import time

LOG = logging.getLogger("tunnel.supervise")


def _record(ledger, event, **fields):
    # The ledger is the measurement, but it is not worth the run: a full disk
    # or a bad path must not end the thing being observed.
    try:
        ledger.record(event, **fields)
    except OSError as exc:
        LOG.error("could not write %s to the ledger: %s", event, exc)


def supervise(argv, ledger, *, backoff_base=60.0, backoff_max=600.0,
              max_rapid_failures=5, rapid_seconds=60.0,
              spawn=subprocess.Popen, sleep=time.sleep, clock=time.monotonic):
    """Run `argv` until it is interrupted, restarting it whenever it exits.

    A child that lived at least `rapid_seconds` is restarted at once and wipes
    the slate -- that is the expected death, a long run ending. One that died
    sooner is a fault, and each fault in a row waits twice as long as the last
    (from `backoff_base` up to `backoff_max`). `max_rapid_failures` of them in
    a row stop the whole thing with 1: a client that cannot stay up is
    something to look at, not something to hammer a proxy with.

    Returns 0 when interrupted (Ctrl-C), 1 when it gives up.
    """
    attempt = 0
    rapid_failures = 0
    backoff = 0.0
    try:
        while True:
            attempt += 1
            started = clock()
            child = spawn(argv)
            exit_code = child.wait()
            lifetime = clock() - started
            _record(ledger, "child-exit", exit_code=exit_code,
                    lifetime_seconds=int(lifetime), attempt=attempt)

            if lifetime >= rapid_seconds:
                rapid_failures = 0
                backoff = 0.0
                continue

            rapid_failures += 1
            if rapid_failures >= max_rapid_failures:
                _record(ledger, "supervisor-gave-up",
                        rapid_failures=rapid_failures)
                return 1
            backoff = backoff_base if backoff == 0.0 else min(backoff * 2,
                                                              backoff_max)
            _record(ledger, "supervisor-backoff", seconds=backoff)
            sleep(backoff)
    except KeyboardInterrupt:
        # Ctrl-C reaches the client too, since it shares the terminal, so it
        # has already stopped by the time this is reached.
        _record(ledger, "supervisor-interrupted")
        return 0


def _ledger_class():
    # Run as a script, `client.py` sits beside this file and is just `client`;
    # imported as part of the package it is `client.client`.
    try:
        from .client import Ledger
    except ImportError:
        from client import Ledger
    return Ledger


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the tunnel client and restart it when it exits, "
                    "recording how long each run lived. Everything after "
                    "'--' is the client's own argument list; without '--', "
                    "everything after these options is.")
    parser.add_argument("--ledger", metavar="PATH",
                        help="append an event line per client exit and "
                             "restart; the same file the client's --ledger "
                             "writes to keeps both in one timeline")
    parser.add_argument("--backoff-base", type=float, default=60.0,
                        metavar="SECONDS",
                        help="wait before restarting after a short-lived run "
                             "(default %(default)s); doubles on each repeat")
    parser.add_argument("--backoff-max", type=float, default=600.0,
                        metavar="SECONDS",
                        help="the longest that wait grows to "
                             "(default %(default)s)")
    parser.add_argument("--max-rapid-failures", type=int, default=5,
                        metavar="N",
                        help="give up after this many short-lived runs in a "
                             "row (default %(default)s)")
    parser.add_argument("client_args", nargs=argparse.REMAINDER,
                        metavar="CLIENT_ARGS")

    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--" in arguments:
        split = arguments.index("--")
        args = parser.parse_args(arguments[:split])
        client_args = arguments[split + 1:]
    else:
        args = parser.parse_args(arguments)
        client_args = args.client_args
    if not client_args:
        parser.error("no client arguments given")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    here = os.path.dirname(os.path.abspath(__file__))
    command = [sys.executable, os.path.join(here, "client.py")] + client_args
    ledger = _ledger_class()(args.ledger)
    return supervise(command, ledger,
                     backoff_base=args.backoff_base,
                     backoff_max=args.backoff_max,
                     max_rapid_failures=args.max_rapid_failures)


if __name__ == "__main__":
    sys.exit(main())
