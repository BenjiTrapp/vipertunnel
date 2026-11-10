#!/usr/bin/env python3
"""The counterpart the published family never shipped, derived from its client.

Only the client side of this backdoor was ever published, so this server is
written to the derivation in `../client/client.py` rather than to a sample.
Where the two disagree the client is right: it is the artefact that was
observed, and this exists to talk to it.

Three sockets, and the first two are the ones a detection sees:

  * **The command socket** (default 443) is where clients connect and stay.
    It is also what a scanner hits, and what it gets back is the two bytes
    `00 00` -- the keep-alive, and the fingerprint by which researchers
    enumerated this family's infrastructure across hosting providers. That
    is reproduced rather than fixed, because a measurement of the family's
    traffic that quietly removed its most distinctive property would be
    measuring something else.
  * **A relay socket per session**, on an ephemeral high port, announced to
    a client over its command connection. A scan of a real C2 of this family
    shows a spread of five-digit ports for exactly this reason.
  * **An operator SOCKS5 port**, on loopback, which speaks real RFC 1928 so
    `curl --socks5`, `proxychains` and `nmap` work unmodified. The server
    translates between the RFC and the client's dialect, because the dialect
    has no version bytes, little-endian ports and inverted status codes.

## The knob the measurement turns

`--keepalive` is the experimental variable, and its effect is a step rather
than a slope, because of a constant in the client:

  * **Below the client's timeout** (120 s in the original): one TCP
    connection, held open indefinitely. A proxy logs one CONNECT and a byte
    count. There is no cadence for a periodicity detection to find.
  * **Above it, or zero for never:** the client's read times out, it tears
    the connection down and builds a new one. A proxy log then shows a
    reconnect every ~120 seconds.

And the asymmetry worth knowing before running an experiment: this server
**cannot choose any other cadence.** If it closes a command connection, the
original client does not reconnect -- it reads zero bytes, `struct` raises,
and the process exits. Only a timeout restarts it. So the choice is 120 s or
nothing, unless the client's constant is changed, which `client.py --timeout`
allows and labels a deviation.
"""

import argparse
import logging
import os
import select
import socket
import socketserver
import struct
import sys
import threading
import time

LOG = logging.getLogger("tunnel.server")

_U8 = struct.Struct("B")
_U16_LE = struct.Struct("H")        # the client's byte order, not the RFC's
_U16_BE = struct.Struct(">H")       # the operator's side, which is the RFC
_TRIPLE = struct.Struct("BBB")
_PAIR = struct.Struct("BB")

_CMD_CONNECT = 1
_ATYP_IPV4 = 1
_ATYP_DOMAIN = 3
_ATYP_IPV6 = 4

_AUTH_NONE = 0
_AUTH_USERPASS = 2

_DIALECT_OK = 1                     # inverted against RFC 1928
_DIALECT_FAIL = 0

_RFC_VERSION = 5
_RFC_OK = 0
_RFC_GENERAL_FAILURE = 1
_RFC_HOST_UNREACHABLE = 4
_RFC_REFUSED = 5
_RFC_CMD_UNSUPPORTED = 7

_RELAY_CHUNK = 16384
_PAIR_TIMEOUT = 30.0


class Ledger(object):
    """Ground truth for the measurement. See the client's copy for the why."""

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


def _recv_exactly(sock, count):
    chunks = []
    have = 0
    while have < count:
        chunk = sock.recv(count - have)
        if not chunk:
            raise OSError("peer closed after %d of %d bytes" % (have, count))
        chunks.append(chunk)
        have += len(chunk)
    return b"".join(chunks)


def _bridge(first, second):
    socks = [first, second]
    while True:
        ready, _, _ = select.select(socks, [], socks, 1.0)
        for sock in ready:
            other = second if sock is first else first
            try:
                chunk = sock.recv(_RELAY_CHUNK)
            except OSError:
                return
            if not chunk:
                return
            try:
                other.sendall(chunk)
            except OSError:
                return


class Client(object):
    """One connected implant, and the lock that keeps two writers apart.

    The keep-alive thread and an operator asking for a relay both write to
    this socket. `sendall` loops over partial sends and releases the GIL, so
    it is not atomic against another thread -- the lock is not decorative.
    """

    def __init__(self, sock, peer, ledger):
        self.sock = sock
        self.peer = peer
        self.ledger = ledger
        self.opened = time.monotonic()
        self.keepalives = 0
        self._write = threading.Lock()
        self._alive = True

    def send_port(self, port):
        with self._write:
            self.sock.sendall(_U16_LE.pack(port))

    def keepalive(self):
        """Send the zero port, and read the client's zero back.

        These two bytes are the published fingerprint. Sending them is the
        point: a measurement of this family's traffic that left them out
        would not be measuring this family.
        """
        with self._write:
            self.sock.sendall(_U16_LE.pack(0))
        echo = _recv_exactly(self.sock, 2)
        if _U16_LE.unpack(echo)[0] != 0:
            raise OSError("client answered a keep-alive with something else")
        self.keepalives += 1

    def close(self):
        self._alive = False
        try:
            self.sock.close()
        except OSError:
            pass

    @property
    def alive(self):
        return self._alive


class Fleet(object):
    """The connected clients, and whose turn it is to carry a session."""

    def __init__(self, ledger):
        self._clients = []
        self._lock = threading.Lock()
        self._next = 0
        self.ledger = ledger

    def add(self, client):
        with self._lock:
            self._clients.append(client)
        self.ledger.record("client-connected", peer=client.peer,
                           connected=len(self._clients))

    def remove(self, client):
        with self._lock:
            if client in self._clients:
                self._clients.remove(client)
            remaining = len(self._clients)
        held = int(time.monotonic() - client.opened)
        self.ledger.record("client-gone", peer=client.peer,
                           held_seconds=held, keepalives=client.keepalives,
                           connected=remaining)

    def pick(self):
        """Round-robin, so several implants share a measurement's traffic."""
        with self._lock:
            if not self._clients:
                return None
            self._next %= len(self._clients)
            client = self._clients[self._next]
            self._next += 1
            return client

    def snapshot(self):
        with self._lock:
            return list(self._clients)


class RelayBroker(object):
    """Hands a client a port to dial, and pairs what dials in with a session.

    The client's dial-in carries no identifier -- it simply connects to the
    port it was told. So the pairing is by port: one listener per pending
    session, closed as soon as it has been used. That is why a scan of one of
    these servers shows a spread of five-digit ports, and it is the reason
    the original could be hijacked by whoever reached the port first.
    Reproduced, because it is a property of the family's traffic.
    """

    def __init__(self, bind_host, ledger):
        self._bind_host = bind_host
        self.ledger = ledger

    def open_session(self, client):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self._bind_host, 0))
        listener.listen(1)
        listener.settimeout(_PAIR_TIMEOUT)
        port = listener.getsockname()[1]
        try:
            client.send_port(port)
            self.ledger.record("relay-announced", peer=client.peer, port=port)
            sock, peer = listener.accept()
            self.ledger.record("relay-paired", port=port, peer="%s:%d" % peer)
            sock.settimeout(None)
            return sock
        finally:
            listener.close()


class OperatorHandler(socketserver.BaseRequestHandler):
    """RFC 1928 on this side, the client's dialect on the other.

    Every difference between the two is a deviation the original introduced
    and this has to undo: the version bytes it dropped, the byte order it
    got backwards, and the status codes it inverted.
    """

    def handle(self):
        operator = self.request
        broker = self.server.broker
        fleet = self.server.fleet
        ledger = self.server.ledger

        try:
            self._greet(operator)
            cmd, host, port = self._read_request(operator)
        except OSError as exc:
            LOG.debug("operator went away during the handshake: %s", exc)
            return

        if cmd != _CMD_CONNECT:
            self._reply(operator, _RFC_CMD_UNSUPPORTED)
            return

        client = fleet.pick()
        if client is None:
            ledger.record("operator-refused", reason="no client connected",
                          host=host, port=port)
            self._reply(operator, _RFC_GENERAL_FAILURE)
            return

        try:
            relay = broker.open_session(client)
        except (OSError, socket.timeout) as exc:
            ledger.record("relay-failed", peer=client.peer, error=exc)
            self._reply(operator, _RFC_GENERAL_FAILURE)
            return

        try:
            bound = self._drive_dialect(relay, host, port)
        except OSError as exc:
            ledger.record("dialect-failed", host=host, port=port, error=exc)
            self._reply(operator, _RFC_HOST_UNREACHABLE)
            relay.close()
            return

        if bound is None:
            ledger.record("target-refused-by-client", host=host, port=port)
            self._reply(operator, _RFC_REFUSED)
            relay.close()
            return

        ledger.record("session-open", host=host, port=port,
                      peer=client.peer)
        self._reply(operator, _RFC_OK, bound[0], bound[1])
        try:
            _bridge(operator, relay)
        finally:
            ledger.record("session-close", host=host, port=port)
            relay.close()

    # -- the operator's side, which is the RFC --------------------------------

    def _greet(self, operator):
        header = _recv_exactly(operator, 2)
        version, count = _PAIR.unpack(header)
        if version != _RFC_VERSION:
            raise OSError("operator is not speaking SOCKS5")
        methods = _recv_exactly(operator, count)
        if self.server.credentials is None:
            if _AUTH_NONE not in methods:
                operator.sendall(_PAIR.pack(_RFC_VERSION, 255))
                raise OSError("operator would not accept no-auth")
            operator.sendall(_PAIR.pack(_RFC_VERSION, _AUTH_NONE))
            return
        if _AUTH_USERPASS not in methods:
            operator.sendall(_PAIR.pack(_RFC_VERSION, 255))
            raise OSError("operator would not offer username/password")
        operator.sendall(_PAIR.pack(_RFC_VERSION, _AUTH_USERPASS))
        # RFC 1929: VER ULEN UNAME PLEN PASSWD
        if _recv_exactly(operator, 1) != b"\x01":
            raise OSError("bad RFC 1929 version")
        ulen = _U8.unpack(_recv_exactly(operator, 1))[0]
        user = _recv_exactly(operator, ulen)
        plen = _U8.unpack(_recv_exactly(operator, 1))[0]
        secret = _recv_exactly(operator, plen)
        want_user, want_secret = self.server.credentials
        ok = (user.decode("utf-8", "replace") == want_user
              and secret.decode("utf-8", "replace") == want_secret)
        operator.sendall(b"\x01" + (b"\x00" if ok else b"\x01"))
        if not ok:
            raise OSError("operator credentials refused")

    def _read_request(self, operator):
        version, cmd, reserved, atyp = struct.unpack(
            "BBBB", _recv_exactly(operator, 4))
        if version != _RFC_VERSION or reserved != 0:
            raise OSError("malformed SOCKS5 request")
        if atyp == _ATYP_IPV4:
            host = socket.inet_ntoa(_recv_exactly(operator, 4))
        elif atyp == _ATYP_DOMAIN:
            length = _U8.unpack(_recv_exactly(operator, 1))[0]
            host = _recv_exactly(operator, length).decode("utf-8", "replace")
        elif atyp == _ATYP_IPV6:
            # The client refuses IPv6, so accepting it here would only move
            # the failure one hop further away from the operator.
            _recv_exactly(operator, 16)
            _recv_exactly(operator, 2)
            raise OSError("the client's dialect has no IPv6")
        else:
            raise OSError("unknown address type %d" % atyp)
        port = _U16_BE.unpack(_recv_exactly(operator, 2))[0]
        return cmd, host, port

    def _reply(self, operator, code, host="0.0.0.0", port=0):
        try:
            operator.sendall(
                struct.pack("BBBB", _RFC_VERSION, code, 0, _ATYP_IPV4)
                + socket.inet_pton(socket.AF_INET, host)
                + _U16_BE.pack(port))
        except OSError:
            pass

    # -- the client's side, which is the dialect ------------------------------

    def _drive_dialect(self, relay, host, port):
        """Speak the greeting, the request and read the reply.

        Returns the bound address the client reported, or None if the client
        refused the target.
        """
        # Greeting with NO version byte: just a count and the methods.
        if self.server.client_credentials is None:
            relay.sendall(_U8.pack(1) + _U8.pack(_AUTH_NONE))
        else:
            relay.sendall(_U8.pack(1) + _U8.pack(_AUTH_USERPASS))
        chosen = _U8.unpack(_recv_exactly(relay, 1))[0]

        if chosen == _AUTH_USERPASS:
            user, secret = self.server.client_credentials or ("", "")
            raw_user = user.encode("utf-8")
            raw_secret = secret.encode("utf-8")
            # Both lengths first, then both strings.
            relay.sendall(_PAIR.pack(len(raw_user), len(raw_secret))
                          + raw_user + raw_secret)
            if _U8.unpack(_recv_exactly(relay, 1))[0] != _DIALECT_OK:
                raise OSError("the client refused our credentials")
        elif chosen != _AUTH_NONE:
            raise OSError("the client chose method %d" % chosen)

        try:
            packed = socket.inet_pton(socket.AF_INET, host)
        except OSError:
            raw = host.encode("utf-8")
            relay.sendall(_TRIPLE.pack(_CMD_CONNECT, _ATYP_DOMAIN, len(raw))
                          + raw + _U16_LE.pack(port))
        else:
            # `addrlen` is sent even for IPv4, where the client ignores it.
            relay.sendall(_TRIPLE.pack(_CMD_CONNECT, _ATYP_IPV4, 4)
                          + packed + _U16_LE.pack(port))

        status = _U8.unpack(_recv_exactly(relay, 1))[0]
        if status != _DIALECT_OK:
            return None
        atyp, addrlen = _PAIR.unpack(_recv_exactly(relay, 2))
        if atyp != _ATYP_IPV4 or addrlen != 4:
            raise OSError("the client answered with an address we cannot read")
        bound_host = socket.inet_ntoa(_recv_exactly(relay, 4))
        bound_port = _U16_LE.unpack(_recv_exactly(relay, 2))[0]
        return bound_host, bound_port


class OperatorServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, fleet, broker, ledger,
                 credentials, client_credentials):
        self.fleet = fleet
        self.broker = broker
        self.ledger = ledger
        self.credentials = credentials
        self.client_credentials = client_credentials
        super(OperatorServer, self).__init__(address, OperatorHandler)


def _serve_clients(listener, fleet, keepalive, ledger, stop):
    """Accept implants and keep each one's connection the way the knob says."""

    def hold(sock, peer):
        client = Client(sock, "%s:%d" % peer, ledger)
        fleet.add(client)
        try:
            while not stop.is_set():
                if keepalive <= 0:
                    # Never send one. The client's read then times out and it
                    # reconnects, which is the cadence being measured.
                    #
                    # But we still have to notice it leaving, which is why
                    # this watches the socket instead of merely sleeping: a
                    # peer that has gone reads as readable with zero bytes,
                    # and without this check the fleet fills with clients
                    # that are not there. `pick` would then hand an operator
                    # a dead connection and the session would fail for a
                    # reason that has nothing to do with the measurement.
                    ready, _, _ = select.select([sock], [], [sock], 1.0)
                    if ready:
                        if not sock.recv(1, socket.MSG_PEEK):
                            raise OSError("client closed the command channel")
                        # Bytes we did not ask for. The client only ever
                        # speaks in answer to a keep-alive, so this is not
                        # our client.
                        raise OSError("unsolicited bytes on the command channel")
                    continue
                if stop.wait(keepalive):
                    return
                client.keepalive()
        except OSError as exc:
            LOG.debug("client %s went away: %s", client.peer, exc)
        finally:
            client.close()
            fleet.remove(client)

    while not stop.is_set():
        try:
            sock, peer = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        sock.settimeout(None)
        threading.Thread(target=hold, args=(sock, peer),
                         name="client-%s:%d" % peer, daemon=True).start()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="The counterpart the published family never shipped, "
                    "derived from its client.")
    parser.add_argument("--bind", default="0.0.0.0", metavar="HOST",
                        help="where to accept implants (default %(default)s)")
    parser.add_argument("--port", type=int, default=443, metavar="PORT",
                        help="the command port (default %(default)s, the "
                             "family's)")
    parser.add_argument("--socks", type=int, default=1080, metavar="PORT",
                        help="the operator's RFC 1928 port, on loopback "
                             "(default %(default)s)")
    parser.add_argument("--keepalive", type=float, default=60.0,
                        metavar="SECONDS",
                        help="THE MEASUREMENT KNOB. Below the client's "
                             "timeout (120s) this holds one connection open "
                             "and there is no cadence to detect; above it, "
                             "or 0 for never, the client reconnects every "
                             "~120s and a proxy log shows that cadence. "
                             "Default %(default)s.")
    parser.add_argument("--socks-user", metavar="USER",
                        help="require RFC 1929 credentials on the operator "
                             "port (loopback is not isolation from other "
                             "local users)")
    parser.add_argument("--socks-password", metavar="SECRET")
    parser.add_argument("--client-user", metavar="USER",
                        help="offer these credentials to the implant instead "
                             "of no-auth")
    parser.add_argument("--client-password", metavar="SECRET")
    parser.add_argument("--ledger", metavar="PATH",
                        help="append an event line per client, keep-alive, "
                             "relay and session -- the ground truth to check "
                             "a detection's report against")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")

    if args.port < 1024 and os.geteuid() != 0:
        LOG.error("binding port %d needs root, or pick a higher --port. "
                  "443 is the family's port and is worth keeping for a "
                  "measurement; a different one changes what the proxy "
                  "allows.", args.port)
        return 2

    ledger = Ledger(args.ledger)
    fleet = Fleet(ledger)
    broker = RelayBroker(args.bind, ledger)
    stop = threading.Event()

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.bind, args.port))
    listener.listen(16)
    listener.settimeout(1.0)

    credentials = None
    if args.socks_user:
        credentials = (args.socks_user, args.socks_password or "")
    client_credentials = None
    if args.client_user:
        client_credentials = (args.client_user, args.client_password or "")

    operator = OperatorServer(("127.0.0.1", args.socks), fleet, broker,
                              ledger, credentials, client_credentials)

    shape = ("one held connection, no cadence"
             if 0 < args.keepalive < 120 else
             "a reconnect every ~120s, which is the client's timeout")
    ledger.record("server-start", command_port=args.port,
                  socks_port=args.socks, keepalive=int(args.keepalive),
                  expected_shape=shape.replace(" ", "_"))
    LOG.info("keep-alive %.0fs means: %s", args.keepalive, shape)

    threads = [
        threading.Thread(target=_serve_clients,
                         args=(listener, fleet, args.keepalive, ledger, stop),
                         name="command", daemon=True),
        threading.Thread(target=operator.serve_forever, name="operator",
                         daemon=True),
    ]
    for thread in threads:
        thread.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        LOG.info("stopping")
    finally:
        stop.set()
        operator.shutdown()
        listener.close()
        for client in fleet.snapshot():
            client.close()
        ledger.record("server-stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
