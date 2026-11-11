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

A fourth is optional and off by default: `--dashboard PORT` serves an
operator view on loopback, described in `dashboard.py`. It is out of band on
purpose -- a listening HTTP port is something this family does not have, so
it would show up in a scan of the measurement host as a trait of the tool
rather than of the family.

## One thing this is not faithful about, deliberately

`LabGuard` refuses to relay anywhere outside the private ranges, loopback and
link-local unless `--allow-public` is passed. The original has no such check
and would tunnel anywhere its operator pointed it. This one does, because an
operator port on loopback plus a mistyped CIDR is enough to scan the public
internet through somebody's workstation, and the authorisation note in the
README would have been the only thing that had stopped it. Refusals are
recorded.

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
import itertools
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

# How much of each direction is kept for the protocol summary. Enough for an
# HTTP request line with headers or a TLS ClientHello, and far too little to
# be a capture of anybody's traffic.
_SNIFF = 512

# Per-second volume buckets kept per host, so a closed session still has a
# shape on the timeline.
_VOLUME_SECONDS = 3600

# The client's read deadline, which this server does not set and cannot
# change. It is here because it is the threshold the keep-alive knob is
# measured against: below it one connection is held, above it the client
# reconnects on that period.
_CLIENT_TIMEOUT = 120


class Ledger(object):
    """Ground truth for the measurement. See the client's copy for the why."""

    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()
        self._watchers = []

    def subscribe(self, watcher):
        """Call `watcher(stamp, event, fields)` for every event from now on.

        The dashboard watches here rather than tailing the file, so it reads
        the same events the file gets rather than parsing back what was just
        formatted. A watcher must not block: it is called on whichever thread
        produced the event, including the one holding a client's socket.
        """
        with self._lock:
            self._watchers.append(watcher)

    def record(self, event, **fields):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        detail = " ".join("%s=%s" % (k, v) for k, v in sorted(fields.items()))
        line = "%s %s %s\n" % (stamp, event, detail)
        LOG.info("%s %s", event, detail)
        with self._lock:
            watchers = list(self._watchers)
        for watcher in watchers:
            # An observer is never worth the run: a dashboard that raises
            # must not take a client's command connection down with it.
            try:
                watcher(stamp, event, fields)
            except Exception as exc:                # pragma: no cover
                LOG.debug("a ledger watcher raised: %s", exc)
        if not self._path:
            return
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()


class Knob(object):
    """The measurement variable, held where several threads can read it.

    The keep-alive interval used to be a local in the command loop, which
    fixed the shape of a run at start-up. The dashboard can turn it mid-run,
    so the value lives here and the loop reads it again on every pass -- the
    step from "one held connection" to "a reconnect every ~120 s" then
    happens inside one run, which is the cheapest way to see both shapes in
    one timeline.
    """

    def __init__(self, seconds):
        self._seconds = float(seconds)
        self._lock = threading.Lock()

    @property
    def seconds(self):
        with self._lock:
            return self._seconds

    def set(self, seconds):
        seconds = float(seconds)
        if seconds < 0:
            raise ValueError("a keep-alive interval cannot be negative")
        with self._lock:
            previous, self._seconds = self._seconds, seconds
        return previous

    @property
    def shape(self):
        """What a proxy log will show at the current setting."""
        if 0 < self._seconds < _CLIENT_TIMEOUT:
            return "one held connection, no cadence"
        return "a reconnect every ~%ds, which is the client's timeout" % (
            _CLIENT_TIMEOUT,)


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


def _summarise(outbound, inbound):
    """Name the protocol from the first bytes of each direction.

    What a Zeek-style analyser would extract, and nothing more. The blue
    team's question about a tunnel is "what did they touch", and that is
    answerable from a request line or an SNI without keeping anybody's
    traffic. Every answer is hedged, because first bytes are a suggestion
    and not a proof.
    """
    head = bytes(outbound[:_SNIFF])
    back = bytes(inbound[:_SNIFF])

    if back[:4] == b"SSH-":
        banner = back.split(b"\r", 1)[0].split(b"\n", 1)[0]
        return "SSH -- server banner %s" % banner.decode("latin-1", "replace")

    first_line = head.split(b"\r\n", 1)[0]
    if b" HTTP/1." in first_line:
        request = first_line.decode("latin-1", "replace")[:120]
        host = ""
        for line in head.split(b"\r\n")[1:]:
            if line[:5].lower() == b"host:":
                host = " (Host: %s)" % line[5:].strip().decode(
                    "latin-1", "replace")[:80]
                break
        return "HTTP -- %s%s" % (request, host)

    if head[:1] == b"\x16" and head[1:2] == b"\x03":
        name = _client_hello_sni(head)
        return "TLS ClientHello%s" % (" -- SNI %s" % name if name else "")

    # NetBIOS length prefix, then the SMB magic.
    if head[:1] == b"\x00" and head[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return "SMB%s -- negotiate" % ("2" if head[4:5] == b"\xfe" else "1")

    if head[:2] == b"\x03\x00":
        return "TPKT/X.224 -- looks like RDP"

    if not head and not back:
        return "nothing crossed"
    return "unrecognised -- %d B out, %d B back before this was decided" % (
        len(outbound), len(inbound))


def _client_hello_sni(data):
    """Pull the server name out of a TLS ClientHello, or give up quietly.

    Hand-rolled because the standard library will not parse a handshake it
    did not make. Defensive throughout: a malformed or truncated hello must
    return nothing rather than raise into a relay thread.
    """
    try:
        if len(data) < 45:
            return None
        at = 43                                  # past record + handshake
        at += 1 + data[at]                       # session id
        if at + 2 > len(data):
            return None
        at += 2 + int.from_bytes(data[at:at + 2], "big")      # cipher suites
        if at >= len(data):
            return None
        at += 1 + data[at]                                    # compression
        if at + 2 > len(data):
            return None
        end = at + 2 + int.from_bytes(data[at:at + 2], "big")
        at += 2
        while at + 4 <= min(end, len(data)):
            kind = int.from_bytes(data[at:at + 2], "big")
            size = int.from_bytes(data[at + 2:at + 4], "big")
            body = data[at + 4:at + 4 + size]
            at += 4 + size
            if kind != 0 or len(body) < 5:        # 0 is server_name
                continue
            return body[5:5 + int.from_bytes(body[3:5], "big")].decode(
                "idna", "replace")[:100]
    except (IndexError, ValueError, UnicodeError):
        return None
    return None


class StreamMeter(object):
    """Volume, rate and a protocol summary for one relay session.

    The relays are the part of this traffic that carries volume, and until
    now the only visible fact about them was that they existed. This counts
    bytes per second in each direction and keeps the first few hundred bytes
    long enough to name the protocol.

    **It is not a capture.** The sniff buffer is bounded at %d bytes per
    direction and is discarded once the summary is made; the payload itself
    is never stored, never written to the ledger and never sent to the
    browser. That traffic belongs to the network under test.
    """ % _SNIFF

    def __init__(self):
        self.out_bytes = 0
        self.in_bytes = 0
        self.buckets = {}                  # epoch second -> [out, in]
        self._out_head = bytearray()
        self._in_head = bytearray()
        self._summary = None
        self._lock = threading.Lock()

    def _bucket(self, index, count):
        second = int(time.time())
        with self._lock:
            slot = self.buckets.setdefault(second, [0, 0])
            slot[index] += count
            if len(self.buckets) > _VOLUME_SECONDS:
                for stale in sorted(self.buckets)[:-_VOLUME_SECONDS]:
                    del self.buckets[stale]

    def to_target(self, chunk):
        self.out_bytes += len(chunk)
        if len(self._out_head) < _SNIFF:
            self._out_head += chunk[:_SNIFF - len(self._out_head)]
        self._bucket(0, len(chunk))

    def from_target(self, chunk):
        self.in_bytes += len(chunk)
        if len(self._in_head) < _SNIFF:
            self._in_head += chunk[:_SNIFF - len(self._in_head)]
        self._bucket(1, len(chunk))

    @property
    def summary(self):
        """Name the protocol once, then drop the bytes it was named from."""
        if self._summary is None and (self._out_head or self._in_head):
            self._summary = _summarise(self._out_head, self._in_head)
            if len(self._out_head) >= _SNIFF or self._in_head:
                self._out_head = bytearray()
                self._in_head = bytearray()
        return self._summary or "nothing crossed yet"

    def series(self, since):
        with self._lock:
            return {second: list(slot)
                    for second, slot in self.buckets.items()
                    if second >= since}


def _bridge(operator, relay, meter=None):
    """Move bytes between the operator and the implant until one side stops.

    `operator` is the RFC 1928 side and `relay` is the implant's, so a chunk
    read from the operator is heading for the target and one read from the
    relay is coming back from it. The meter needs that distinction; the
    bridge itself does not care.
    """
    socks = [operator, relay]
    while True:
        ready, _, _ = select.select(socks, [], socks, 1.0)
        for sock in ready:
            other = relay if sock is operator else operator
            try:
                chunk = sock.recv(_RELAY_CHUNK)
            except OSError:
                return
            if not chunk:
                return
            if meter is not None:
                if sock is operator:
                    meter.to_target(chunk)
                else:
                    meter.from_target(chunk)
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

    _ids = itertools.count(1)

    def __init__(self, sock, peer, ledger):
        self.sock = sock
        self.peer = peer
        self.ledger = ledger
        # A stable handle for the dashboard. The peer address is not one: the
        # source port changes on every reconnect, which is the very thing the
        # cadence measurement is watching.
        self.id = next(Client._ids)
        self.opened = time.monotonic()
        self.opened_wall = time.time()
        self.keepalives = 0
        self.sessions = 0
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
        self.ledger.record("keepalive", peer=self.peer,
                           count=self.keepalives)

    def close(self):
        self._alive = False
        try:
            self.sock.close()
        except OSError:
            pass

    @property
    def alive(self):
        return self._alive

    def describe(self):
        return {
            "id": self.id,
            "peer": self.peer,
            "host": self.peer.rsplit(":", 1)[0],
            "opened": self.opened_wall,
            "held_seconds": int(time.monotonic() - self.opened),
            "keepalives": self.keepalives,
            "sessions": self.sessions,
        }


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

    def find(self, client_id):
        with self._lock:
            for client in self._clients:
                if client.id == client_id:
                    return client
        return None


class WireLog(object):
    """The actual bytes of the last few dialect handshakes.

    This repository's whole claim is that it reproduces one family's wire
    faithfully. Until now that claim lived in a table in the documentation
    and nowhere in the running program, so it had to be taken on trust. A
    capture puts the bytes that actually went out beside what the derivation
    says they should be, which makes the claim checkable instead.

    **Handshakes only.** The relayed payload is never captured: it is the
    victim network's own traffic, it is unbounded, and none of it is needed
    to show that the dialect is right.
    """

    _ids = itertools.count(1)

    def __init__(self, limit=8):
        self._limit = limit
        self._captures = []
        self._lock = threading.Lock()

    def start(self, peer, target):
        return _Capture(self, peer, target)

    def _add(self, capture):
        with self._lock:
            self._captures.append(capture)
            if len(self._captures) > self._limit:
                del self._captures[:len(self._captures) - self._limit]

    def snapshot(self):
        with self._lock:
            return [capture.describe() for capture in reversed(self._captures)]


class _Capture(object):
    """One handshake, step by step, with the deviation named at each step."""

    # A domain name can be 255 bytes and nothing here is longer; the cap
    # keeps a malformed peer from filling the ring with one step.
    _MAX = 300

    def __init__(self, log, peer, target):
        self._log = log
        self.id = next(WireLog._ids)
        self.peer = peer
        self.target = target
        self.at = time.time()
        self.steps = []
        self.outcome = "incomplete"

    def step(self, direction, label, data, note):
        raw = bytes(data)[:self._MAX]
        self.steps.append({
            "direction": direction,        # "to-implant" or "from-implant"
            "label": label,
            "hex": " ".join("%02x" % byte for byte in raw),
            "bytes": len(data),
            "note": note,
        })

    def finish(self, outcome):
        self.outcome = outcome
        self._log._add(self)

    def describe(self):
        return {
            "id": self.id,
            "at": self.at,
            "peer": self.peer,
            "target": self.target,
            "outcome": self.outcome,
            "steps": self.steps,
        }


class SessionBook(object):
    """The relay sessions carrying traffic right now.

    Not needed by the protocol -- the server pairs by port and then forgets.
    It exists so the dashboard can show what is open, and so a session can be
    put on a timeline next to the command connection that announced it.
    """

    _ids = itertools.count(1)

    def __init__(self):
        self._open = {}
        self._lock = threading.Lock()
        # Closed sessions leave their per-second volume behind, keyed by
        # implant host, so a session that ended five minutes ago still has a
        # shape on the timeline rather than vanishing from it.
        self._archive = {}

    def open(self, client, host, port, relay_port):
        entry = {
            "id": next(SessionBook._ids),
            "client_id": client.id,
            "peer": client.peer,
            "host": host,
            "port": port,
            "relay_port": relay_port,
            "opened": time.time(),
            "started": time.monotonic(),
            "meter": StreamMeter(),
        }
        with self._lock:
            self._open[entry["id"]] = entry
        return entry

    def close(self, entry):
        with self._lock:
            self._open.pop(entry["id"], None)
            implant = entry["peer"].rsplit(":", 1)[0]
            archive = self._archive.setdefault(implant, {})
            for second, slot in entry["meter"].buckets.items():
                kept = archive.setdefault(second, [0, 0])
                kept[0] += slot[0]
                kept[1] += slot[1]
            if len(archive) > _VOLUME_SECONDS:
                for stale in sorted(archive)[:-_VOLUME_SECONDS]:
                    del archive[stale]

    def snapshot(self):
        now = time.monotonic()
        with self._lock:
            entries = list(self._open.values())
        out = []
        for entry in sorted(entries, key=lambda e: e["id"]):
            meter = entry["meter"]
            age = max(1, int(now - entry["started"]))
            out.append({
                "id": entry["id"],
                "client_id": entry["client_id"],
                "peer": entry["peer"],
                "target": "%s:%d" % (entry["host"], entry["port"]),
                "relay_port": entry["relay_port"],
                "opened": entry["opened"],
                "age_seconds": int(now - entry["started"]),
                "out_bytes": meter.out_bytes,
                "in_bytes": meter.in_bytes,
                "rate": int((meter.out_bytes + meter.in_bytes) / age),
                "summary": meter.summary,
                "recent": _as_series(meter.series(int(time.time()) - 60)),
            })
        return out

    def volume(self, since):
        """Per-second volume per implant host, live sessions and closed."""
        merged = {}
        with self._lock:
            for implant, archive in self._archive.items():
                target = merged.setdefault(implant, {})
                for second, slot in archive.items():
                    if second < since:
                        continue
                    kept = target.setdefault(second, [0, 0])
                    kept[0] += slot[0]
                    kept[1] += slot[1]
            entries = list(self._open.values())
        for entry in entries:
            implant = entry["peer"].rsplit(":", 1)[0]
            target = merged.setdefault(implant, {})
            for second, slot in entry["meter"].series(since).items():
                kept = target.setdefault(second, [0, 0])
                kept[0] += slot[0]
                kept[1] += slot[1]
        return {implant: _as_series(buckets)
                for implant, buckets in merged.items()}


def _as_series(buckets):
    """Sparse `[second, out, in]` triples -- only the seconds with traffic."""
    return [[second, slot[0], slot[1]]
            for second, slot in sorted(buckets.items())]


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
        """Return `(socket, port)` once the client has dialled back in."""
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
            return sock, port
        finally:
            listener.close()


class Phases(object):
    """Named spans of a run, for an exercise both teams are watching.

    A measurement is usually two or three deliberate stretches -- "held
    connection", then "cadence", then "traffic through it" -- and the
    boundaries are the only thing that makes an alert's timestamp mean
    anything. Without them a report says "the rule fired at 14:12" and
    nobody can say what was running at 14:12.

    Each boundary is a ledger line, so the phases survive in the artefact a
    finding cites rather than only in a browser tab.
    """

    _ids = itertools.count(1)

    def __init__(self, ledger):
        self._ledger = ledger
        self._phases = []
        self._lock = threading.Lock()

    def start(self, name, knob=None):
        name = str(name)[:120].strip() or "unnamed"
        self.stop()
        phase = {"id": next(Phases._ids), "name": name,
                 "started": time.time(), "ended": None,
                 "keepalive": knob.seconds if knob else None}
        with self._lock:
            self._phases.append(phase)
        self._ledger.record("phase-start", name=name.replace(" ", "_"),
                            keepalive=phase["keepalive"])
        return phase

    def stop(self):
        with self._lock:
            open_phase = next((p for p in reversed(self._phases)
                               if p["ended"] is None), None)
            if open_phase is None:
                return None
            open_phase["ended"] = time.time()
        self._ledger.record(
            "phase-end", name=open_phase["name"].replace(" ", "_"),
            held_seconds=int(open_phase["ended"] - open_phase["started"]))
        return open_phase

    def current(self):
        with self._lock:
            return next((dict(p) for p in reversed(self._phases)
                         if p["ended"] is None), None)

    def snapshot(self):
        with self._lock:
            return [dict(p) for p in self._phases]


class LabGuard(object):
    """Refuse to relay anywhere that is obviously not your lab.

    The authorisation note in the README says this is adversary emulation in
    a lab you own. The program did nothing to hold itself to that: an
    operator port on loopback will happily tunnel a scan of the public
    internet through somebody's workstation, and a typo in a CIDR is enough.

    So by default the targets allowed are the private ranges, loopback and
    link-local. `--allow-public` turns the guard off and says so in the
    ledger, because sometimes a lab really does use routable space -- but it
    should then be a decision somebody made rather than a default nobody
    noticed. Refusals are recorded; a quiet guard would be its own trap.
    """

    def __init__(self, allow_public=False):
        self.allow_public = allow_public

    def refuse(self, host):
        """Return a reason to refuse `host`, or None to allow it."""
        if self.allow_public:
            return None
        try:
            packed = socket.inet_pton(socket.AF_INET, host)
        except OSError:
            # A name, not an address. Resolving it here would be a lookup the
            # original never makes, so the name is judged by what it resolves
            # to only if resolution is free -- and refused otherwise.
            try:
                host = socket.gethostbyname(host)
                packed = socket.inet_pton(socket.AF_INET, host)
            except OSError:
                return ("the name did not resolve, so it cannot be shown to "
                        "be inside the lab (use --allow-public to permit it)")
        a, b = packed[0], packed[1]
        private = (a == 10
                   or (a == 172 and 16 <= b <= 31)
                   or (a == 192 and b == 168)
                   or a == 127
                   or (a == 169 and b == 254)
                   or (a == 100 and 64 <= b <= 127))      # CGNAT, RFC 6598
        if private:
            return None
        return ("%s is outside the private ranges, loopback and link-local. "
                "This is adversary emulation for a lab you own; pass "
                "--allow-public if the lab really is on routable space."
                % host)


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

        refusal = self.server.guard.refuse(host)
        if refusal:
            ledger.record("target-outside-the-lab", host=host, port=port,
                          reason=refusal.replace(" ", "_"))
            LOG.error("refusing %s:%d -- %s", host, port, refusal)
            self._reply(operator, _RFC_REFUSED)
            return

        client = fleet.pick()
        if client is None:
            ledger.record("operator-refused", reason="no client connected",
                          host=host, port=port)
            self._reply(operator, _RFC_GENERAL_FAILURE)
            return

        try:
            relay, relay_port = broker.open_session(client)
        except (OSError, socket.timeout) as exc:
            ledger.record("relay-failed", peer=client.peer, error=exc)
            self._reply(operator, _RFC_GENERAL_FAILURE)
            return

        capture = self.server.wire.start(client.peer, "%s:%d" % (host, port))
        capture.step("to-implant", "relay port announced",
                     _U16_LE.pack(relay_port),
                     "a bare uint16, little-endian: the port to dial back "
                     "on. Not in RFC 1928 at all -- the command channel "
                     "carries nothing else, and a zero here is the "
                     "keep-alive.")
        try:
            bound = self._drive_dialect(relay, host, port, capture)
        except OSError as exc:
            capture.finish("failed: %s" % exc)
            ledger.record("dialect-failed", host=host, port=port, error=exc)
            self._reply(operator, _RFC_HOST_UNREACHABLE)
            relay.close()
            return

        if bound is None:
            capture.finish("the implant could not reach the target")
            ledger.record("target-refused-by-client", host=host, port=port)
            self._reply(operator, _RFC_REFUSED)
            relay.close()
            return

        capture.finish("carried")
        client.sessions += 1
        entry = self.server.sessions.open(client, host, port, relay_port)
        ledger.record("session-open", host=host, port=port,
                      peer=client.peer)
        self._reply(operator, _RFC_OK, bound[0], bound[1])
        try:
            _bridge(operator, relay, entry["meter"])
        finally:
            meter = entry["meter"]
            self.server.sessions.close(entry)
            # The volume and the protocol belong in the ledger: they are the
            # facts a volume-based detection would have had, and the file is
            # what a finding cites. The payload itself is never recorded.
            ledger.record("session-close", host=host, port=port,
                          out_bytes=meter.out_bytes,
                          in_bytes=meter.in_bytes,
                          saw=meter.summary.replace(" ", "_"))
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

    def _drive_dialect(self, relay, host, port, capture=None):
        """Speak the greeting, the request and read the reply.

        Returns the bound address the client reported, or None if the client
        refused the target.

        `capture` records the bytes and names the deviation at every step, so
        the claim that this is the family's wire can be read off the running
        program rather than taken from a table.
        """
        def note(direction, label, data, text):
            if capture is not None:
                capture.step(direction, label, data, text)

        # Greeting with NO version byte: just a count and the methods.
        if self.server.client_credentials is None:
            greeting = _U8.pack(1) + _U8.pack(_AUTH_NONE)
            which = "method 0, no authentication"
        else:
            greeting = _U8.pack(1) + _U8.pack(_AUTH_USERPASS)
            which = "method 2, username and password"
        relay.sendall(greeting)
        note("to-implant", "greeting", greeting,
             "nmethods | methods -- %s. RFC 1928 puts a 05 version byte "
             "first; this dialect has none, which is why an RFC client "
             "deadlocks against it." % which)
        chosen = _recv_exactly(relay, 1)
        note("from-implant", "method chosen", chosen,
             "the selected method, as in the RFC")
        chosen = _U8.unpack(chosen)[0]

        if chosen == _AUTH_USERPASS:
            user, secret = self.server.client_credentials or ("", "")
            raw_user = user.encode("utf-8")
            raw_secret = secret.encode("utf-8")
            # Both lengths first, then both strings.
            auth = (_PAIR.pack(len(raw_user), len(raw_secret))
                    + raw_user + raw_secret)
            relay.sendall(auth)
            note("to-implant", "credentials", auth,
                 "ulen | plen | uname | passwd. RFC 1929 interleaves them "
                 "as VER ULEN UNAME PLEN PASSWD.")
            reply = _recv_exactly(relay, 1)
            note("from-implant", "auth reply", reply,
                 "1 is success here. The RFC uses 0.")
            if _U8.unpack(reply)[0] != _DIALECT_OK:
                raise OSError("the client refused our credentials")
        elif chosen != _AUTH_NONE:
            raise OSError("the client chose method %d" % chosen)

        try:
            packed = socket.inet_pton(socket.AF_INET, host)
        except OSError:
            raw = host.encode("utf-8")
            request = (_TRIPLE.pack(_CMD_CONNECT, _ATYP_DOMAIN, len(raw))
                       + raw + _U16_LE.pack(port))
            shape = ("cmd | atyp=3 | addrlen | name | port. The port is "
                     "little-endian: %02x %02x is %d, not %d."
                     % (port & 0xff, port >> 8, port,
                        ((port & 0xff) << 8) | (port >> 8)))
        else:
            # `addrlen` is sent even for IPv4, where the client ignores it.
            request = (_TRIPLE.pack(_CMD_CONNECT, _ATYP_IPV4, 4)
                       + packed + _U16_LE.pack(port))
            shape = ("cmd | atyp=1 | addrlen=4 | addr | port. No version "
                     "byte and no RSV. addrlen is sent even for IPv4, where "
                     "the client reads four bytes regardless and ignores it. "
                     "The port is little-endian: %02x %02x is %d."
                     % (port & 0xff, port >> 8, port))
        relay.sendall(request)
        note("to-implant", "connect request", request, shape)

        raw_status = _recv_exactly(relay, 1)
        status = _U8.unpack(raw_status)[0]
        note("from-implant", "reply status", raw_status,
             "1 means the target connected; 0 means refused. Inverted "
             "against RFC 1928, where 0 is success.")
        if status != _DIALECT_OK:
            return None
        bound = _recv_exactly(relay, 2)
        atyp, addrlen = _PAIR.unpack(bound)
        if atyp != _ATYP_IPV4 or addrlen != 4:
            raise OSError("the client answered with an address we cannot read")
        rest = _recv_exactly(relay, 6)
        note("from-implant", "bound address", bound + rest,
             "atyp | addrlen | addr | port -- the address the implant's own "
             "socket got, port little-endian again.")
        bound_host = socket.inet_ntoa(rest[:4])
        bound_port = _U16_LE.unpack(rest[4:])[0]
        return bound_host, bound_port


class OperatorServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, fleet, broker, sessions, ledger,
                 credentials, client_credentials, wire, guard):
        self.fleet = fleet
        self.broker = broker
        self.sessions = sessions
        self.ledger = ledger
        self.credentials = credentials
        self.client_credentials = client_credentials
        self.wire = wire
        self.guard = guard
        super(OperatorServer, self).__init__(address, OperatorHandler)


def _serve_clients(listener, fleet, knob, ledger, stop):
    """Accept implants and keep each one's connection the way the knob says."""

    def hold(sock, peer):
        client = Client(sock, "%s:%d" % peer, ledger)
        fleet.add(client)
        try:
            while not stop.is_set():
                # Read the knob on every pass, not once: the dashboard can
                # turn it mid-run, and a run that shows both shapes in one
                # timeline is worth more than two runs that each show one.
                keepalive = knob.seconds
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
                # Waiting in one-second slices rather than for the whole
                # interval, so turning the knob down takes effect within a
                # second instead of after the old interval has run out.
                deadline = time.monotonic() + keepalive
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        client.keepalive()
                        break
                    if stop.wait(min(1.0, remaining)):
                        return
                    if knob.seconds != keepalive:
                        break
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


def _dashboard_class():
    # Imported late so the tunnel runs with the dashboard file absent, and
    # resolved both ways because this file is both a script and a package
    # module: run directly, `dashboard.py` sits beside it and is just
    # `dashboard`; imported as part of the package it is `server.dashboard`.
    try:
        from .dashboard import Dashboard
    except ImportError:
        from dashboard import Dashboard
    return Dashboard


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
    parser.add_argument("--dashboard", type=int, metavar="PORT",
                        help="serve the operator dashboard on this port, "
                             "loopback only. OFF by default and out of band: "
                             "it is a listening port the family does not "
                             "have, so it changes what a scan of this host "
                             "reports. Reach it over an SSH forward rather "
                             "than exposing it.")
    parser.add_argument("--dashboard-view", type=int, metavar="PORT",
                        help="serve a second, READ-ONLY dashboard on this "
                             "port -- for the blue team to watch the same "
                             "ground truth during a joint exercise without "
                             "being able to change the run. It can still "
                             "POST to /api/ingest, which is the point of "
                             "having it.")
    parser.add_argument("--allow-public", action="store_true",
                        help="permit relaying to addresses outside the "
                             "private ranges, loopback and link-local. OFF "
                             "by default: this is emulation for a lab you "
                             "own, and an operator port on loopback will "
                             "otherwise tunnel a mistyped CIDR to the public "
                             "internet through somebody's workstation.")
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
    knob = Knob(args.keepalive)
    fleet = Fleet(ledger)
    sessions = SessionBook()
    wire = WireLog()
    guard = LabGuard(args.allow_public)
    phases = Phases(ledger)
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
                              sessions, ledger, credentials,
                              client_credentials, wire, guard)

    ledger.record("server-start", command_port=args.port,
                  socks_port=args.socks, keepalive=int(args.keepalive),
                  targets="anywhere" if args.allow_public else "lab_only",
                  expected_shape=knob.shape.replace(" ", "_"))
    LOG.info("keep-alive %.0fs means: %s", args.keepalive, knob.shape)
    if args.allow_public:
        LOG.warning("--allow-public: this will relay to routable addresses")

    threads = [
        threading.Thread(target=_serve_clients,
                         args=(listener, fleet, knob, ledger, stop),
                         name="command", daemon=True),
        threading.Thread(target=operator.serve_forever, name="operator",
                         daemon=True),
    ]

    board = None
    if args.dashboard:
        board = _dashboard_class()(
            ("127.0.0.1", args.dashboard), fleet, sessions, knob, ledger,
            socks_port=args.socks, command_port=args.port,
            socks_credentials=credentials, wire=wire, guard=guard,
            phases=phases)
        threads.append(threading.Thread(target=board.serve_forever,
                                        name="dashboard", daemon=True))
        LOG.info("dashboard on http://127.0.0.1:%d -- out of band, and a "
                 "port this family does not have", args.dashboard)

    view = None
    if args.dashboard_view:
        if board is None:
            LOG.error("--dashboard-view needs --dashboard as well")
            return 2
        view = _dashboard_class()(
            ("127.0.0.1", args.dashboard_view), fleet, sessions, knob, ledger,
            socks_port=args.socks, command_port=args.port,
            socks_credentials=credentials, wire=wire, guard=guard,
            phases=phases, marks=board.marks, readonly=True)
        threads.append(threading.Thread(target=view.serve_forever,
                                        name="dashboard-view", daemon=True))
        LOG.info("read-only view on http://127.0.0.1:%d -- for the blue "
                 "team; it can ingest detections and change nothing else",
                 args.dashboard_view)

    for thread in threads:
        thread.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        LOG.info("stopping")
    finally:
        stop.set()
        if view is not None:
            view.shutdown()
        if board is not None:
            board.shutdown()
        operator.shutdown()
        listener.close()
        for client in fleet.snapshot():
            client.close()
        ledger.record("server-stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
