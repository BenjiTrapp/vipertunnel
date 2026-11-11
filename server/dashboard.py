#!/usr/bin/env python3
"""An operator view of the tunnel: what is connected, what it looks like, and
the one knob that changes the answer.

Off by default, and reached with `server.py --dashboard 8787`. Three things
to know before turning it on:

  * **It is out of band.** A listening HTTP port is a trait this family does
    not have. Scanning the measurement host with the dashboard up reports a
    property of this tool, not of the thing being emulated -- so it binds
    loopback only and should be reached over an SSH forward.
  * **It observes the ledger, it does not replace it.** Every number here is
    derived from events that were written to the ledger file as well. The
    file stays the artefact a finding cites; this is the thing that tells you
    where to look.
  * **It computes what a periodicity detection computes.** The cadence panel
    is mean, standard deviation and coefficient of variation over the gaps
    between command connections from one host. That is roughly the arithmetic
    a beaconing detection runs, which makes the dashboard a cheap preview of
    whether the run it is watching can be detected at all -- before anyone
    goes looking in the SIEM.

## What it can change

Each of these changes the run being measured, so each is in the ledger with
`by=dashboard`.

  * **The keep-alive knob**, live. The step from "one held connection" to "a
    reconnect every ~120 s" is the experiment, and turning it mid-run puts
    both shapes in one timeline with one client and one ledger.
  * **Hang up on a client.** Worth knowing what this does: the original does
    not reconnect from a close, so this ends that implant until something
    outside starts it again. That is the asymmetry the repository documents,
    and it is available here so it can be demonstrated rather than described.
  * **Drive a probe through the tunnel**, by speaking RFC 1928 to the
    server's own operator port exactly as `curl --socks5` would. Nothing
    about the wire changes; this only saves a second terminal.
  * **Leave a note in the ledger.** The marker an analyst wants when a
    detection fires: a dated line in the same file as the ground truth.
  * **Name a phase.** A measurement is two or three deliberate stretches, and
    the boundaries are the only thing that makes an alert's timestamp mean
    anything.

## What it takes in

`POST /api/ingest` accepts a detection from anywhere -- a SIEM webhook, an
EDR, a Zeek notice, a colleague -- and puts it on the same axis as the
truth, where the offset from the phase start is the time to detect. One
generic endpoint rather than an integration per tool, which is also the
extension point: new things need no code here, only something that can POST.

`GET /api/debrief` returns the whole run as one markdown file.
"""

import json
import os
import queue
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from .server import LOG as _SERVER_LOG
except ImportError:                                  # run as a script
    from server import LOG as _SERVER_LOG

LOG = _SERVER_LOG.getChild("dashboard")

_WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# Enough history for an hour of a 120-second cadence, and small enough that a
# browser left open overnight does not grow without bound.
_HISTORY = 2000

# A probe is an operator convenience, not a transfer tool. These bounds keep
# a stray request from turning the dashboard into one.
_PROBE_SEND_MAX = 1024
_PROBE_READ_MAX = 4096
_PROBE_TIMEOUT = 10.0

# A scan through the tunnel is the dialect's native operation, and an
# unbounded one behind a loopback port is a different tool entirely.
_SCAN_MAX = 2048
_SCAN_WORKERS = 8
# Shorter than a probe's deadline on purpose: a probe is one deliberate
# question and can afford to wait, while a sweep spends this on every dark
# address and a /28 of them at ten seconds each is a different experience.
_SCAN_TIMEOUT = 3.0

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
}

# Events that mark the arrival of a command connection. The gaps between
# these are the cadence.
_ARRIVAL = "client-connected"


class EventLog(object):
    """Recent ledger events, and whoever is currently watching them.

    The browser gets history on load and a live stream after that, so both
    come from one place. A subscriber that stops reading is dropped rather
    than allowed to back up into the thread holding a client's socket.
    """

    def __init__(self, limit=_HISTORY):
        self._limit = limit
        self._events = []
        self._listeners = []
        self._lock = threading.Lock()
        self._next_id = 1

    def record(self, stamp, event, fields):
        entry = {
            "id": self._next_id,
            "at": time.time(),
            "stamp": stamp,
            "event": event,
            "fields": {k: str(v) for k, v in sorted(fields.items())},
        }
        with self._lock:
            self._next_id += 1
            self._events.append(entry)
            if len(self._events) > self._limit:
                del self._events[:len(self._events) - self._limit]
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener.put_nowait(entry)
            except queue.Full:
                # A browser tab that went to sleep. Dropping its backlog is
                # correct: it reloads history on the next connect anyway.
                pass

    def history(self):
        with self._lock:
            return list(self._events)

    def listen(self):
        listener = queue.Queue(maxsize=256)
        with self._lock:
            self._listeners.append(listener)
        return listener

    def unlisten(self, listener):
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)


def cadence(arrivals, now=None):
    """Describe the gaps between command connections from one host.

    `arrivals` is a list of wall-clock times. The return value is what a
    periodicity detection would work with: the gaps, their mean, their
    standard deviation, and the coefficient of variation -- the last being
    the one that matters, because it is scale-free. A CV near zero is a
    machine on a timer; a human or a pooled connection is nowhere near it.

    Fewer than two gaps is not a cadence, and this says so rather than
    reporting a mean of one number as though it meant something.
    """
    gaps = [round(b - a, 3) for a, b in zip(arrivals, arrivals[1:])]
    out = {
        "connections": len(arrivals),
        "gaps": gaps,
        "mean": None,
        "stdev": None,
        "cv": None,
        "verdict": "not enough connections yet",
        "since_last": None,
    }
    if arrivals:
        out["since_last"] = round((now or time.time()) - arrivals[-1], 1)
    if len(gaps) < 2:
        if len(arrivals) == 1:
            out["verdict"] = ("one connection, still open -- this is the "
                              "held-connection shape")
        return out
    mean = sum(gaps) / len(gaps)
    variance = sum((gap - mean) ** 2 for gap in gaps) / len(gaps)
    stdev = variance ** 0.5
    out["mean"] = round(mean, 2)
    out["stdev"] = round(stdev, 2)
    out["cv"] = round(stdev / mean, 4) if mean else None
    if out["cv"] is not None and out["cv"] < 0.05:
        out["verdict"] = ("a timer, near-zero jitter -- about as easy as a "
                          "periodicity detection ever gets")
    elif out["cv"] is not None and out["cv"] < 0.25:
        out["verdict"] = "periodic with some jitter"
    else:
        out["verdict"] = "irregular -- no cadence to find here"
    return out


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def _ipv4_tcp(src, src_port, dst, dst_port, seq, ack, flags, payload):
    """One IPv4 + TCP packet, checksums and all."""
    tcp_length = 20 + len(payload)
    header = struct.pack(
        ">HHIIBBHHH", src_port, dst_port, seq, ack,
        5 << 4,                       # data offset 5 words, no options
        flags, 65535, 0, 0)
    pseudo = (socket.inet_aton(src) + socket.inet_aton(dst)
              + struct.pack(">BBH", 0, 6, tcp_length))
    tcp_sum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack(">H", tcp_sum) + header[18:]
    total = 20 + tcp_length
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, 6, 0)
    ip += socket.inet_aton(src) + socket.inet_aton(dst)
    ip = ip[:10] + struct.pack(">H", _checksum(ip)) + ip[12:]
    return ip + header + payload


def build_pcap(tap):
    """Rebuild one tapped session as a pcap a blue team can open.

    **The framing is reconstructed, not captured**, and the filename and the
    documentation both say so. What is real: the payload bytes, their order,
    their chunk boundaries, the time this server relayed each chunk, and the
    four-tuple -- the implant's own source address for the target connection
    comes back in the dialect's reply, so the conversation is labelled with
    the addresses of the leg this server never sees. What is invented: the
    IP and TCP headers, the sequence numbers, and a three-way handshake at
    the front so a reader sees a session rather than loose segments.

    Written as LINKTYPE_RAW, so there is no fake Ethernet layer pretending a
    capture point existed.
    """
    implant_host = tap["peer"].rsplit(":", 1)[0]
    bound = tap.get("bound") or (implant_host, 0)
    src, src_port = bound[0], int(bound[1])
    dst_host, _, dst_port = tap["target"].rpartition(":")
    dst_port = int(dst_port)

    records = tap["records"]
    start = records[0][0] if records else tap["opened"]
    out = [struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)]

    def frame(when, packet):
        out.append(struct.pack("<IIII", int(when), int((when % 1) * 1e6),
                               len(packet), len(packet)) + packet)

    # A synthetic handshake, so the file opens as a conversation.
    seq = {0: 1, 1: 1}
    frame(start, _ipv4_tcp(src, src_port, dst_host, dst_port,
                           0, 0, 0x02, b""))                     # SYN
    frame(start, _ipv4_tcp(dst_host, dst_port, src, src_port,
                           0, 1, 0x12, b""))                     # SYN-ACK
    frame(start, _ipv4_tcp(src, src_port, dst_host, dst_port,
                           1, 1, 0x10, b""))                     # ACK

    for when, direction, data in records:
        if not data:
            continue
        if direction == 0:
            packet = _ipv4_tcp(src, src_port, dst_host, dst_port,
                               seq[0], seq[1], 0x18, data)
        else:
            packet = _ipv4_tcp(dst_host, dst_port, src, src_port,
                               seq[1], seq[0], 0x18, data)
        frame(when, packet)
        seq[direction] += len(data)

    last = records[-1][0] if records else start
    frame(last, _ipv4_tcp(src, src_port, dst_host, dst_port,
                          seq[0], seq[1], 0x11, b""))            # FIN-ACK
    return b"".join(out)


class Marks(object):
    """Events from outside this program, on the same axis as the truth.

    One generic endpoint rather than an integration per tool: anything that
    can POST becomes a lane on the ground-truth timeline. A SIEM webhook
    posting its alerts is the case this was built for -- the offset between
    an alert and the phase it belongs to is the time-to-detect, measured
    instead of estimated -- but an EDR, a Zeek notice or a colleague's
    annotation all land the same way.

    This is also the extension point. New things need no code here, only
    somebody who can POST.
    """

    _SOURCES = 24          # distinct lanes worth drawing
    _LIMIT = 2000

    def __init__(self, ledger):
        self._ledger = ledger
        self._marks = []
        self._lock = threading.Lock()
        self._next_id = 1

    def add(self, source, label, at=None, severity="info"):
        source = str(source)[:60].strip() or "unknown"
        label = str(label)[:300].strip() or "(no label)"
        severity = str(severity)[:20].strip().lower() or "info"
        when = float(at) if at else time.time()
        with self._lock:
            if len({m["source"] for m in self._marks} | {source}) > self._SOURCES:
                raise ValueError("too many distinct sources (%d); post under "
                                 "a name already in use" % self._SOURCES)
            mark = {"id": self._next_id, "source": source, "label": label,
                    "at": when, "severity": severity}
            self._next_id += 1
            self._marks.append(mark)
            if len(self._marks) > self._LIMIT:
                del self._marks[:len(self._marks) - self._LIMIT]
        self._ledger.record("ingested", source=source.replace(" ", "_"),
                            severity=severity,
                            label=label.replace(" ", "_")[:120])
        return mark

    def snapshot(self):
        with self._lock:
            return list(self._marks)

    def sources(self):
        with self._lock:
            return sorted({mark["source"] for mark in self._marks})


class Scan(object):
    """A TCP connect sweep through the tunnel.

    This is the *native* operation of the dialect: it supports CONNECT and
    nothing else, so a connect scan is the one thing the protocol does
    without being bent. It is also what an operator does with a reverse
    SOCKS tunnel first -- find out what the host can reach -- and it is the
    bursty, high-volume shape the documentation says the relays produce and
    nothing here could produce on purpose until now.

    Every attempt goes through the server's own operator port, so it crosses
    the real translation and opens a real relay session on a real ephemeral
    port. A scan therefore shows up on the timeline the way a scan should:
    a spread of five-digit ports in a short window.

    Bounded on four axes, because an unbounded scanner behind a loopback
    port is a different and much worse tool:

      * every target passes the lab guard, one at a time,
      * at most `_SCAN_MAX` attempts per scan,
      * at most `_SCAN_WORKERS` at once,
      * a short per-attempt deadline.
    """

    def __init__(self, board):
        self._board = board
        self._lock = threading.Lock()
        self._state = {"running": False, "done": 0, "total": 0,
                       "findings": [], "tally": {}, "started": None,
                       "note": ""}

    def status(self):
        with self._lock:
            state = dict(self._state)
            state["tally"] = dict(state["tally"])
            state["findings"] = list(state["findings"])[-200:]
        return state

    def start(self, targets, ports):
        hosts = _expand_hosts(targets)
        wanted = _expand_ports(ports)
        if not hosts or not wanted:
            raise ValueError("give at least one host and one port")
        # Count before building: a cap that first allocates the thing it is
        # capping spends seconds and hundreds of megabytes on a request it
        # was always going to refuse.
        planned = len(hosts) * len(wanted)
        if planned > _SCAN_MAX:
            raise ValueError("%d attempts is over the %d cap; narrow the "
                             "range or the port list" % (planned, _SCAN_MAX))
        refused = [h for h in hosts if self._board.guard
                   and self._board.guard.refuse(h)]
        if refused:
            raise ValueError("%d of %d hosts are outside the lab (%s...); "
                             "this will not scan them"
                             % (len(refused), len(hosts), refused[0]))
        attempts = [(host, port) for host in hosts for port in wanted]
        with self._lock:
            if self._state["running"]:
                raise ValueError("a scan is already running")
            self._state = {"running": True, "done": 0,
                           "total": len(attempts), "findings": [],
                           "tally": {}, "started": time.time(),
                           "note": "%d hosts x %d ports" % (len(hosts),
                                                            len(wanted))}
        self._board.ledger.record("scan-start", by="dashboard",
                                  hosts=len(hosts), ports=len(wanted),
                                  attempts=len(attempts))
        threading.Thread(target=self._run, args=(attempts,),
                         name="scan", daemon=True).start()
        return self.status()

    def _run(self, attempts):
        queue_ = list(reversed(attempts))
        lock = threading.Lock()

        def worker():
            while True:
                with lock:
                    if not queue_:
                        return
                    host, port = queue_.pop()
                verdict = self._one(host, port)
                with self._lock:
                    self._state["done"] += 1
                    tally = self._state["tally"]
                    tally[verdict["state"]] = tally.get(verdict["state"], 0) + 1
                    # Only what an operator reads one by one is kept as a
                    # finding. A /28 sweep is mostly silence, and a list of
                    # four hundred identical "no answer" rows would bury the
                    # three that matter.
                    if verdict["state"] != "refused":
                        keep = self._state["findings"]
                        if verdict["state"] == "open" or len(keep) < 40:
                            keep.append(verdict)

        workers = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(_SCAN_WORKERS, len(attempts)))]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()

        with self._lock:
            self._state["running"] = False
            tally = dict(self._state["tally"])
        self._board.ledger.record("scan-end", by="dashboard",
                                  attempts=len(attempts),
                                  open_found=tally.get("open", 0),
                                  refused=tally.get("refused", 0),
                                  no_answer=tally.get("no-answer", 0))

    def _one(self, host, port):
        """One CONNECT through the tunnel, named the way a scanner names it."""
        where = {"host": host, "port": port}
        try:
            result = self._board.probe(host, port, "", timeout=_SCAN_TIMEOUT)
        except socket.timeout:
            return dict(where, state="no-answer",
                        detail="no answer in %gs -- filtered or dark"
                               % _SCAN_TIMEOUT)
        except OSError as exc:
            return dict(where, state="error", detail=str(exc)[:120])
        if result.get("ok"):
            self._board.ledger.record("scan-open", host=host, port=port)
            return dict(where, state="open", detail="the implant reached it")
        status = result.get("status")
        if status == 5:
            return dict(where, state="refused", detail="the target refused")
        if status == 4:
            return dict(where, state="no-answer",
                        detail=result.get("detail", "")[:120])
        if status == 1:
            # No implant connected, so nothing after this will work either.
            with self._lock:
                self._state["note"] = ("no implant is connected -- the rest "
                                       "of this scan will fail the same way")
            return dict(where, state="no-implant",
                        detail=result.get("detail", "")[:120])
        return dict(where, state="error",
                    detail=result.get("detail", "unexplained")[:120])


def _expand_hosts(text):
    """Accept `10.0.0.5`, `10.0.0.0/24` or a comma-separated mix of both.

    Hand-rolled rather than `ipaddress` only for the /24-and-smaller cases
    this needs; anything wider is over the attempt cap anyway.
    """
    hosts = []
    for piece in str(text).replace(" ", "").split(","):
        if not piece:
            continue
        if "/" not in piece:
            hosts.append(piece)
            continue
        network, _, bits = piece.partition("/")
        try:
            width = int(bits)
            packed = socket.inet_aton(network)
        except (ValueError, OSError):
            raise ValueError("%s is not an address or a CIDR" % piece)
        if not 20 <= width <= 32:
            raise ValueError("%s: only /20 to /32 are accepted" % piece)
        base = int.from_bytes(packed, "big") & (0xffffffff << (32 - width))
        for offset in range(1 << (32 - width)):
            hosts.append(socket.inet_ntoa((base + offset).to_bytes(4, "big")))
    return hosts


def _expand_ports(text):
    ports = []
    for piece in str(text).replace(" ", "").split(","):
        if not piece:
            continue
        low, _, high = piece.partition("-")
        try:
            start = int(low)
            end = int(high) if high else start
        except ValueError:
            raise ValueError("%s is not a port or a range" % piece)
        if not (0 < start <= end <= 65535):
            raise ValueError("%s is not a usable port range" % piece)
        ports.extend(range(start, end + 1))
    return ports


class Dashboard(ThreadingHTTPServer):
    """The HTTP side. Loopback only; see the module docstring for why."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, fleet, sessions, knob, ledger,
                 socks_port, command_port, socks_credentials=None,
                 wire=None, guard=None, phases=None, marks=None,
                 tap=None, readonly=False):
        self.fleet = fleet
        self.sessions = sessions
        self.knob = knob
        self.ledger = ledger
        self.socks_port = socks_port
        self.command_port = command_port
        self.socks_credentials = socks_credentials
        self.wire = wire
        self.guard = guard
        self.phases = phases
        self.tap = tap
        # Two dashboards on one run share the marks, so the blue team's
        # read-only view shows the same ingested detections the operator's
        # does rather than an empty lane.
        self.marks = marks if marks is not None else Marks(ledger)
        self.readonly = readonly
        self.started = time.time()
        self.events = EventLog()
        self.relay_ports = []
        self.scan = Scan(self)
        # Arrival times per implant host, for the cadence. Keyed by host and
        # not by peer, because the source port is different on every
        # reconnect -- which is the thing being counted.
        self._arrivals = {}
        self._arrival_lock = threading.Lock()
        # Running totals since this dashboard started. The event ring buffer
        # forgets, and a counter on the page that silently stops counting
        # would be worse than no counter.
        self._totals = {"connections": 0, "keepalives": 0, "sessions": 0,
                        "deaths": 0, "notes": 0}
        ledger.subscribe(self._observe)
        super(Dashboard, self).__init__(address, _Handler)

    # -- watching -----------------------------------------------------------

    _COUNTS = {
        _ARRIVAL: "connections",
        "keepalive": "keepalives",
        "session-open": "sessions",
        "client-gone": "deaths",
        "operator-note": "notes",
    }

    def _observe(self, stamp, event, fields):
        if event == _ARRIVAL:
            peer = str(fields.get("peer", ""))
            host = peer.rsplit(":", 1)[0] or "unknown"
            with self._arrival_lock:
                times = self._arrivals.setdefault(host, [])
                times.append(time.time())
                if len(times) > _HISTORY:
                    del times[:len(times) - _HISTORY]
        counted = self._COUNTS.get(event)
        if counted:
            with self._arrival_lock:
                self._totals[counted] += 1
        if event == "relay-announced":
            # The spread of five-digit ports is one of the traits a scan of
            # the real infrastructure reports, so it is worth keeping.
            with self._arrival_lock:
                self.relay_ports.append(int(fields.get("port", 0)))
                del self.relay_ports[:-50]
        self.events.record(stamp, event, fields)

    def totals(self):
        with self._arrival_lock:
            return dict(self._totals)

    def cadences(self):
        with self._arrival_lock:
            hosts = {host: list(times)
                     for host, times in self._arrivals.items()}
        now = time.time()
        return [dict(cadence(times, now), host=host)
                for host, times in sorted(hosts.items())]

    def state(self):
        seconds = self.knob.seconds
        return {
            "server": {
                "command_port": self.command_port,
                "socks_port": self.socks_port,
                "socks_auth": self.socks_credentials is not None,
                "lab_only": bool(self.guard and not self.guard.allow_public),
                "readonly": self.readonly,
                "tap": self.tap is not None,
                "started": self.started,
                "uptime_seconds": int(time.time() - self.started),
                "now": time.time(),
            },
            "knob": {
                "keepalive": seconds,
                "client_timeout": 120,
                "shape": self.knob.shape,
                "held": 0 < seconds < 120,
            },
            "clients": [client.describe()
                        for client in self.fleet.snapshot()],
            "sessions": self.sessions.snapshot(),
            "cadence": self.cadences(),
            "totals": self.totals(),
            "phases": self.phases.snapshot() if self.phases else [],
            "marks": self.marks.snapshot()[-400:],
            "volume": self.sessions.volume(int(time.time()) - 900),
        }

    # -- doing --------------------------------------------------------------

    def set_keepalive(self, seconds):
        previous = self.knob.set(seconds)
        self.ledger.record("knob-turned", keepalive=self.knob.seconds,
                           was=previous,
                           expected_shape=self.knob.shape.replace(" ", "_"),
                           by="dashboard")
        return self.knob.seconds

    def hang_up(self, client_id):
        client = self.fleet.find(int(client_id))
        if client is None:
            return None
        self.ledger.record("hung-up-on-client", peer=client.peer,
                           by="dashboard",
                           note="the_original_does_not_reconnect_from_a_close")
        client.close()
        return client.peer

    def note(self, text):
        text = str(text)[:500].replace("\n", " ")
        self.ledger.record("operator-note", by="dashboard",
                           text=text.replace(" ", "_") or "empty")
        return text

    def wire_captures(self):
        return self.wire.snapshot() if self.wire else []

    def taps(self):
        """The tapped sessions, rendered for reading rather than for bytes."""
        if self.tap is None:
            return []
        out = []
        for entry in self.tap.snapshot():
            rows = []
            for when, direction, data in entry["records"]:
                # Truncated for reading, and the row says so: a hex dump
                # that quietly stops is a hex dump somebody will trust.
                rows.append({
                    "at": when,
                    "direction": "to-target" if direction == 0 else "from-target",
                    "bytes": len(data),
                    "shown": min(len(data), 256),
                    "hex": " ".join("%02x" % byte for byte in data[:256]),
                    "text": "".join(chr(b) if 32 <= b < 127 else "."
                                    for b in data[:512]),
                })
            out.append({
                "id": entry["id"], "peer": entry["peer"],
                "target": entry["target"], "opened": entry["opened"],
                "summary": entry["summary"],
                "out_bytes": entry["out_bytes"],
                "in_bytes": entry["in_bytes"],
                "dropped": entry["dropped"],
                "rows": rows[:80],
            })
        return out

    def pcap(self, session_id):
        if self.tap is None:
            return None
        for entry in self.tap.snapshot():
            if entry["id"] == int(session_id):
                return build_pcap(entry)
        return None

    def fingerprint(self, force=False):
        """Probe our own command port the way a researcher's scanner did.

        The `00 00` a bare probe gets back is how this family's
        infrastructure was enumerated across hosting providers. Reproducing
        it from the inside answers a question the documentation cannot: is
        *this* host fingerprintable the way the real ones were?

        The answer turns out to depend on the measurement knob, which is
        worth knowing before a run rather than after. The banner is the
        keep-alive leaking, so a server that never sends one never leaks it.

        Two warnings, both honest rather than defensive:

          * A bare probe is indistinguishable from an implant, because the
            protocol has no identifier. So this connection briefly joins the
            fleet, and `Fleet.pick` could hand it an operator's session --
            which is exactly the hijack property the dialect has and the
            documentation describes. It is refused while a real implant is
            connected unless `force` says otherwise.
          * It takes up to one keep-alive interval to get an answer.
        """
        connected = len(self.fleet.snapshot())
        if connected and not force:
            return {
                "ok": False,
                "detail": ("%d implant(s) are connected. A bare probe is "
                           "indistinguishable from an implant, so it would "
                           "join the fleet and could be handed a session -- "
                           "the hijack the dialect allows. Force it only if "
                           "no session is wanted during the probe."
                           % connected),
                "needs_force": True,
            }

        interval = self.knob.seconds
        budget = min(_PROBE_TIMEOUT, interval + 2.0) if interval > 0 else 3.0
        self.ledger.record("self-probe", by="dashboard",
                           port=self.command_port, waited=int(budget))
        started = time.monotonic()
        banner = b""
        try:
            sock = socket.create_connection(("127.0.0.1", self.command_port),
                                            timeout=budget)
        except OSError as exc:
            return {"ok": False, "detail": "could not reach our own command "
                                           "port: %s" % exc}
        try:
            sock.settimeout(budget)
            try:
                banner = sock.recv(2)
            except (socket.timeout, OSError):
                banner = b""
        finally:
            try:
                sock.close()
            except OSError:
                pass

        waited = round(time.monotonic() - started, 2)
        got = " ".join("%02x" % byte for byte in banner)
        if banner == b"\x00\x00":
            verdict = ("fingerprintable. A bare probe gets 00 00, which is "
                       "the trait that let researchers enumerate this "
                       "family across hosting providers.")
        elif banner:
            verdict = ("something came back, but not the keep-alive: %s" % got)
        elif interval <= 0:
            verdict = ("silent, and the knob is why. With no keep-alive "
                       "there is nothing to leak, so this host does NOT "
                       "carry the family's banner -- the same setting that "
                       "removes the cadence also removes the fingerprint. "
                       "Worth recording: a run in this position is testing "
                       "neither a periodicity detection nor a banner hunt.")
        else:
            verdict = ("silent after %ss, which is longer than the %gs "
                       "keep-alive interval -- unexpected."
                       % (waited, interval))

        with self._arrival_lock:
            ports = sorted(set(p for p in self.relay_ports if p))
        return {
            "ok": True,
            "banner": got or None,
            "waited": waited,
            "keepalive": interval,
            "verdict": verdict,
            "relay_ports": ports[-12:],
            "traits": self._traits(bool(banner == b"\x00\x00"), ports),
        }

    # Straight from the infrastructure table in docs/provenance.md, so the
    # emulation can be checked against what the real hosts reported rather
    # than against an impression of them.
    def _traits(self, banner, ports):
        return [
            {"trait": "00 00 on a bare probe to the command port",
             "real": "yes -- the trait that enumerated the fleet",
             "here": "yes" if banner else "no, the keep-alive is off"},
            {"trait": "command port 443",
             "real": "yes",
             "here": "yes" if self.command_port == 443
                     else "no, %d" % self.command_port},
            {"trait": "a spread of five-digit relay ports",
             "real": "yes",
             "here": ("yes -- %d seen, e.g. %s" % (len(ports), ports[-3:]))
                     if ports else "none announced yet"},
            {"trait": "plaintext SOCKS over 443, not wrapped in TLS",
             "real": "yes", "here": "yes"},
            {"trait": "port 22 open alongside, Ubuntu 22.04 OpenSSH banner",
             "real": "~75% of identified hosts",
             "here": "your host's business, not this tool's"},
            {"trait": "Pyramid C2 on 8000 answering 401 Basic realm=\"Proxy\"",
             "real": "often", "here": "no -- out of scope"},
            {"trait": "a listening HTTP port for an operator view",
             "real": "no",
             "here": "YES, this dashboard -- out of band, and the one trait "
                     "that would give the emulation away"},
        ]

    def probe(self, host, port, payload="", timeout=None):
        """Open one session through the tunnel, the way `curl --socks5` does.

        Deliberately an RFC 1928 conversation with this server's own operator
        port rather than a shortcut into the relay: the probe then exercises
        the same translation an operator's tool would, and a probe that works
        proves the whole path rather than half of it.
        """
        deadline = timeout or _PROBE_TIMEOUT
        raw = payload.encode("utf-8", "replace")[:_PROBE_SEND_MAX]
        if self.guard is not None:
            refusal = self.guard.refuse(host)
            if refusal:
                return {"ok": False, "status": None, "detail": refusal}
        started = time.monotonic()
        sock = socket.create_connection(("127.0.0.1", self.socks_port),
                                        timeout=deadline)
        try:
            sock.settimeout(deadline)
            if self.socks_credentials:
                user, secret = self.socks_credentials
                sock.sendall(b"\x05\x01\x02")
                if _read(sock, 2) != b"\x05\x02":
                    raise OSError("the operator port would not take a "
                                  "username and password")
                sock.sendall(b"\x01"
                             + bytes([len(user)]) + user.encode("utf-8")
                             + bytes([len(secret)]) + secret.encode("utf-8"))
                if _read(sock, 2)[1:] != b"\x00":
                    raise OSError("the operator port refused the credentials")
            else:
                sock.sendall(b"\x05\x01\x00")
                if _read(sock, 2) != b"\x05\x00":
                    raise OSError("the operator port would not take no-auth")

            try:
                packed = socket.inet_pton(socket.AF_INET, host)
            except OSError:
                name = host.encode("idna") if host else b""
                sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name
                             + struct.pack(">H", port))
            else:
                sock.sendall(b"\x05\x01\x00\x01" + packed
                             + struct.pack(">H", port))

            reply = _read(sock, 4)
            status = reply[1]
            if status != 0:
                return {
                    "ok": False,
                    "status": status,
                    "detail": _RFC_STATUS.get(status, "reply code %d" % status),
                    "seconds": round(time.monotonic() - started, 3),
                }
            # Consume the bound address so the next byte is the stream's.
            atyp = reply[3]
            if atyp == 1:
                _read(sock, 6)
            elif atyp == 3:
                _read(sock, _read(sock, 1)[0] + 2)
            else:
                _read(sock, 18)

            if raw:
                sock.sendall(raw)
            got = b""
            try:
                while len(got) < _PROBE_READ_MAX:
                    chunk = sock.recv(_PROBE_READ_MAX - len(got))
                    if not chunk:
                        break
                    got += chunk
                    if not raw:
                        break
            except (socket.timeout, OSError):
                pass
            return {
                "ok": True,
                "status": 0,
                "detail": "the tunnel carried it",
                "sent": len(raw),
                "received": len(got),
                "preview": got[:512].decode("utf-8", "replace"),
                "seconds": round(time.monotonic() - started, 3),
            }
        finally:
            try:
                sock.close()
            except OSError:
                pass


    def debrief(self):
        """A one-file account of the run, for the debrief both teams attend.

        Assembled only from what the ledger already holds, so nothing here
        is a second version of the truth. The number it exists to produce is
        the offset between each ingested alert and the phase it landed in --
        the time-to-detect, measured rather than estimated, and an explicit
        "nothing fired" for a phase where nothing did.
        """
        now = time.time()
        phases = self.phases.snapshot() if self.phases else []
        marks = self.marks.snapshot()
        lines = []
        add = lines.append

        add("# vipertunnel -- run debrief")
        add("")
        add("Generated %s. Every figure below is derived from the ledger "
            "file, which stays the artefact to cite."
            % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))
        add("")
        add("| | |")
        add("|---|---|")
        add("| command port | %d |" % self.command_port)
        add("| operator port | 127.0.0.1:%d |" % self.socks_port)
        add("| relaying | %s |" % ("the private ranges, loopback and "
                                   "link-local only"
                                   if self.guard and not self.guard.allow_public
                                   else "anywhere (--allow-public)"))
        add("| server up | %s |" % _duration(now - self.started))
        totals = self.totals()
        add("| command connections | %d |" % totals["connections"])
        add("| keep-alives sent | %d |" % totals["keepalives"])
        add("| relay sessions | %d |" % totals["sessions"])
        add("")

        add("## Cadence, per implant host")
        add("")
        add("The arithmetic a beaconing detection runs. A coefficient of "
            "variation near zero is a machine on a timer.")
        add("")
        add("| host | connections | mean gap | stdev | CV | verdict |")
        add("|---|---|---|---|---|---|")
        for entry in self.cadences():
            add("| %s | %d | %s | %s | %s | %s |" % (
                entry["host"], entry["connections"],
                _or_dash(entry["mean"], " s"), _or_dash(entry["stdev"], " s"),
                _or_dash(entry["cv"]), entry["verdict"]))
        if not self.cadences():
            add("| — | 0 | | | | nothing connected |")
        add("")

        add("## Phases, and what was detected in each")
        add("")
        if not phases:
            add("No phases were declared. An alert's timestamp then has "
                "nothing to be measured against, which is the one thing "
                "worth fixing before the next run.")
        for phase in phases:
            ended = phase["ended"] or now
            add("### %s" % phase["name"])
            add("")
            add("%s → %s (%s), keep-alive %s" % (
                _stamp(phase["started"]),
                _stamp(phase["ended"]) if phase["ended"] else "still running",
                _duration(ended - phase["started"]),
                "%gs" % phase["keepalive"] if phase["keepalive"] is not None
                else "unknown"))
            add("")
            # A running phase has no end yet, so its window stays open. That
            # is not pedantry: a detection platform whose clock runs a few
            # seconds ahead would otherwise have its alerts silently dropped
            # out of the phase they belong to.
            horizon = phase["ended"] if phase["ended"] else float("inf")
            during = [m for m in marks
                      if phase["started"] <= m["at"] <= horizon]

            # The knob recorded on the phase is the value at its start, and
            # the whole point of the knob is that it can be turned mid-run.
            # A debrief that reported only the opening value would describe
            # a phase that may never have existed.
            turns = [e for e in self.events.history()
                     if e["event"] == "knob-turned"
                     and phase["started"] <= e["at"] <= min(
                         horizon, now)]
            settings = [phase["keepalive"]]
            if turns:
                add("Keep-alive was turned inside this phase: %s."
                    % ", ".join("%ss after %s" % (e["fields"].get("keepalive"),
                                                  _duration(e["at"] - phase["started"]))
                                for e in turns))
                add("")
                settings += [_as_float(e["fields"].get("keepalive"))
                             for e in turns]

            if not during:
                add("**Nothing fired.** %s" % _silence(settings))
                add("")
                continue
            add("| source | after phase start | severity | label |")
            add("|---|---|---|---|")
            for mark in during:
                add("| %s | %s | %s | %s |" % (
                    mark["source"], _duration(mark["at"] - phase["started"]),
                    mark["severity"], mark["label"]))
            first = min(m["at"] for m in during)
            add("")
            add("**Time to first detection: %s.**"
                % _duration(first - phase["started"]))
            add("")

        outside = [m for m in marks
                   if not any(p["started"] <= m["at"] <=
                              (p["ended"] if p["ended"] else float("inf"))
                              for p in phases)]
        if outside:
            add("## Ingested outside any phase")
            add("")
            add("| source | at | severity | label |")
            add("|---|---|---|---|")
            for mark in outside:
                add("| %s | %s | %s | %s |" % (
                    mark["source"], _stamp(mark["at"]), mark["severity"],
                    mark["label"]))
            add("")

        add("## What a proxy log would have held")
        add("")
        add("One line per command connection, and nothing else from this "
            "run is visible from there.")
        add("")
        add("```")
        opened = {}
        count = 0
        for entry in self.events.history():
            peer = entry["fields"].get("peer", "")
            if entry["event"] == "client-connected":
                opened[peer] = entry["at"]
            elif entry["event"] in ("client-gone", "hung-up-on-client"):
                start = opened.pop(peer, None)
                if start is None:
                    continue
                count += 1
                add("%s  %s  CONNECT <this server>:%d  200  %ds  ?B" % (
                    _stamp(start), peer.rsplit(":", 1)[0], self.command_port,
                    int(entry["at"] - start)))
        for peer, start in opened.items():
            count += 1
            add("%s  %s  CONNECT <this server>:%d  200  %ds  ?B  (open)" % (
                _stamp(start), peer.rsplit(":", 1)[0], self.command_port,
                int(now - start)))
        if not count:
            add("# nothing -- no command connection was made")
        add("```")
        add("")

        captures = self.wire_captures()
        if captures:
            add("## The wire, as it actually went out")
            add("")
            add("The last handshake, byte for byte, with the deviation from "
                "RFC 1928 at each step. Handshakes only: the relayed payload "
                "is the traffic of the network under test and is never kept.")
            add("")
            capture = captures[0]
            add("`%s` → `%s` — %s"
                % (capture["peer"], capture["target"], capture["outcome"]))
            add("")
            add("| | bytes | means |")
            add("|---|---|---|")
            for step in capture["steps"]:
                arrow = "→" if step["direction"] == "to-implant" else "←"
                add("| %s %s | `%s` | %s |"
                    % (arrow, step["label"], step["hex"], step["note"]))
            add("")

        add("## Authorisation")
        add("")
        add("Adversary emulation for a detection measurement in a lab the "
            "operator owns. Relaying outside the private ranges is refused "
            "unless --allow-public was passed, and this run %s."
            % ("had it passed" if self.guard and self.guard.allow_public
               else "did not"))
        add("")
        return "\n".join(lines)


def _as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _silence(settings):
    """Say what nothing-firing means at the keep-alive settings in force.

    "Nothing fired" is two completely different findings depending on the
    knob, and a debrief that printed one sentence for both would be the most
    misleading thing in the file.
    """
    values = [s for s in settings if s is not None]
    if not values:
        return ("That is a result, not a gap -- but the keep-alive during "
                "this phase was not recorded, so which of the two findings "
                "it is cannot be said. Declare phases around knob changes.")
    cadence_shape = any(v <= 0 or v >= 120 for v in values)
    held_shape = any(0 < v < 120 for v in values)
    if cadence_shape and not held_shape:
        return ("That is a finding about the **detection**, not about the "
                "tunnel: at this setting the client reconnects on a timer "
                "with near-zero jitter, which is about as easy as a "
                "periodicity detection ever gets. If it did not fire here, "
                "it will not fire on the real thing.")
    if held_shape and not cadence_shape:
        return ("That is a finding about the **tunnel**, not about the "
                "detection: at this setting there is one held connection "
                "and no cadence for a periodicity rule to bin. A proxy log "
                "holds one CONNECT and a byte count. Nothing was there to "
                "find, and that is the result worth reporting.")
    return ("The keep-alive moved between the two shapes inside this phase, "
            "so a silence here cannot be attributed to either. Put a phase "
            "boundary at the knob change and run it again.")


def _stamp(when):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when))


def _duration(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm %ds" % (seconds // 60, seconds % 60)
    return "%dh %dm" % (seconds // 3600, (seconds % 3600) // 60)


def _or_dash(value, unit=""):
    return "—" if value is None else "%s%s" % (value, unit)


_RFC_STATUS = {
    1: "general failure -- usually no implant is connected",
    2: "not allowed",
    3: "network unreachable",
    4: "host unreachable -- the implant could not reach the target",
    5: "connection refused by the target",
    7: "command not supported",
}


def _read(sock, count):
    chunks = []
    have = 0
    while have < count:
        chunk = sock.recv(count - have)
        if not chunk:
            raise OSError("the operator port closed after %d of %d bytes"
                          % (have, count))
        chunks.append(chunk)
        have += len(chunk)
    return b"".join(chunks)


class _Handler(BaseHTTPRequestHandler):
    server_version = "dashboard"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        LOG.debug(fmt, *args)

    # -- plumbing -----------------------------------------------------------

    def _send(self, status, body, content_type="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # No external fetches anywhere in this page, and saying so is cheap:
        # a dashboard for a lab tool should not be able to phone anywhere.
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; connect-src 'self'")
        if self.path.endswith(".woff2"):
            self.send_header("Cache-Control", "public, max-age=604800")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, status=200):
        self._send(status, json.dumps(payload), "application/json")

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 64 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    # -- routes -------------------------------------------------------------

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route == "/api/state":
            payload = self.server.state()
            # Enough for the widest zoom the chart offers; the browser keeps
            # the rest of what it has already streamed.
            payload["events"] = self.server.events.history()[-800:]
            return self._json(payload)
        if route == "/api/events":
            return self._stream()
        if route == "/api/wire":
            return self._json({"captures": self.server.wire_captures()})
        if route == "/api/scan":
            return self._json(self.server.scan.status())
        if route == "/api/tap":
            return self._json({"sessions": self.server.taps()})
        if route == "/api/pcap":
            query = self.path.partition("?")[2]
            wanted = dict(piece.split("=", 1) for piece in query.split("&")
                          if "=" in piece).get("session", "0")
            try:
                body = self.server.pcap(wanted)
            except (TypeError, ValueError):
                body = None
            if not body:
                return self._json({"error": "no tapped session with that id; "
                                            "--tap must be on"}, 404)
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Length", str(len(body)))
            # The name carries the caveat, because a file called
            # "session-3.pcap" would be treated as sensor evidence by the
            # next person to open it.
            self.send_header(
                "Content-Disposition",
                'attachment; filename="vipertunnel-session%s-'
                'RECONSTRUCTED.pcap"' % wanted)
            self.end_headers()
            return self.wfile.write(body)
        if route == "/api/debrief":
            body = self.server.debrief().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition",
                             'attachment; filename="vipertunnel-debrief-%s.md"'
                             % time.strftime("%Y%m%d-%H%M%S"))
            self.end_headers()
            return self.wfile.write(body)
        return self._static(route)

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        body = self._body()
        if self.server.readonly and route != "/api/ingest":
            # The blue team's view may still post detections -- that is the
            # whole point of it -- but it must not be able to turn the knob,
            # hang up on an implant or drive traffic. A joint exercise with
            # one operator and several watchers needs exactly this line.
            return self._json({"error": "this view is read-only; only "
                                        "/api/ingest is open on it"}, 403)
        try:
            if route == "/api/keepalive":
                return self._json(
                    {"keepalive": self.server.set_keepalive(
                        body.get("seconds", 0)),
                     "shape": self.server.knob.shape})
            if route == "/api/note":
                return self._json({"note": self.server.note(
                    body.get("text", ""))})
            if route == "/api/hangup":
                peer = self.server.hang_up(body.get("client", 0))
                if peer is None:
                    return self._json({"error": "no such client"}, 404)
                return self._json({"peer": peer})
            if route == "/api/probe":
                return self._json(self.server.probe(
                    str(body.get("host", "")),
                    int(body.get("port", 0)),
                    str(body.get("payload", ""))))
            if route == "/api/fingerprint":
                return self._json(self.server.fingerprint(
                    bool(body.get("force"))))
            if route == "/api/ingest":
                mark = self.server.marks.add(
                    body.get("source", "unknown"),
                    body.get("label", ""),
                    body.get("at"),
                    body.get("severity", "info"))
                return self._json({"mark": mark})
            if route == "/api/phase":
                if body.get("stop"):
                    ended = self.server.phases.stop()
                    return self._json({"ended": ended})
                return self._json({"started": self.server.phases.start(
                    body.get("name", ""), self.server.knob)})
            if route == "/api/scan":
                return self._json(self.server.scan.start(
                    body.get("targets", ""), body.get("ports", "")))
        except (ValueError, TypeError) as exc:
            return self._json({"error": str(exc)}, 400)
        except OSError as exc:
            return self._json({"ok": False, "detail": str(exc)}, 200)
        return self._json({"error": "no such route"}, 404)

    def _stream(self):
        """Server-sent events: one line per ledger event, as it happens.

        SSE rather than a WebSocket because the standard library has an HTTP
        server and no WebSocket one, and this needs no upstream channel --
        the browser's writes are ordinary POSTs.
        """
        listener = self.server.events.listen()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            while True:
                try:
                    entry = listener.get(timeout=15.0)
                except queue.Empty:
                    # A comment frame, so a dead tab is noticed here rather
                    # than held open until the process stops.
                    self.wfile.write(b": still here\n\n")
                    self.wfile.flush()
                    continue
                self.wfile.write(
                    ("data: %s\n\n" % json.dumps(entry)).encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.server.events.unlisten(listener)
        self.close_connection = True

    def _static(self, route):
        name = "index.html" if route in ("/", "") else route.lstrip("/")
        path = os.path.normpath(os.path.join(_WEB, name))
        if not path.startswith(_WEB) or not os.path.isfile(path):
            return self._send(404, "not found", "text/plain; charset=utf-8")
        extension = os.path.splitext(path)[1]
        with open(path, "rb") as handle:
            body = handle.read()
        self._send(200, body, _MIME.get(extension, "application/octet-stream"))
