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


class Dashboard(ThreadingHTTPServer):
    """The HTTP side. Loopback only; see the module docstring for why."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, fleet, sessions, knob, ledger,
                 socks_port, command_port, socks_credentials=None,
                 wire=None, guard=None):
        self.fleet = fleet
        self.sessions = sessions
        self.knob = knob
        self.ledger = ledger
        self.socks_port = socks_port
        self.command_port = command_port
        self.socks_credentials = socks_credentials
        self.wire = wire
        self.guard = guard
        self.started = time.time()
        self.events = EventLog()
        self.relay_ports = []
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

    def probe(self, host, port, payload=""):
        """Open one session through the tunnel, the way `curl --socks5` does.

        Deliberately an RFC 1928 conversation with this server's own operator
        port rather than a shortcut into the relay: the probe then exercises
        the same translation an operator's tool would, and a probe that works
        proves the whole path rather than half of it.
        """
        raw = payload.encode("utf-8", "replace")[:_PROBE_SEND_MAX]
        if self.guard is not None:
            refusal = self.guard.refuse(host)
            if refusal:
                return {"ok": False, "status": None, "detail": refusal}
        started = time.monotonic()
        sock = socket.create_connection(("127.0.0.1", self.socks_port),
                                        timeout=_PROBE_TIMEOUT)
        try:
            sock.settimeout(_PROBE_TIMEOUT)
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
        return self._static(route)

    def do_POST(self):
        route = self.path.split("?", 1)[0]
        body = self._body()
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
