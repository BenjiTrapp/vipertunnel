"""The two halves, talking to each other over the real dialect.

Everything else in this repository is derived from the published client, and
the derivation is only worth something if the halves actually agree. So this
assembles both sides in one process and pushes bytes through: command
channel, announced relay port, dial-back, the greeting with no version byte,
the request with its little-endian port, the inverted reply, and the bridge.

A failure here means the dialect is wrong somewhere, which is the one bug
class that would quietly invalidate a measurement rather than break it.
"""

import socket
import struct
import threading
import unittest

from client.client import Tunnel
from client.client import Ledger as ClientLedger
from server.server import (Fleet, Knob, Ledger, OperatorServer, RelayBroker,
                           SessionBook, _serve_clients)


class _Echo(object):
    """A target the tunnelled connection can shout at."""

    def __init__(self):
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self.address = self._listener.getsockname()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._listener.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._echo, args=(conn,),
                             daemon=True).start()

    def _echo(self, conn):
        with conn:
            while True:
                try:
                    chunk = conn.recv(4096)
                except OSError:
                    return
                if not chunk:
                    return
                conn.sendall(chunk.upper())


class _Tunnel(object):
    """Both halves, wired together on loopback."""

    def __init__(self, keepalive=0.5):
        self.keepalive = keepalive

    def __enter__(self):
        self.ledger = Ledger(None)
        self.fleet = Fleet(self.ledger)
        self.sessions = SessionBook()
        self.stop = threading.Event()

        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        command_port = self.listener.getsockname()[1]

        self.operator = OperatorServer(
            ("127.0.0.1", 0), self.fleet, RelayBroker("127.0.0.1",
                                                      self.ledger),
            self.sessions, self.ledger, None, None)
        self.socks_port = self.operator.server_address[1]

        self.threads = [
            threading.Thread(target=_serve_clients,
                             args=(self.listener, self.fleet,
                                   Knob(self.keepalive), self.ledger,
                                   self.stop), daemon=True),
            threading.Thread(target=self.operator.serve_forever, daemon=True),
        ]
        self.tunnel = Tunnel(("127.0.0.1", command_port), None, "u", "p",
                             5.0, ClientLedger(None))
        self.threads.append(threading.Thread(target=self.tunnel.run,
                                             daemon=True))
        for thread in self.threads:
            thread.start()

        # The operator port refuses with "no client connected" until the
        # implant's command connection has arrived, so wait for it rather
        # than racing it.
        for _ in range(100):
            if self.fleet.snapshot():
                break
            threading.Event().wait(0.05)
        else:
            raise AssertionError("the implant never connected")
        return self

    def __exit__(self, *exc):
        self.tunnel.stop()
        self.stop.set()
        self.operator.shutdown()
        self.operator.server_close()
        self.listener.close()
        for client in self.fleet.snapshot():
            client.close()

    def connect(self, target):
        """Ask the operator port for `target` and return the open socket."""
        sock = socket.create_connection(("127.0.0.1", self.socks_port),
                                        timeout=10)
        sock.settimeout(10)
        sock.sendall(b"\x05\x01\x00")
        assert sock.recv(2) == b"\x05\x00"
        sock.sendall(b"\x05\x01\x00\x01"
                     + socket.inet_aton(target[0])
                     + struct.pack(">H", target[1]))
        reply = sock.recv(10)
        return sock, reply


class WireTest(unittest.TestCase):
    def test_bytes_go_through_and_come_back(self):
        with _Echo() as echo, _Tunnel() as tunnel:
            sock, reply = tunnel.connect(echo.address)
            self.addCleanup(sock.close)
            self.assertEqual(reply[0], 5, "not a SOCKS5 reply")
            self.assertEqual(reply[1], 0, "the operator port refused")
            sock.sendall(b"knock knock")
            self.assertEqual(sock.recv(64), b"KNOCK KNOCK")

    def test_a_refused_target_reaches_the_operator_as_a_refusal(self):
        # A port nothing is listening on: the client cannot connect, answers
        # the dialect's 0, and the server has to turn that into the RFC's 5.
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        address = closed.getsockname()
        closed.close()
        with _Tunnel() as tunnel:
            sock, reply = tunnel.connect(address)
            self.addCleanup(sock.close)
            self.assertEqual(reply[1], 5, "expected a refusal")

    def test_a_session_is_booked_while_it_is_open(self):
        with _Echo() as echo, _Tunnel() as tunnel:
            sock, _ = tunnel.connect(echo.address)
            self.addCleanup(sock.close)
            sock.sendall(b"hold")
            sock.recv(64)
            open_now = tunnel.sessions.snapshot()
            self.assertEqual(len(open_now), 1)
            self.assertEqual(open_now[0]["target"],
                             "%s:%d" % echo.address)
            self.assertGreater(open_now[0]["relay_port"], 0)

    def test_the_keepalive_is_answered_rather_than_ignored(self):
        # The two bytes `00 00` in both directions. If the client answered a
        # keep-alive with anything else the server would drop it, so a client
        # that is still in the fleet after several intervals is the check.
        with _Tunnel(keepalive=0.2) as tunnel:
            client = tunnel.fleet.snapshot()[0]
            for _ in range(60):
                if client.keepalives >= 3:
                    break
                threading.Event().wait(0.05)
            self.assertGreaterEqual(client.keepalives, 3)
            self.assertIn(client, tunnel.fleet.snapshot())


if __name__ == "__main__":
    unittest.main()
