"""The dashboard's arithmetic and its routes.

Two things are worth testing here and the rest is not. The cadence numbers,
because they are the thing an operator will quote and a wrong coefficient of
variation is a wrong finding. And the control routes, because each of them
changes the run being measured.
"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from server.dashboard import Dashboard, EventLog, cadence
from server.server import (Fleet, Knob, LabGuard, Ledger, SessionBook,
                           WireLog)


class CadenceTest(unittest.TestCase):
    def test_a_perfect_timer_has_no_jitter(self):
        arrivals = [1000.0 + 120.0 * n for n in range(6)]
        result = cadence(arrivals, now=arrivals[-1])
        self.assertEqual(result["mean"], 120.0)
        self.assertEqual(result["cv"], 0.0)
        self.assertIn("timer", result["verdict"])

    def test_scattered_gaps_are_reported_as_no_cadence(self):
        result = cadence([0.0, 5.0, 400.0, 410.0, 1200.0], now=1200.0)
        self.assertGreater(result["cv"], 0.25)
        self.assertIn("no cadence", result["verdict"])

    def test_one_connection_is_the_held_shape_not_a_mean(self):
        # The trap this guards: reporting a mean over a single number as
        # though it described a cadence.
        result = cadence([1000.0], now=1500.0)
        self.assertIsNone(result["mean"])
        self.assertEqual(result["connections"], 1)
        self.assertIn("held-connection", result["verdict"])
        self.assertEqual(result["since_last"], 500.0)

    def test_nothing_connected_says_so(self):
        result = cadence([], now=10.0)
        self.assertEqual(result["connections"], 0)
        self.assertIsNone(result["since_last"])


class EventLogTest(unittest.TestCase):
    def test_history_is_bounded(self):
        log = EventLog(limit=3)
        for n in range(10):
            log.record("stamp", "event", {"n": n})
        history = log.history()
        self.assertEqual(len(history), 3)
        self.assertEqual(history[-1]["fields"]["n"], "9")

    def test_a_listener_gets_what_happens_after_it_subscribes(self):
        log = EventLog()
        log.record("stamp", "before", {})
        listener = log.listen()
        log.record("stamp", "after", {})
        self.assertEqual(listener.get_nowait()["event"], "after")
        self.assertTrue(listener.empty())

    def test_a_full_listener_is_not_allowed_to_block_the_server(self):
        # The listener queue stands in for a browser tab that stopped
        # reading. Recording must stay fast whatever it does.
        log = EventLog()
        listener = log.listen()
        for n in range(listener.maxsize + 50):
            log.record("stamp", "event", {"n": n})
        self.assertEqual(listener.qsize(), listener.maxsize)


class _Board(object):
    """A dashboard on a port the kernel picked, torn down afterwards."""

    def __enter__(self):
        self.ledger = Ledger(None)
        self.knob = Knob(60.0)
        self.fleet = Fleet(self.ledger)
        self.wire = WireLog()
        self.board = Dashboard(("127.0.0.1", 0), self.fleet, SessionBook(),
                               self.knob, self.ledger, socks_port=0,
                               command_port=443, wire=self.wire,
                               guard=LabGuard())
        self.port = self.board.server_address[1]
        self.thread = threading.Thread(target=self.board.serve_forever,
                                       daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.board.shutdown()
        self.board.server_close()
        self.thread.join(timeout=5)

    def get(self, route):
        with urllib.request.urlopen(
                "http://127.0.0.1:%d%s" % (self.port, route),
                timeout=5) as response:
            return json.loads(response.read())

    def post(self, route, payload):
        request = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, route),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())


class RoutesTest(unittest.TestCase):
    def test_state_reports_the_knob_and_the_shape_it_produces(self):
        with _Board() as board:
            state = board.get("/api/state")
            self.assertEqual(state["knob"]["keepalive"], 60.0)
            self.assertTrue(state["knob"]["held"])
            self.assertIn("one held connection", state["knob"]["shape"])
            self.assertEqual(state["clients"], [])

    def test_turning_the_knob_changes_the_shape_and_is_recorded(self):
        with _Board() as board:
            answer = board.post("/api/keepalive", {"seconds": 0})
            self.assertEqual(answer["keepalive"], 0.0)
            self.assertIn("reconnect", answer["shape"])
            self.assertEqual(board.knob.seconds, 0.0)
            events = [e["event"] for e in board.get("/api/state")["events"]]
            self.assertIn("knob-turned", events)

    def test_a_negative_keepalive_is_refused_rather_than_stored(self):
        with _Board() as board:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                board.post("/api/keepalive", {"seconds": -5})
            self.assertEqual(caught.exception.code, 400)
            self.assertEqual(board.knob.seconds, 60.0)

    def test_a_note_lands_in_the_ledger(self):
        with _Board() as board:
            board.post("/api/note", {"text": "alert 4411 fired"})
            notes = [e for e in board.get("/api/state")["events"]
                     if e["event"] == "operator-note"]
            self.assertEqual(len(notes), 1)
            self.assertIn("4411", notes[0]["fields"]["text"])

    def test_hanging_up_on_a_client_that_is_not_there_is_a_404(self):
        with _Board() as board:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                board.post("/api/hangup", {"client": 9999})
            self.assertEqual(caught.exception.code, 404)

    def test_the_page_is_served_and_nothing_outside_web_is(self):
        with _Board() as board:
            url = "http://127.0.0.1:%d/" % board.port
            with urllib.request.urlopen(url, timeout=5) as response:
                self.assertIn(b"vipertunnel", response.read())
            # A traversal must not reach the source beside the web directory.
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(
                    "http://127.0.0.1:%d/..%%2fdashboard.py" % board.port,
                    timeout=5)
            self.assertEqual(caught.exception.code, 404)

    def test_the_fonts_are_served_from_here_with_the_right_type(self):
        # The fonts are in the repository rather than on a CDN, because the
        # page's own Content-Security-Policy is default-src 'self' and a
        # measurement host usually has no internet. A wrong MIME type would
        # break the page quietly, so it is worth a test.
        with _Board() as board:
            for name in ("orbitron-latin", "jetbrains-mono-latin"):
                url = "http://127.0.0.1:%d/fonts/%s.woff2" % (board.port, name)
                with urllib.request.urlopen(url, timeout=5) as response:
                    self.assertEqual(response.headers["Content-Type"],
                                     "font/woff2")
                    self.assertTrue(response.read().startswith(b"wOF2"))

    def test_totals_keep_counting_past_the_event_buffer(self):
        # The ring buffer forgets; a counter on the page that silently
        # stopped counting would be worse than no counter.
        with _Board() as board:
            board.board.events = EventLog(limit=2)
            for _ in range(5):
                board.ledger.record("client-connected", peer="10.0.0.9:4444")
            board.ledger.record("session-open", host="10.0.0.5", port=80)
            state = board.get("/api/state")
            self.assertEqual(len(state["events"]), 2)
            self.assertEqual(state["totals"]["connections"], 5)
            self.assertEqual(state["totals"]["sessions"], 1)
            self.assertEqual(state["cadence"][0]["connections"], 5)


if __name__ == "__main__":
    unittest.main()
