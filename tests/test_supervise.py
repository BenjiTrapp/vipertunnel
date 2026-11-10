import unittest

from client.client import Ledger
from client.supervise import supervise


class _MemLedger(object):
    def __init__(self):
        self.events = []

    def record(self, event, **fields):
        self.events.append((event, fields))


class _Child(object):
    """Stands in for a Popen: `wait()` is where the fake clock moves."""

    def __init__(self, spawner, lifetime, returncode):
        self._spawner = spawner
        self._lifetime = lifetime
        self.returncode = returncode

    def wait(self):
        self._spawner.now += self._lifetime
        return self.returncode


class _Spawner(object):
    """Hands out children that live exactly as long as they are told to.

    Time only moves inside `wait()`, so a test states a lifetime and gets that
    lifetime back from the supervisor without anyone sleeping. `stop_after`
    plays the operator's Ctrl-C: the supervisor is interrupted when it next
    tries to start a child, which is after it has dated the last death and
    served any backoff that death earned.
    """

    def __init__(self, lifetimes, stop_after=None, returncode=0):
        self._lifetimes = lifetimes
        self._stop_after = stop_after
        self._returncode = returncode
        self.starts = 0
        self.now = 0.0

    def clock(self):
        return self.now

    def __call__(self, argv):
        if self._stop_after is not None and self.starts >= self._stop_after:
            raise KeyboardInterrupt()
        lifetime = self._lifetimes[self.starts]
        self.starts += 1
        return _Child(self, lifetime, self._returncode)


class SuperviseTest(unittest.TestCase):
    def test_long_lived_child_is_restarted_without_backoff(self):
        # lives 3 h, dies, is restarted; no sleeping before the restart
        fake = _Spawner(lifetimes=[10800.0, 10800.0], stop_after=2)
        slept = []
        rc = supervise(["client"], _MemLedger(), spawn=fake, sleep=slept.append,
                       clock=fake.clock)
        self.assertEqual(rc, 0)
        self.assertEqual(fake.starts, 2)
        self.assertEqual(slept, [])

    def test_rapid_failures_open_the_circuit_breaker(self):
        fake = _Spawner(lifetimes=[0.5] * 9)
        slept = []
        rc = supervise(["client"], _MemLedger(), max_rapid_failures=3,
                       spawn=fake, sleep=slept.append, clock=fake.clock)
        self.assertEqual(rc, 1)
        self.assertEqual(fake.starts, 3)

    def test_backoff_grows_then_resets_after_a_long_life(self):
        fake = _Spawner(lifetimes=[0.5, 0.5, 10800.0, 0.5], stop_after=4)
        slept = []
        supervise(["client"], _MemLedger(), backoff_base=60.0,
                  spawn=fake, sleep=slept.append, clock=fake.clock)
        self.assertEqual(slept[:2], [60.0, 120.0])
        self.assertEqual(slept[2], 60.0)

    def test_each_death_is_dated_in_the_ledger(self):
        ledger = _MemLedger()
        fake = _Spawner(lifetimes=[10807.0], stop_after=1)
        supervise(["client"], ledger, spawn=fake, sleep=lambda s: None,
                  clock=fake.clock)
        entry = [e for e in ledger.events if e[0] == "child-exit"][0]
        self.assertEqual(entry[1]["lifetime_seconds"], 10807)
        self.assertEqual(entry[1]["exit_code"], 0)

    def test_an_unwritable_ledger_does_not_kill_the_run(self):
        ledger = Ledger("/proc/this/cannot/be/written")
        fake = _Spawner(lifetimes=[1.0], stop_after=1)
        with self.assertLogs("tunnel.supervise", level="ERROR") as logged:
            supervise(["client"], ledger, spawn=fake, sleep=lambda s: None,
                      clock=fake.clock)   # must not raise
        self.assertIn("child-exit", logged.output[0])


if __name__ == "__main__":
    unittest.main()
