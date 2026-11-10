import socket
import threading
import unittest

from client.client import _connect_through_proxy


class _RefusingProxy(object):
    """Answers any CONNECT with a 407, the way an authenticating proxy does."""

    def __init__(self):
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.address = self._listener.getsockname()
        self._thread = threading.Thread(target=self._serve)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._thread.join()
        self._listener.close()

    def _serve(self):
        conn, _ = self._listener.accept()
        with conn:
            seen = b""
            while b"\r\n\r\n" not in seen:
                seen += conn.recv(1024)
            conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                         b"Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
                         b"Content-Length: 0\r\n\r\n")


class ConnectThroughProxyTest(unittest.TestCase):
    def test_a_407_is_reported_as_such(self):
        with _RefusingProxy() as proxy:
            with self.assertRaises(OSError) as caught:
                _connect_through_proxy(proxy.address, ("203.0.113.9", 443), 5.0)
        self.assertIn("407", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
