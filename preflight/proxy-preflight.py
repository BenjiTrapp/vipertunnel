#!/usr/bin/env python3
"""Can this proxy carry the tunnel at all? Answer before deploying, not after.

The tunnel needs one thing from a proxy: `CONNECT <host>:443`, followed by
bytes that are not TLS and not HTTP. Two kinds of proxy answer that very
differently, and the difference is not visible until you try:

  * A proxy that filters nothing passes the CONNECT and then moves bytes it
    does not inspect. The tunnel works.
  * A proxy with a destination allowlist refuses any CONNECT whose target is
    not on the list. The tunnel cannot exist on that host -- and neither can
    the family it emulates, which is a finding rather than a gap.

There is a third case this exists to catch, and it is the expensive one: a
proxy that *permits* the CONNECT and then terminates or inspects the stream.
The CONNECT succeeds, the deployment looks fine, and the tunnel's handshake
dies for a reason that reads as a server fault. So this does not stop at the
`200`: it asks a listener you control to echo a known string back, and only
a byte-for-byte match counts as a pass.

Run it from the host that will carry the implant, not from the team server.
What the team server can reach is a different question.

    # on the host that will run the implant
    ./proxy-preflight.py --proxy 127.0.0.1:3128 --echo 203.0.113.9:443

    # with no echo listener yet, to learn only what the proxy permits
    ./proxy-preflight.py --proxy 10.0.0.9:8080 --target example.org:443

Stand the echo listener up on the host that will run the server:

    ./proxy-preflight.py --echo-server 0.0.0.0:443
"""

import argparse
import socket
import sys
import time

_PROBE = b"PREFLIGHT-" + b"%08x" % (int(time.time()) & 0xFFFFFFFF)
_DEADLINE = 20.0


def _split(text, default_port):
    if ":" in text:
        host, _, port = text.rpartition(":")
        return host, int(port)
    return text, default_port


def _connect(proxy, target, deadline):
    """Open a CONNECT tunnel. Returns (socket, status_line) or raises."""
    sock = socket.create_connection(proxy, timeout=deadline)
    where = "%s:%d" % target
    sock.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n"
                  "Proxy-Connection: Keep-Alive\r\n\r\n"
                  % (where, where)).encode("ascii"))
    header = b""
    sock.settimeout(deadline)
    while b"\r\n\r\n" not in header:
        if len(header) > 8192:
            sock.close()
            raise OSError("proxy sent more than 8 KiB of headers")
        chunk = sock.recv(1)
        if not chunk:
            sock.close()
            raise OSError("proxy closed during CONNECT after %d bytes"
                          % len(header))
        header += chunk
    status = header.split(b"\r\n", 1)[0].decode("latin-1", "replace").strip()
    return sock, status


def probe(proxy, target, expect_echo):
    """One destination, three verdicts: refused, permitted, or carried."""
    label = "%s:%d" % target
    try:
        sock, status = _connect(proxy, target, _DEADLINE)
    except OSError as exc:
        print("  %-28s CONNECT failed: %s" % (label, exc))
        return "unreachable"

    if " 200" not in status:
        sock.close()
        # This is the allowlist answer, and it is a result. A 403 here means
        # this family's traffic cannot be produced from this host at all.
        print("  %-28s REFUSED  -> %s" % (label, status))
        return "refused"

    if not expect_echo:
        sock.close()
        print("  %-28s permitted (%s) -- but nothing proved bytes survive"
              % (label, status))
        return "permitted"

    try:
        sock.sendall(_PROBE)
        sock.settimeout(_DEADLINE)
        back = b""
        while len(back) < len(_PROBE):
            chunk = sock.recv(len(_PROBE) - len(back))
            if not chunk:
                break
            back += chunk
    except OSError as exc:
        sock.close()
        print("  %-28s permitted, then the stream died: %s" % (label, exc))
        return "intercepted"
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if back == _PROBE:
        print("  %-28s CARRIED  (%s, %d bytes echoed intact)"
              % (label, status, len(back)))
        return "carried"

    # The expensive case: the CONNECT worked and something in the middle did
    # not pass the bytes through unchanged.
    print("  %-28s permitted but ALTERED: sent %r, got %r"
          % (label, _PROBE[:24], back[:24]))
    return "altered"


def echo_server(bind):
    """A listener that answers raw bytes with the same raw bytes.

    Deliberately not TLS and not HTTP: the point is to prove a proxy will
    carry a stream it cannot parse, which is what the tunnel needs.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(bind)
    listener.listen(8)
    print("echo listener on %s:%d -- raw bytes in, same bytes out. Ctrl-C to stop."
          % bind)
    try:
        while True:
            sock, peer = listener.accept()
            try:
                sock.settimeout(_DEADLINE)
                data = sock.recv(4096)
                if data:
                    sock.sendall(data)
                    print("  echoed %d bytes for %s:%d" % (len(data), peer[0], peer[1]))
            except OSError as exc:
                print("  %s:%d went away: %s" % (peer[0], peer[1], exc))
            finally:
                sock.close()
    except KeyboardInterrupt:
        print("stopping")
    finally:
        listener.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Can this proxy carry the tunnel? Ask before deploying.")
    parser.add_argument("--proxy", metavar="HOST:PORT",
                        help="the proxy to interrogate, as the implant would "
                             "use it (default port 3128)")
    parser.add_argument("--echo", metavar="HOST:PORT", action="append",
                        default=[],
                        help="a destination running --echo-server. Proves "
                             "bytes survive, not merely that CONNECT was "
                             "permitted. Repeatable.")
    parser.add_argument("--target", metavar="HOST:PORT", action="append",
                        default=[],
                        help="a destination to test CONNECT against without "
                             "an echo listener. Tells you what the proxy "
                             "permits and nothing more. Repeatable.")
    parser.add_argument("--echo-server", metavar="HOST:PORT",
                        help="run the echo listener instead of probing")
    args = parser.parse_args(argv)

    if args.echo_server:
        echo_server(_split(args.echo_server, 443))
        return 0

    if not args.proxy:
        parser.error("--proxy is required unless --echo-server is given")
    if not args.echo and not args.target:
        parser.error("give at least one --echo or --target")

    proxy = _split(args.proxy, 3128)
    print("proxy %s:%d" % proxy)

    verdicts = {}
    for raw in args.echo:
        verdicts[raw] = probe(proxy, _split(raw, 443), True)
    for raw in args.target:
        verdicts[raw] = probe(proxy, _split(raw, 443), False)

    print()
    carried = [k for k, v in verdicts.items() if v == "carried"]
    refused = [k for k, v in verdicts.items() if v == "refused"]
    broken = [k for k, v in verdicts.items()
              if v in ("intercepted", "altered")]

    if carried:
        print("DEPLOYABLE through this proxy to: %s" % ", ".join(carried))
    if refused:
        print("REFUSED by an allowlist: %s" % ", ".join(refused))
        print("  A destination-filtering proxy cannot carry this tunnel, and")
        print("  cannot carry the family it emulates either. That is a result")
        print("  about the environment, not a missing feature here.")
    if broken:
        print("PERMITTED BUT NOT CARRIED: %s" % ", ".join(broken))
        print("  The CONNECT succeeded and the stream did not survive. This is")
        print("  the case that looks like a server fault after deployment --")
        print("  something in the path is terminating or rewriting the bytes.")
    if not carried and not refused and not broken:
        print("Nothing conclusive. Re-run with --echo against a listener you")
        print("control: a 200 on its own proves only that CONNECT was allowed.")

    return 0 if carried else 1


if __name__ == "__main__":
    sys.exit(main())
