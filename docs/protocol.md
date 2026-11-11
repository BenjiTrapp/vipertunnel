# The wire

SOCKS5 with pieces removed. Not a variant of RFC 1928 — a dialect that
confuses anything expecting the real thing.

The published client is the only description of this protocol that exists;
the server side was never published. Everything below was derived by reading
it, and `server/server.py` is written to the same derivation. Where the two
disagree the client is right: it is the artefact that was observed.

## In one table

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

## The command channel

One connection, held open, carrying `uint16` port numbers and nothing else.

```mermaid
sequenceDiagram
    autonumber
    participant I as implant
    participant S as server (:443)
    participant O as operator (RFC 1928, loopback)

    I->>S: TCP connect
    Note over S: a bare probe gets the next line and nothing else --<br/>the 00 00 fingerprint that enumerated this family
    S-->>I: 00 00  (keep-alive, uint16 LE zero)
    I-->>S: 00 00  (the echo)

    O->>S: SOCKS5 CONNECT host:port
    S->>S: open a listener on an ephemeral port
    S-->>I: 9f 1a  (that port, little-endian)
    I->>S: TCP connect to the announced port
    Note over I,S: the relay carries no identifier, so the<br/>pairing is by port alone
```

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

## The relay handshake

On the relay connection the roles invert: the **server** is the SOCKS client
and the **implant** is the SOCKS server. That inversion is the whole idea of
a reverse tunnel.

```mermaid
sequenceDiagram
    autonumber
    participant S as server<br/>(SOCKS client here)
    participant I as implant<br/>(SOCKS server here)
    participant T as target

    S->>I: 01 00
    Note right of S: nmethods=1, method=none.<br/>RFC 1928 would start with 05.
    I-->>S: 00
    Note left of I: chosen method

    S->>I: 01 01 04 then c0 a8 01 05 then bb 01
    Note right of S: cmd=CONNECT, atyp=IPv4, addrlen=4 (ignored),<br/>address, port 443 little-endian

    I->>T: TCP connect
    T-->>I: established

    I-->>S: 01
    Note left of I: 1 is SUCCESS. The RFC uses 0.
    I-->>S: 01 04 then c0 a8 01 09 then 9c 8e
    Note left of I: atyp, addrlen, bound address, bound port LE

    S->>I: raw bytes
    I-->>S: raw bytes
    I->>T: raw bytes
    T-->>I: raw bytes
```

## What an RFC client does instead

A consequence worth knowing if you compare notes with other emulations: a
**public simulation of this family sends `05 01 00`**, the RFC 1928 greeting.
The real client reads the first byte as `nmethods`, so `05` makes it wait for
five method bytes that never come.

```mermaid
sequenceDiagram
    participant R as an RFC 1928 client
    participant I as implant
    R->>I: 05 01 00
    Note right of I: reads 05 as nmethods,<br/>then waits for five method bytes
    Note right of I: 01 00 are two of them.<br/>Three never come.
    Note over R,I: deadlock until the read deadline
```

An RFC greeting does not talk to this family, which is exactly what the "no
version byte" row in the table means in practice.

## What the two sides refuse

| Asked for | Implant answers | Server turns that into |
|---|---|---|
| BIND or UDP ASSOCIATE | `00` | RFC `07`, command not supported |
| IPv6 target | `00` | refused before it is sent; the server will not forward an `atyp` the client has no code for |
| an unreachable target | `00` | RFC `05`, connection refused |
| a target that connects | `01` + bound address | RFC `00` + bound address |

The server translates in both directions, because the dialect has no version
bytes, little-endian ports and inverted status codes. Every difference is a
deviation the original introduced and the server has to undo.
