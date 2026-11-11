# Provenance

## Who named it, and when

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

## Attribution, and one thing to know before you emulate it

Attributed to **UNC2165 / EvilCorp** by Google Threat Horizons and GuidePoint,
typically as a follow-on to a FAKEUPDATES infection, with the access then
monetised or sold on — RansomHub in the reported cases. In the incident
InfoGuard analysed the ransomware was DragonForce, and they say plainly there
is **insufficient evidence** the access was transferred to them.

**EvilCorp has been under US sanctions since 2019 (OFAC).** That is a fact
about the actor, not about this code, but it is the reason their tooling gets
unusual attention — and a reason to keep an emulation of it inside a lab you
own and can account for.

## What independent sources say about the protocol

Useful because it corroborates the derivation in this repository from a
different sample set. GuidePoint, reading their own sample a year before the
InfoGuard write-up, reported that it:

- uses "a tunnel **heavily based on the SOCKS5 protocol, although the
  protocol is not fully implemented**" — which is the dialect in
  [the wire](protocol.md);
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
strings and are deliberately absent — see the note at the top of the README.

## Infrastructure, and how far an emulation goes

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
| A listening HTTP port for an operator UI | no | **only if you pass `--dashboard`**, and then on loopback — see [the dashboard](dashboard.md) |
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

## Samples and indicators

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

## MITRE ATT&CK

As mapped by third parties across the family, not by this tool: **T1059.006**
(Python), **T1053.005** (Scheduled Task), **T1546.001** (Change Default File
Association), **T1027** and **T1027.002** (Obfuscation, Software Packing),
**T1090.001** / **T1090.002** / **T1090.003** (Internal, External and
Multi-hop Proxy), **T1572** (Protocol Tunnelling), **T1573** (Encrypted
Channel), **T1102** (Web Service).

What *this* repository exercises is the proxy and tunnelling set — T1090 and
T1572. The persistence, obfuscation and packing techniques are the delivery
chain, and none of it is here.

## Related tooling in the same cluster

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

## Reading list

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
