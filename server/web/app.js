/* The operator view.
 *
 * No framework and no build step, because the repository promises "standard
 * library only, no install step" and a dashboard is not a good enough reason
 * to break that promise. Three jobs:
 *
 *   1. poll /api/state for the live numbers (held time, session ages),
 *   2. stream /api/events for the feed, so a line appears the moment the
 *      ledger gets it,
 *   3. draw the timeline, which is the one thing here that is easier to see
 *      than to read.
 *
 * The timeline is rebuilt from the same events the ledger file holds, so
 * anything visible here can be found in the file a finding cites. */

const POLL_MS = 2000;
const LABEL_W = 118;
const LANE_H = 66;
const MARK_H = 26;
const AXIS_H = 24;
const PHASE_H = 16;
const NS = "http://www.w3.org/2000/svg";

const model = {
  server: null,
  knob: null,
  clients: [],
  sessions: [],
  cadence: [],
  totals: {},
  volume: {},
  phases: [],
  marks: [],
  events: [],
  span: 0,          // 0 is "fit": pick the window from the data
};

const el = (id) => document.getElementById(id);
const svgEl = (tag, attrs, parent) => {
  const node = document.createElementNS(NS, tag);
  for (const key in attrs) node.setAttribute(key, attrs[key]);
  if (parent) parent.appendChild(node);
  return node;
};

/* -- talking to the server ------------------------------------------------- */

async function poll() {
  try {
    const state = await (await fetch("/api/state")).json();
    Object.assign(model, {
      server: state.server, knob: state.knob, clients: state.clients,
      sessions: state.sessions, cadence: state.cadence,
      totals: state.totals || {}, volume: state.volume || {},
      phases: state.phases || [], marks: state.marks || [],
    });
    if (state.events && state.events.length >= model.events.length) {
      model.events = state.events;
    }
    renderAll();
  } catch (err) {
    setFeedStatus("server gone");
  }
}

function stream() {
  const source = new EventSource("/api/events");
  source.onopen = () => setFeedStatus("live");
  source.onerror = () => setFeedStatus("reconnecting");
  source.onmessage = (message) => {
    const entry = JSON.parse(message.data);
    if (model.events.some((e) => e.id === entry.id)) return;
    model.events.push(entry);
    if (model.events.length > 2000) model.events.shift();
    renderFeed();
    renderProxyLog();
    renderTimeline();
    // A handshake just finished, so the capture is new.
    if (entry.event === "session-open" || entry.event === "dialect-failed" ||
        entry.event === "target-refused-by-client") {
      renderWire();
    }
  };
}

const setFeedStatus = (text) => {
  const node = el("fact-feed");
  node.textContent = text;
  node.className = text === "live" ? "up" : "down";
};

async function post(route, body) {
  const response = await fetch(route, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return response.json();
}

/* -- the strip ------------------------------------------------------------- */

/* The busiest host is the one whose numbers go in the strip. With one
 * implant, which is the usual case, it is the only one. */
const busiest = () =>
  model.cadence.slice().sort((a, b) => b.connections - a.connections)[0];

function renderStrip() {
  if (!model.knob) return;
  const held = model.knob.held;
  const best = busiest();

  el("shape-line").textContent = held
    ? "One held connection. A proxy logs a single CONNECT and a byte count."
    : `A reconnect every ~${model.knob.client_timeout} s, which is the client's read deadline.`;

  /* The predicted shape and the measured one are two different claims, and
   * they do come apart: reading an announced relay port resets the command
   * connection's read deadline, so traffic during a run loosens the cadence
   * the setting alone would produce. Saying only the prediction would hide
   * exactly that. */
  let why = held
    ? "No cadence for a periodicity detection to find — a result worth having, not a failed run. Run the other position too; the pair is the finding."
    : "The server never sends a keep-alive, so the client's read times out and it builds a new connection.";
  if (best && best.cv !== null) {
    why += ` Measured on ${best.host}: ${best.verdict}.`;
    if (!held && best.cv >= 0.05) {
      why += " The measurement disagrees with the setting — a relay session resets the read deadline.";
    }
  }
  el("shape-why").textContent = why;

  el("m-cv").textContent = best && best.cv !== null ? best.cv.toFixed(3) : "—";
  el("m-mean").textContent =
    best && best.mean !== null ? `${best.mean}s` : "—";
  el("m-mean").title = best && best.stdev !== null
    ? `standard deviation ± ${best.stdev} s` : "";
  el("m-conns").textContent = model.totals.connections || 0;
  el("m-ka").textContent = model.totals.keepalives || 0;
  el("m-sessions").textContent = model.sessions.length;

  const positions = [...document.querySelectorAll(".switch .pos")];
  positions.forEach((button) => {
    button.classList.toggle(
      "on", Number(button.dataset.seconds) === Number(model.knob.keepalive));
  });
  /* A value between the two positions is legal and sometimes wanted, but a
   * switch with neither end lit and no number anywhere would leave the page
   * silent about what is actually set. */
  const custom = !positions.some((b) => b.classList.contains("on"));
  const field = el("knob-custom");
  field.closest(".custom").classList.toggle("on", custom);
  field.placeholder = custom ? `${model.knob.keepalive} s` : "s";

  if (model.server) {
    el("fact-command").textContent = `0.0.0.0:${model.server.command_port}`;
    el("fact-socks").textContent = `127.0.0.1:${model.server.socks_port}` +
      (model.server.socks_auth ? " auth" : "");
    el("fact-uptime").textContent = duration(model.server.uptime_seconds);
    const lab = model.server.lab_only;
    const targets = el("fact-targets");
    targets.textContent = lab ? "lab only" : "ANYWHERE";
    targets.className = lab ? "up" : "down";
    targets.title = lab
      ? "Relaying is limited to the private ranges, loopback and link-local."
      : "--allow-public is set: this will relay to routable addresses.";
  }
}

/* -- wire tap -------------------------------------------------------------- */

/* The repository's claim is the wire. Showing the bytes next to the
 * deviation they embody is what turns that from an assertion into something
 * a reader can check. */
async function renderWire() {
  const answer = await (await fetch("/api/wire")).json();
  const captures = answer.captures || [];
  el("wire-count").textContent = captures.length;
  el("wire-empty").classList.toggle("hidden", captures.length > 0);
  const host = el("wire");
  host.textContent = "";
  if (!captures.length) return;

  const capture = captures[0];
  const head = document.createElement("div");
  head.className = "wire-head";
  head.innerHTML =
    `<span class="k">${new Date(capture.at * 1000).toISOString().slice(11, 19)}Z</span> ` +
    `<b>${escapeText(capture.peer)}</b> → ${escapeText(capture.target)} ` +
    `<span class="${capture.outcome === "carried" ? "ok" : "bad"}">${escapeText(capture.outcome)}</span>`;
  host.appendChild(head);

  for (const step of capture.steps) {
    const row = document.createElement("div");
    row.className = "wire-step " +
      (step.direction === "to-implant" ? "out" : "in");
    const arrow = step.direction === "to-implant" ? "→" : "←";
    row.innerHTML =
      `<div class="wire-label">${arrow} ${escapeText(step.label)}</div>` +
      `<div class="wire-hex">${escapeText(step.hex)}` +
      (step.bytes > 300 ? ` <span class="k">… ${step.bytes} B</span>` : "") +
      `</div><div class="wire-note">${escapeText(step.note)}</div>`;
    host.appendChild(row);
  }
}

/* -- fingerprint ----------------------------------------------------------- */

async function runFingerprint(force) {
  const out = el("fp-out");
  out.textContent = "probing our own command port…";
  const result = await post("/api/fingerprint", { force: !!force });
  out.textContent = "";

  if (!result.ok) {
    const line = document.createElement("div");
    line.className = "bad";
    line.textContent = result.detail;
    out.appendChild(line);
    if (result.needs_force) {
      const button = document.createElement("button");
      button.className = "ghost";
      button.textContent = "probe anyway";
      button.style.marginTop = "8px";
      button.onclick = () => runFingerprint(true);
      out.appendChild(button);
    }
    el("fp-traits").classList.add("hidden");
    return;
  }

  const banner = document.createElement("div");
  banner.className = result.banner === "00 00" ? "ok" : "bad";
  banner.textContent = result.banner
    ? `banner: ${result.banner}   (after ${result.waited}s)`
    : `no banner after ${result.waited}s`;
  out.appendChild(banner);

  const verdict = document.createElement("div");
  verdict.style.marginTop = "6px";
  verdict.textContent = result.verdict;
  out.appendChild(verdict);

  if (result.relay_ports && result.relay_ports.length) {
    const ports = document.createElement("div");
    ports.style.marginTop = "6px";
    ports.innerHTML = `<span class="k">relay ports announced:</span> ` +
      escapeText(result.relay_ports.join(", "));
    out.appendChild(ports);
  }

  const table = el("fp-traits");
  const body = table.querySelector("tbody");
  body.textContent = "";
  for (const trait of result.traits) {
    const row = body.insertRow();
    row.insertCell().textContent = trait.trait;
    row.insertCell().textContent = trait.real;
    const here = row.insertCell();
    here.textContent = trait.here;
    here.className = /^yes/.test(trait.here) ? "yes"
                   : /^YES/.test(trait.here) ? "warnish" : "";
  }
  table.classList.remove("hidden");
}

/* -- fleet and sessions ---------------------------------------------------- */

function renderFleet() {
  const body = el("fleet").querySelector("tbody");
  body.textContent = "";
  el("fleet-count").textContent = model.clients.length;
  el("fleet-empty").classList.toggle("hidden", model.clients.length > 0);
  el("fleet").classList.toggle("hidden", model.clients.length === 0);

  for (const client of model.clients) {
    const row = body.insertRow();
    row.insertCell().textContent = client.peer;
    row.insertCell().textContent = duration(client.held_seconds);
    row.insertCell().textContent = client.keepalives;
    row.insertCell().textContent = client.sessions;
    const button = document.createElement("button");
    button.className = "danger";
    button.textContent = "hang up";
    button.title = "The original does not reconnect from a close: this ends " +
                   "that implant until something outside starts it again.";
    button.onclick = async () => {
      if (!confirm(
        "Hanging up ends this implant — the original does not reconnect " +
        "from a close, and that is reproduced. Continue?")) return;
      await post("/api/hangup", { client: client.id });
      poll();
    };
    row.insertCell().appendChild(button);
  }

  const sessions = el("sessions");
  sessions.textContent = "";
  el("session-count").textContent = model.sessions.length;
  el("session-empty").classList.toggle("hidden", model.sessions.length > 0);
  for (const session of model.sessions) {
    const card = document.createElement("div");
    card.className = "session";
    card.innerHTML =
      `<div class="session-top">` +
      `<b>${escapeText(session.target)}</b>` +
      `<span class="rx">→ ${bytes(session.out_bytes)}</span>` +
      `<span class="tx">← ${bytes(session.in_bytes)}</span>` +
      `<span class="k">${bytes(session.rate)}/s · ${duration(session.age_seconds)}</span>` +
      `<span class="spark">${sparkline(session.recent)}</span>` +
      `</div>` +
      `<div class="session-saw">${escapeText(session.summary)}</div>` +
      `<div class="session-foot k">relay port ${session.relay_port} · via ${escapeText(session.peer)}</div>`;
    sessions.appendChild(card);
  }
}

/* The bytes-per-second of one session, small enough to sit in its card. The
 * relays are the part of this traffic that carries volume, and a number
 * alone does not show whether it arrived in one burst or steadily. */
function sparkline(series) {
  if (!series || series.length < 2) return "";
  const width = 90, height = 16;
  const from = series[0][0], span = Math.max(1, series[series.length - 1][0] - from);
  const peak = Math.max(...series.map((s) => s[1] + s[2]), 1);
  const points = series.map(([second, out, into]) =>
    `${((second - from) / span * width).toFixed(1)},` +
    `${(height - (out + into) / peak * height).toFixed(1)}`);
  return `<svg viewBox="0 0 ${width} ${height}" width="${width}" height="${height}">` +
    `<polyline points="${points.join(" ")}" fill="none" ` +
    `stroke="var(--tx)" stroke-width="1.5"/></svg>`;
}

const bytes = (count) => {
  if (count < 1024) return `${count} B`;
  if (count < 1024 * 1024) return `${(count / 1024).toFixed(1)} KiB`;
  return `${(count / 1048576).toFixed(1)} MiB`;
};

/* -- the feed -------------------------------------------------------------- */

const FEED_CLASS = {
  "client-connected": "e-arrive",
  "client-gone": "e-leave",
  "hung-up-on-client": "e-leave",
  "keepalive": "e-keepalive",
  "relay-announced": "e-relay",
  "relay-paired": "e-relay",
  "session-open": "e-relay",
  "session-close": "e-relay",
  "operator-note": "e-note",
  "knob-turned": "e-note",
  "relay-failed": "e-fail",
  "dialect-failed": "e-fail",
  "operator-refused": "e-fail",
  "target-refused-by-client": "e-fail",
};

function renderFeed() {
  const feed = el("feed");
  // Rebuilding on every poll would throw away the operator's scroll
  // position, so only redraw when there is actually something new.
  const newest = model.events.length
    ? model.events[model.events.length - 1].id : 0;
  if (feed.dataset.newest === String(newest)) return;
  feed.dataset.newest = String(newest);
  el("feed-count").textContent = model.totals.connections !== undefined
    ? model.events.length : 0;
  feed.textContent = "";
  for (const entry of model.events.slice(-300).reverse()) {
    const item = document.createElement("li");
    item.className = FEED_CLASS[entry.event] || "";
    const stamp = document.createElement("time");
    stamp.textContent = entry.stamp.slice(11, 19);
    const name = document.createElement("span");
    name.className = "ev";
    name.textContent = entry.event;
    const fields = document.createElement("span");
    fields.className = "fields";
    fields.textContent = Object.entries(entry.fields)
      .map(([k, v]) => `${k}=${v}`).join(" ");
    item.append(stamp, name, fields);
    feed.appendChild(item);
  }
}

/* What a forward proxy would have written, from the same events.
 *
 * Only facts this server actually holds go in a line. It does not know the
 * hostname the implant dialled or how many bytes the proxy counted, so those
 * are left as `?` -- a reconstruction that guesses is worse than one with
 * holes in it. */
function renderProxyLog() {
  const lines = [];
  const destination = `<this server>:${model.server ? model.server.command_port : 443}`;
  const segments = commandSegments();
  for (const segment of segments) {
    const start = new Date(segment.start * 1000).toISOString().slice(0, 19) + "Z";
    const held = Math.max(0, Math.round(segment.end - segment.start));
    lines.push(
      `${start}  ${segment.host}  CONNECT ${destination}  200  ` +
      `${held}s  ?B${segment.open ? "  (open)" : ""}`);
  }
  if (!segments.length) {
    lines.push("# nothing yet. One line will appear per command connection,");
    lines.push("# which is exactly as much as a proxy log would hold --");
    lines.push("# no keep-alives, no relay ports, no session targets.");
  } else {
    lines.push("");
    lines.push(`# ${segments.length} line(s). Everything else on this page` +
               " is invisible from here.");
  }
  el("proxylog").textContent = lines.join("\n");
}

/* -- the timeline ---------------------------------------------------------- */

/* Rebuild command connections from the events, then let the live fleet close
 * the gaps: a dashboard started mid-run has no connect event for a client
 * that is already up, and the fleet's own `opened` is the honest start. */
function commandSegments() {
  const open = new Map();
  const done = [];
  for (const entry of model.events) {
    const peer = entry.fields.peer;
    if (entry.event === "client-connected" && peer) {
      open.set(peer, { peer, host: hostPart(peer), start: entry.at,
                       keepalives: [] });
    } else if (entry.event === "keepalive" && open.has(peer)) {
      open.get(peer).keepalives.push(entry.at);
    } else if ((entry.event === "client-gone" ||
                entry.event === "hung-up-on-client") && open.has(peer)) {
      const segment = open.get(peer);
      segment.end = entry.at;
      segment.died = entry.at;
      open.delete(peer);
      done.push(segment);
    }
  }
  const now = model.server ? model.server.now : Date.now() / 1000;
  const live = new Set();
  for (const client of model.clients) {
    live.add(client.peer);
    const segment = open.get(client.peer) ||
      { peer: client.peer, host: hostPart(client.peer),
        start: client.opened, keepalives: [] };
    segment.end = now;
    segment.open = true;
    open.set(client.peer, segment);
  }
  for (const [peer, segment] of open) {
    if (!live.has(peer)) {
      // Last seen in an event but gone from the fleet: the dashboard missed
      // the departure, so end it where it was last heard from.
      segment.end = segment.keepalives.length
        ? segment.keepalives[segment.keepalives.length - 1] : segment.start;
    }
    done.push(segment);
  }
  return done.sort((a, b) => a.start - b.start);
}

function sessionSegments() {
  const open = new Map();
  const done = [];
  for (const entry of model.events) {
    const key = `${entry.fields.host}:${entry.fields.port}`;
    if (entry.event === "session-open") {
      open.set(key, { host: hostPart(entry.fields.peer || ""), key,
                      start: entry.at });
    } else if (entry.event === "session-close" && open.has(key)) {
      const segment = open.get(key);
      segment.end = entry.at;
      open.delete(key);
      done.push(segment);
    }
  }
  const now = model.server ? model.server.now : Date.now() / 1000;
  for (const segment of open.values()) {
    done.push(Object.assign({}, segment, { end: now, open: true }));
  }
  return done;
}

const hostPart = (peer) => String(peer).replace(/:\d+$/, "") || "unknown";

const severityClass = (severity) =>
  /crit|high|alert/.test(String(severity)) ? "high"
  : /med|warn/.test(String(severity)) ? "medium" : "info";

/* -- purple: phases and ingested detections -------------------------------- */

function renderPurple() {
  const now = model.server ? model.server.now : Date.now() / 1000;
  const current = model.phases.find((p) => !p.ended);
  el("phase-now").textContent = current
    ? `${current.name} · ${duration(now - current.started)}`
    : "none";
  el("phase-stop").classList.toggle("hidden", !current);

  const table = el("phases");
  const body = table.querySelector("tbody");
  body.textContent = "";
  table.classList.toggle("hidden", model.phases.length === 0);
  for (const phase of model.phases) {
    const end = phase.ended || now;
    // A running phase keeps an open window, so an alert from a platform
    // whose clock runs slightly ahead still lands in the phase it belongs
    // to rather than falling out of every phase.
    const horizon = phase.ended || Infinity;
    const during = model.marks.filter(
      (m) => m.at >= phase.started && m.at <= horizon);
    const row = body.insertRow();
    row.insertCell().textContent = phase.name + (phase.ended ? "" : "  (running)");
    row.insertCell().textContent =
      phase.keepalive === null ? "—" : `${phase.keepalive}s`;
    row.insertCell().textContent = duration(end - phase.started);
    const found = row.insertCell();
    /* "Nothing fired" is a result, not a blank. A phase with a keep-alive
     * under the client's timeout has no cadence to find, so an empty cell
     * here would read as missing data rather than as the finding. */
    if (!during.length) {
      found.textContent = "nothing fired";
      found.className = "warnish";
    } else {
      const first = Math.min(...during.map((m) => m.at));
      found.textContent = `${during.length} · first after ` +
        duration(first - phase.started);
      found.className = "yes";
    }
  }

  const feed = el("marks");
  feed.textContent = "";
  el("mark-count").textContent = model.marks.length;
  el("marks-empty").classList.toggle("hidden", model.marks.length > 0);
  for (const mark of model.marks.slice(-80).reverse()) {
    const item = document.createElement("li");
    item.className = "m-" + severityClass(mark.severity);
    const stamp = document.createElement("time");
    stamp.textContent = new Date(mark.at * 1000).toISOString().slice(11, 19);
    const source = document.createElement("span");
    source.className = "ev";
    source.textContent = mark.source;
    const label = document.createElement("span");
    label.className = "fields";
    label.textContent = mark.label;
    item.append(stamp, source, label);
    feed.appendChild(item);
  }
}

const escapeText = (text) => String(text).replace(/[<>&"]/g, (c) =>
  ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));

/* A hover card rather than an SVG <title>: a run is read by sweeping across
 * it, and a tooltip that takes a second to appear cannot be swept. */
function makeTip(host) {
  const node = document.createElement("div");
  node.className = "tip";
  host.appendChild(node);
  return {
    show(html, x, y) {
      node.innerHTML = html;
      node.style.opacity = 1;
      const width = host.clientWidth;
      node.style.left = Math.min(Math.max(0, x + 14),
                                 Math.max(0, width - node.offsetWidth)) + "px";
      node.style.top = Math.max(0, y - 10) + "px";
    },
    hide() { node.style.opacity = 0; },
  };
}

let tip = null;

function renderTimeline() {
  const chart = el("chart");
  const commands = commandSegments();
  const sessions = sessionSegments();
  if (!commands.length) {
    chart.textContent = "";
    tip = null;
    el("chart-empty").classList.remove("hidden");
    return;
  }
  el("chart-empty").classList.add("hidden");

  const hosts = [...new Set(commands.map((s) => s.host))].sort();
  const width = Math.max(chart.clientWidth || 1000, 560);
  const marks = model.marks.length ? MARK_H : 0;
  const height = PHASE_H + hosts.length * LANE_H + marks + AXIS_H + 10;
  const now = model.server ? model.server.now : Date.now() / 1000;

  /* `fit` is the default because the useful span is a property of the run,
   * not of the operator: a six-second test cadence and an overnight held
   * connection want windows three orders of magnitude apart, and guessing
   * wrong puts the whole run in the last pixel column. */
  const earliest = Math.min.apply(null, commands.map((s) => s.start));
  const span = model.span > 0
    ? model.span
    : Math.max(60, (now - earliest) * 1.08);
  const from = now - span;
  const plot = width - LABEL_W - 8;
  const x = (t) => LABEL_W + ((Math.min(Math.max(t, from), now) - from) /
                              span) * plot;

  chart.textContent = "";
  const svg = svgEl("svg", {
    viewBox: `0 0 ${width} ${height}`,
    height: height,
    preserveAspectRatio: "none",
    role: "img",
    "aria-label": "command connections and relay sessions over time",
  }, chart);

  // A soft bloom on the bars, the way the charts in the reference design
  // light up. Decoration, and it costs one filter.
  const defs = svgEl("defs", {}, svg);
  const glow = svgEl("filter", {
    id: "tl-glow", x: "-50%", y: "-50%", width: "200%", height: "200%",
  }, defs);
  svgEl("feGaussianBlur", { stdDeviation: 2, result: "b" }, glow);
  const merge = svgEl("feMerge", {}, glow);
  svgEl("feMergeNode", { in: "b" }, merge);
  svgEl("feMergeNode", { in: "SourceGraphic" }, merge);
  for (const [id, colour] of [["g-cmd", "--rx"], ["g-sess", "--tx"]]) {
    const value = getComputedStyle(document.documentElement)
      .getPropertyValue(colour).trim();
    const gradient = svgEl("linearGradient",
                           { id, x1: 0, x2: 0, y1: 0, y2: 1 }, defs);
    svgEl("stop", { offset: 0, "stop-color": value, "stop-opacity": 1 },
          gradient);
    svgEl("stop", { offset: 1, "stop-color": value, "stop-opacity": .55 },
          gradient);
  }

  // Time grid, labelled with how long ago rather than a clock time: the
  // question on this chart is always "how long between these".
  const axis = svgEl("g", { class: "ax" }, svg);
  for (let i = 0; i <= 5; i++) {
    const t = from + (span * i) / 5;
    const gx = x(t).toFixed(1);
    svgEl("line", { x1: gx, y1: 0, x2: gx, y2: height - AXIS_H }, axis);
    const ago = Math.round(now - t);
    svgEl("text", {
      x: gx, y: height - 7,
      "text-anchor": i === 0 ? "start" : i === 5 ? "end" : "middle",
    }, axis).textContent = ago === 0 ? "now" : "-" + duration(ago);
  }

  /* Phases first, behind everything: they are the context an alert's
   * timestamp is read against, so they belong under the data rather than
   * competing with it. */
  for (const phase of model.phases) {
    const end = phase.ended || now;
    if (end < from) continue;
    const x1 = x(phase.started), x2 = Math.max(x(end), x1 + 2);
    svgEl("rect", {
      class: "phase-band", x: x1.toFixed(1), y: PHASE_H,
      width: (x2 - x1).toFixed(1), height: height - AXIS_H - PHASE_H,
    }, svg);
    svgEl("line", {
      class: "phase-edge", x1: x1.toFixed(1), y1: PHASE_H,
      x2: x1.toFixed(1), y2: height - AXIS_H,
    }, svg);
    if (x2 - x1 > 46) {
      svgEl("text", { class: "phase-name", x: (x1 + 5).toFixed(1), y: 11 },
            svg).textContent = phase.name;
    }
  }

  const bars = svgEl("g", { filter: "url(#tl-glow)" }, svg);
  const lanes = new Map();

  hosts.forEach((host, index) => {
    const top = PHASE_H + index * LANE_H;
    lanes.set(host, top);
    svgEl("rect", {
      class: "lane-bg", x: LABEL_W, y: top + 4,
      width: plot, height: LANE_H - 12,
    }, svg);
    svgEl("text", { class: "lane-label", x: 4, y: top + 22 }, svg)
      .textContent = host;

    const mine = commands.filter((s) => s.host === host && s.end > from);
    mine.forEach((segment, position) => {
      const x1 = x(segment.start);
      const x2 = Math.max(x(segment.end), x1 + 2);
      svgEl("rect", {
        x: x1.toFixed(1), y: top + 10, width: (x2 - x1).toFixed(1),
        height: 15, fill: "url(#g-cmd)",
      }, bars);
      for (const at of segment.keepalives) {
        if (at < from) continue;
        svgEl("line", {
          x1: x(at).toFixed(1), y1: top + 10,
          x2: x(at).toFixed(1), y2: top + 25,
          stroke: "var(--warn)", "stroke-width": 2,
        }, bars);
      }
      if (segment.died && segment.died > from) {
        svgEl("line", {
          x1: x(segment.died).toFixed(1), y1: top + 6,
          x2: x(segment.died).toFixed(1), y2: top + 29,
          stroke: "var(--dead)", "stroke-width": 2,
        }, bars);
      }
      /* The gap to the previous connection, written on the chart, but only
       * where it changes. A steady cadence gets one label and then silence,
       * so a label means "the rhythm changed here" -- which is the thing
       * worth noticing. Twenty-three identical numbers hide it. */
      const previous = mine[position - 1];
      if (previous && previous.end) {
        const gap = Math.round(segment.start - previous.start);
        const before = position > 1
          ? Math.round(previous.start - mine[position - 2].start) : null;
        if (gap !== before && x1 - x(previous.start) > 28) {
          svgEl("text", {
            class: "gap-label", x: ((x(previous.start) + x1) / 2).toFixed(1),
            y: top + 40, "text-anchor": "middle",
          }, svg).textContent = gap + "s";
        }
      }
    });

    for (const session of sessions) {
      if (session.host !== host || session.end < from) continue;
      const x1 = x(session.start);
      const x2 = Math.max(x(session.end), x1 + 2);
      svgEl("rect", {
        x: x1.toFixed(1), y: top + 30, width: (x2 - x1).toFixed(1),
        height: 8, fill: "url(#g-sess)",
      }, bars);
    }

    /* The volume the relays carried, per second, under the lane. The README
     * calls the relays "the part that carries volume", and until now that
     * was the one thing about them with no shape on this chart. Log-scaled,
     * because a 4 KiB probe and a 40 MiB transfer belong on one axis. */
    const series = model.volume[host] || [];
    const base = top + LANE_H - 14;
    const tall = 18;
    svgEl("line", {
      class: "volume-base", x1: LABEL_W, y1: base,
      x2: LABEL_W + plot, y2: base,
    }, svg);
    if (series.length) {
      const peak = Math.max(...series.map(([, out, into]) => out + into), 1);
      const step = Math.max(1.5, plot / Math.max(1, span));
      for (const [second, out, into] of series) {
        if (second < from) continue;
        const bar = Math.log1p(out + into) / Math.log1p(peak) * tall;
        svgEl("rect", {
          class: "volume", x: x(second).toFixed(1),
          y: (base - bar).toFixed(1),
          width: step.toFixed(1), height: bar.toFixed(1),
        }, svg);
      }
      svgEl("text", {
        class: "volume-peak", x: LABEL_W + 3, y: base - tall - 1,
      }, svg).textContent = "peak " + bytes(peak) + "/s";
    }
  });

  /* Detections, on the same axis as the truth. One row, one tick per
   * ingested mark, so the gap between a thing happening and somebody
   * noticing is a distance you can see rather than two timestamps to
   * subtract. */
  if (marks) {
    const top = PHASE_H + hosts.length * LANE_H;
    svgEl("text", { class: "lane-label", x: 4, y: top + 16 }, svg)
      .textContent = "detections";
    svgEl("line", {
      class: "volume-base", x1: LABEL_W, y1: top + 18,
      x2: LABEL_W + plot, y2: top + 18,
    }, svg);
    for (const mark of model.marks) {
      if (mark.at < from) continue;
      const mx = x(mark.at).toFixed(1);
      const kind = "mark mark-" + severityClass(mark.severity);
      svgEl("line", {
        class: kind, x1: mx, y1: top + 3, x2: mx, y2: top + 18,
      }, bars);
      svgEl("circle", { class: kind, cx: mx, cy: top + 3, r: 2.5 }, bars);
    }
  }

  // Hover: find the connection under the cursor and describe it.
  const highlight = svgEl("rect", {
    class: "hl", x: 0, y: 0, width: 2, height: height - AXIS_H,
  }, svg);
  const hit = svgEl("rect", {
    x: LABEL_W, y: 0, width: plot, height: height - AXIS_H, fill: "transparent",
  }, svg);
  tip = tip || makeTip(chart);
  const atCursor = (event) => {
    const box = svg.getBoundingClientRect();
    const sx = (event.clientX - box.left) * width / box.width;
    const sy = (event.clientY - box.top) * height / box.height;
    const when = from + ((sx - LABEL_W) / plot) * span;
    const host = hosts[Math.floor(sy / LANE_H)];
    const segment = commands.find(
      (s) => s.host === host && s.start <= when && s.end >= when);
    return { segment, when, box, host };
  };
  hit.addEventListener("pointermove", (event) => {
    const { segment, box } = atCursor(event);
    if (!segment) { tip.hide(); highlight.setAttribute("opacity", 0); return; }
    highlight.setAttribute("x", x(segment.start).toFixed(1));
    highlight.setAttribute("width",
      Math.max(2, x(segment.end) - x(segment.start)).toFixed(1));
    highlight.setAttribute("y", lanes.get(segment.host) + 8);
    highlight.setAttribute("height", 19);
    highlight.setAttribute("opacity", .18);
    const lived = Math.round(segment.end - segment.start);
    const during = sessionSegments().filter(
      (s) => s.host === segment.host &&
             s.start < segment.end && s.end > segment.start).length;
    tip.show(
      `<b>${segment.peer}</b><br>` +
      `<span class="r">held ${duration(lived)}` +
      `${segment.open ? ", still open" : ""}</span><br>` +
      `<span class="k">keep-alives ${segment.keepalives.length}</span><br>` +
      `<span class="t">relay sessions ${during}</span>`,
      event.clientX - box.left, event.clientY - box.top);
  });
  hit.addEventListener("pointerleave", () => {
    tip.hide();
    highlight.setAttribute("opacity", 0);
  });
}

/* -- helpers --------------------------------------------------------------- */

function duration(seconds) {
  seconds = Math.max(0, Math.round(seconds));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function renderAll() {
  renderStrip();
  renderFleet();
  renderFeed();
  renderProxyLog();
  renderPurple();
  renderTimeline();
}

/* -- wiring ---------------------------------------------------------------- */

document.querySelectorAll(".switch .pos").forEach((button) => {
  button.onclick = async () => {
    await post("/api/keepalive", { seconds: Number(button.dataset.seconds) });
    poll();
  };
});

el("knob-set").onclick = async () => {
  const value = Number(el("knob-custom").value);
  if (!Number.isFinite(value) || value < 0) return;
  await post("/api/keepalive", { seconds: value });
  el("knob-custom").value = "";
  poll();
};

el("zoom").onclick = (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  model.span = Number(button.dataset.span);
  el("zoom").querySelectorAll("button").forEach(
    (b) => b.classList.toggle("on", b === button));
  renderTimeline();
};

el("probe").onsubmit = async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const out = el("probe-out");
  out.textContent = "probing…";
  const result = await post("/api/probe", {
    host: form.get("host"),
    port: Number(form.get("port")),
    payload: form.get("payload") || "",
  });
  out.textContent = "";
  const line = document.createElement("div");
  line.className = result.ok ? "ok" : "bad";
  line.textContent = result.ok
    ? `carried — sent ${result.sent} B, received ${result.received} B in ${result.seconds}s`
    : `no — ${result.detail}`;
  out.appendChild(line);
  if (result.preview) {
    const pre = document.createElement("pre");
    pre.textContent = result.preview;
    out.appendChild(pre);
  }
  poll();
};

el("note").onsubmit = async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const answer = await post("/api/note", { text: form.get("text") });
  el("note-out").innerHTML =
    `<span class="ok">written to the ledger: ${answer.note}</span>`;
  event.target.reset();
};

el("wire-refresh").onclick = renderWire;
el("fp-run").onclick = () => runFingerprint(false);

el("phase").onsubmit = async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  await post("/api/phase", { name: form.get("name") });
  event.target.reset();
  poll();
};

el("phase-stop").onclick = async () => {
  await post("/api/phase", { stop: true });
  poll();
};

el("ingest").onsubmit = async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const answer = await post("/api/ingest", {
    source: form.get("source"),
    label: form.get("label"),
    severity: "info",
  });
  if (answer.error) {
    alert(answer.error);
    return;
  }
  event.target.querySelector('[name="label"]').value = "";
  poll();
};

el("theme").onclick = () => {
  const root = document.documentElement;
  const next = root.dataset.theme === "grid" ? "report" : "grid";
  root.dataset.theme = next;
  localStorage.setItem("theme", next);
  renderTimeline();   // the gradients read their colours from the theme
};
document.documentElement.dataset.theme =
  localStorage.getItem("theme") || "grid";

window.addEventListener("resize", renderTimeline);

poll();
stream();
renderWire();
setInterval(poll, POLL_MS);
