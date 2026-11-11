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
const LABEL_W = 120;
const LANE_H = 48;
const AXIS_H = 22;

const model = {
  server: null,
  knob: null,
  clients: [],
  sessions: [],
  cadence: [],
  events: [],
  span: 0,          // 0 is "fit": pick the window from the data
  tab: "events",
};

const el = (id) => document.getElementById(id);

/* -- talking to the server ------------------------------------------------- */

async function poll() {
  try {
    const state = await (await fetch("/api/state")).json();
    model.server = state.server;
    model.knob = state.knob;
    model.clients = state.clients;
    model.sessions = state.sessions;
    model.cadence = state.cadence;
    if (state.events && state.events.length >= model.events.length) {
      model.events = state.events;
    }
    renderAll();
  } catch (err) {
    el("fact-feed").textContent = "server gone";
    el("fact-feed").className = "feed-down";
  }
}

function stream() {
  const source = new EventSource("/api/events");
  source.onopen = () => {
    el("fact-feed").textContent = "live";
    el("fact-feed").className = "feed-up";
  };
  source.onerror = () => {
    el("fact-feed").textContent = "reconnecting";
    el("fact-feed").className = "feed-down";
  };
  source.onmessage = (message) => {
    const entry = JSON.parse(message.data);
    if (model.events.some((e) => e.id === entry.id)) return;
    model.events.push(entry);
    if (model.events.length > 2000) model.events.shift();
    renderFeed();
    renderTimeline();
  };
}

async function post(route, body) {
  const response = await fetch(route, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return response.json();
}

/* -- the verdict ----------------------------------------------------------- */

function renderVerdict() {
  if (!model.knob) return;
  const held = model.knob.held;
  el("verdict").dataset.shape = held ? "held" : "cadence";

  el("shape-line").textContent = held
    ? "One held connection. A proxy logs a single CONNECT and a byte count."
    : `A reconnect every ~${model.knob.client_timeout} s, which is the client's read deadline.`;
  el("shape-why").textContent = held
    ? "There is no cadence here for a periodicity detection to find — which is a result worth having, not a failed run. Run the other position too; the pair is the finding."
    : "The server never sends a keep-alive, so the client's read times out and it builds a new connection. Near-zero jitter: about as easy as a periodicity detection ever gets.";

  document.querySelectorAll(".switch .pos").forEach((button) => {
    button.classList.toggle(
      "on", Number(button.dataset.seconds) === Number(model.knob.keepalive));
  });

  // The busiest host is the one worth putting in the headline numbers.
  const best = model.cadence.slice().sort(
    (a, b) => b.connections - a.connections)[0];
  const mean = el("m-mean"), cv = el("m-cv");
  el("m-conns").textContent = best ? best.connections : 0;
  mean.textContent = best && best.mean !== null ? `${best.mean} s` : "—";
  cv.textContent = best && best.cv !== null ? best.cv.toFixed(3) : "—";
  cv.parentElement.className = "metric" +
    (best && best.cv !== null && best.cv < 0.05 ? " timer" :
     best && best.cv !== null ? " loose" : "");

  /* The predicted shape and the measured one, side by side and labelled as
   * two different claims. They do come apart: a relay session resets the
   * command connection's read deadline, so a run with traffic in it has
   * more jitter than the knob alone would suggest -- and a dashboard that
   * only showed the prediction would hide exactly that. */
  const line = el("measured-verdict");
  if (!best || best.cv === null) {
    line.textContent = best ? `Measured: ${best.verdict}.`
                            : "Nothing measured yet.";
    line.classList.remove("disagrees");
    return;
  }
  const predictedTimer = !held;
  const measuredTimer = best.cv < 0.05;
  line.innerHTML = `Measured on <b>${escape(best.host)}</b>: ${
    escape(best.verdict)} — gaps of ${
    best.gaps.slice(-6).map((g) => g + "s").join(", ")}.`;
  line.classList.toggle("disagrees", predictedTimer !== measuredTimer);
  if (predictedTimer && !measuredTimer) {
    line.innerHTML += " <b>The measurement disagrees with the setting:</b> " +
      "a relay session resets the command connection's read deadline, so " +
      "traffic during a run loosens the cadence it would otherwise have.";
  }
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
    const action = row.insertCell();
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
    action.appendChild(button);
  }

  const sessions = el("sessions").querySelector("tbody");
  sessions.textContent = "";
  el("session-count").textContent = model.sessions.length;
  el("session-empty").classList.toggle("hidden", model.sessions.length > 0);
  el("sessions").classList.toggle("hidden", model.sessions.length === 0);
  for (const session of model.sessions) {
    const row = sessions.insertRow();
    row.insertCell().textContent = session.target;
    row.insertCell().textContent = session.relay_port;
    row.insertCell().textContent = session.peer;
    row.insertCell().textContent = duration(session.age_seconds);
  }
}

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

/* What a forward proxy would have written, from the same events. The crux of
 * the whole repository is that these two views disagree, so showing the
 * defender's one next to the truth is cheap and worth it.
 *
 * Only facts this server actually holds go in a line. It does not know what
 * hostname the implant dialled or how many bytes the proxy counted, so those
 * are left as `?` rather than invented -- a reconstruction that guesses is
 * worse than one with holes in it. */
function renderProxyLog() {
  const lines = [];
  const destination = `<this server>:${port()}`;
  for (const segment of commandSegments()) {
    const start = new Date(segment.start * 1000).toISOString()
      .replace(".000", "");
    const held = Math.max(0, Math.round(segment.end - segment.start));
    lines.push(
      `${start} ${segment.host} CONNECT ${destination} HTTP/1.1 200 ` +
      `duration=${held}s bytes=? ${segment.open ? "(still open)" : ""}`);
  }
  if (!lines.length) {
    lines.push("# nothing yet. One line will appear per command connection,");
    lines.push("# which is exactly as much as a proxy log would hold --");
    lines.push("# no keep-alives, no relay ports, no session targets.");
  } else {
    lines.push("");
    lines.push(`# ${lines.length - 1} line(s). Everything else on this page` +
               " is invisible from here.");
  }
  el("proxylog").textContent = lines.join("\n");
}

const port = () => (model.server ? model.server.command_port : 443);

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
                       keepalives: [], deaths: [] });
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
        start: client.opened, keepalives: [], deaths: [] };
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

function renderTimeline() {
  const chart = el("chart");
  const commands = commandSegments();
  const sessions = sessionSegments();
  if (!commands.length) {
    chart.textContent = "";
    el("chart-empty").classList.remove("hidden");
    return;
  }
  el("chart-empty").classList.add("hidden");

  const hosts = [...new Set(commands.map((s) => s.host))].sort();
  const width = Math.max(chart.clientWidth || 900, 520);
  const height = hosts.length * LANE_H + AXIS_H + 8;
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

  const parts = [];
  parts.push(`<svg viewBox="0 0 ${width} ${height}" height="${height}" ` +
             `preserveAspectRatio="none" role="img">`);

  // Time grid: five ticks, labelled with how long ago rather than a clock
  // time, because the question is always "how long between these".
  for (let i = 0; i <= 5; i++) {
    const t = from + (span * i) / 5;
    const gx = x(t).toFixed(1);
    parts.push(`<line class="gridline" x1="${gx}" y1="0" x2="${gx}" ` +
               `y2="${height - AXIS_H}"/>`);
    const ago = Math.round((now - t));
    parts.push(`<text x="${gx}" y="${height - 6}" text-anchor="${
      i === 0 ? "start" : i === 5 ? "end" : "middle"}">${
      ago === 0 ? "now" : "-" + duration(ago)}</text>`);
  }

  hosts.forEach((host, index) => {
    const top = index * LANE_H;
    parts.push(`<rect class="lane-bg" x="${LABEL_W}" y="${top + 4}" ` +
               `width="${plot}" height="${LANE_H - 10}" rx="2"/>`);
    parts.push(`<text class="lane-label" x="4" y="${top + 20}">${
      escape(host)}</text>`);

    const mine = commands.filter((s) => s.host === host && s.end > from);
    mine.forEach((segment, position) => {
      const x1 = x(segment.start), x2 = Math.max(x(segment.end), x(segment.start) + 2);
      parts.push(`<rect class="seg-command${segment.open ? " open" : ""}" ` +
                 `x="${x1.toFixed(1)}" y="${top + 10}" ` +
                 `width="${(x2 - x1).toFixed(1)}" height="14" rx="2">` +
                 `<title>${escape(segment.peer)} — ${
                   duration(Math.round(segment.end - segment.start))}${
                   segment.open ? ", still open" : ""}</title></rect>`);
      for (const at of segment.keepalives) {
        if (at < from) continue;
        parts.push(`<line class="tick-keepalive" x1="${x(at).toFixed(1)}" ` +
                   `y1="${top + 10}" x2="${x(at).toFixed(1)}" ` +
                   `y2="${top + 24}"/>`);
      }
      if (segment.died && segment.died > from) {
        parts.push(`<line class="tick-death" x1="${x(segment.died).toFixed(1)}" ` +
                   `y1="${top + 6}" x2="${x(segment.died).toFixed(1)}" ` +
                   `y2="${top + 28}"/>`);
      }
      // The gap to the previous connection, written on the chart: this is
      // the number a periodicity detection is looking for.
      const previous = mine[position - 1];
      if (previous && previous.end) {
        const gap = segment.start - previous.start;
        const mid = (x(previous.start) + x1) / 2;
        if (x1 - x(previous.start) > 34) {
          parts.push(`<text class="gap-label" x="${mid.toFixed(1)}" ` +
                     `y="${top + 36}" text-anchor="middle">${
                       Math.round(gap)}s</text>`);
        }
      }
    });

    for (const session of sessions) {
      if (session.host !== host || session.end < from) continue;
      const x1 = x(session.start);
      const x2 = Math.max(x(session.end), x1 + 2);
      parts.push(`<rect class="seg-session" x="${x1.toFixed(1)}" ` +
                 `y="${top + 28}" width="${(x2 - x1).toFixed(1)}" ` +
                 `height="9" rx="2"><title>${escape(session.key)} — ${
                   duration(Math.round(session.end - session.start))}` +
                 `</title></rect>`);
    }
  });

  parts.push("</svg>");
  chart.innerHTML = parts.join("");
}

/* -- helpers --------------------------------------------------------------- */

function duration(seconds) {
  seconds = Math.max(0, Math.round(seconds));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

const escape = (text) => String(text).replace(/[<>&"]/g, (c) =>
  ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" }[c]));

function renderAll() {
  if (model.server) {
    el("fact-command").textContent = `0.0.0.0:${model.server.command_port}`;
    el("fact-socks").textContent = `127.0.0.1:${model.server.socks_port}` +
      (model.server.socks_auth ? " (auth)" : "");
    el("fact-uptime").textContent = duration(model.server.uptime_seconds);
  }
  renderVerdict();
  renderFleet();
  renderFeed();
  renderTimeline();
  if (model.tab === "proxy") renderProxyLog();
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

el("tabs").onclick = (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  model.tab = button.dataset.tab;
  el("tabs").querySelectorAll("button").forEach(
    (b) => b.classList.toggle("on", b === button));
  el("tab-events").classList.toggle("hidden", model.tab !== "events");
  el("tab-proxy").classList.toggle("hidden", model.tab !== "proxy");
  if (model.tab === "proxy") renderProxyLog();
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
  await post("/api/note", { text: form.get("text") });
  event.target.reset();
};

el("theme").onclick = () => {
  const root = document.documentElement;
  const next = root.dataset.theme === "scope" ? "report" : "scope";
  root.dataset.theme = next;
  localStorage.setItem("theme", next);
};
document.documentElement.dataset.theme =
  localStorage.getItem("theme") || "scope";

window.addEventListener("resize", renderTimeline);

poll();
stream();
setInterval(poll, POLL_MS);
