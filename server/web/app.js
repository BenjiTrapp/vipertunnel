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
const LANE_H = 52;
const AXIS_H = 24;
const NS = "http://www.w3.org/2000/svg";

const model = {
  server: null,
  knob: null,
  clients: [],
  sessions: [],
  cadence: [],
  totals: {},
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
      totals: state.totals || {},
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
  };
}

const setFeedStatus = (text) => { el("m-feed").textContent = "feed: " + text; };

async function post(route, body) {
  const response = await fetch(route, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return response.json();
}

/* -- the hero -------------------------------------------------------------- */

/* The busiest host is the one whose numbers go in the headline. With one
 * implant, which is the usual case, it is the only one. */
const busiest = () =>
  model.cadence.slice().sort((a, b) => b.connections - a.connections)[0];

function renderHero() {
  if (!model.knob) return;
  const held = model.knob.held;
  const best = busiest();

  el("hero-cv").textContent =
    best && best.cv !== null ? best.cv.toFixed(3) : "—";

  el("shape-line").textContent = held
    ? "One held connection. A proxy logs a single CONNECT and a byte count."
    : `A reconnect every ~${model.knob.client_timeout} s, which is the client's read deadline.`;

  /* The predicted shape and the measured one are two different claims, and
   * they do come apart: reading an announced relay port resets the command
   * connection's read deadline, so traffic during a run loosens the cadence
   * the setting alone would produce. Saying only the prediction would hide
   * exactly that. */
  let why = held
    ? "No cadence here for a periodicity detection to find — a result worth having, not a failed run. Run the other position too; the pair is the finding."
    : "The server never sends a keep-alive, so the client's read times out and it builds a new connection.";
  if (best && best.cv !== null) {
    why += ` Measured on ${best.host}: ${best.verdict}.`;
    if (!held && best.cv >= 0.05) {
      why += " The measurement disagrees with the setting — a relay session resets the read deadline.";
    }
  }
  el("shape-why").textContent = why;

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
    el("cmdline").textContent =
      `server.py --port ${model.server.command_port}` +
      ` --socks ${model.server.socks_port}` +
      ` --keepalive ${model.knob.keepalive}` +
      ` --dashboard ${location.port || 8787}`;
  }
}

function renderTicker() {
  const best = busiest();
  const totals = model.totals;

  el("m-conns").textContent = totals.connections || 0;
  el("m-conns-d").textContent = totals.deaths
    ? `${totals.deaths} ended, ${model.clients.length} open`
    : "none have ended yet";

  el("m-mean").textContent =
    best && best.mean !== null ? `${best.mean} s` : "—";
  el("m-mean-d").textContent = best && best.stdev !== null
    ? `± ${best.stdev} s standard deviation`
    : "needs two gaps";

  el("m-fleet").textContent = model.clients.length;
  el("m-fleet-d").textContent = model.clients.length
    ? model.clients.map((c) => c.host).join(", ")
    : "no command channel open";

  el("m-sessions").textContent = model.sessions.length;
  el("m-sessions-d").textContent = totals.sessions
    ? `${totals.sessions} opened so far, one port each`
    : "one five-digit port each";
  el("m-ka").textContent = totals.keepalives || 0;
  el("m-uptime").textContent =
    model.server ? duration(model.server.uptime_seconds) : "—";
}

/* -- fleet and sessions ---------------------------------------------------- */

function renderFleet() {
  const body = el("fleet").querySelector("tbody");
  body.textContent = "";
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

  const sessions = el("sessions").querySelector("tbody");
  sessions.textContent = "";
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
  const height = hosts.length * LANE_H + AXIS_H + 10;
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

  const bars = svgEl("g", { filter: "url(#tl-glow)" }, svg);
  const lanes = new Map();

  hosts.forEach((host, index) => {
    const top = index * LANE_H;
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
        height: 9, fill: "url(#g-sess)",
      }, bars);
    }
  });

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
  renderHero();
  renderTicker();
  renderFleet();
  renderFeed();
  renderProxyLog();
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
setInterval(poll, POLL_MS);
