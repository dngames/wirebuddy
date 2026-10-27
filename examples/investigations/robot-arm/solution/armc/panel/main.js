// The arm's joints over capture time from ARMC telemetry (actual thick, target thin), and below
// them each MOVE at the time its first byte was sent, as high and as red as its wait for the ACK.
// The packets are parsed here, not by ../armc.lua: UDP telemetry as it is, the TCP commands put
// back together per direction, so a MOVE whose payload left after its header counts from the header.

/** From extension.json's params: the ports armc.lua decodes too. */
const PORT = Number(wb.params.port ?? 7700);
const TELEMETRY = Number(wb.params.telemetry ?? 7701);
const HEADER = 8;
const MOVE = 0x01;
const ACK = 0x81;
const NACK = 0x82;
/** Telemetry further apart breaks the lines. */
const GAP = 0.25;
/** The latency strip's log scale, in ms. */
const LAT_MIN = 0.01;
const LAT_MAX = 100;

// --- The panel's query, in one place

/** Commands and telemetry as IP packets, matched by WireBuddy in the file itself (fast)... */
const query = { match: { proto: ["tcp", "udp"], port: [PORT, TELEMETRY] }, bytes: "ip" };
/** ...or, in a file it can't read itself (a compressed one), by a display filter. */
const slowQuery = { filter: `tcp.port == ${PORT} || udp.port == ${TELEMETRY}`, bytes: "ip" };

// --- Page

const $ = (sel) => document.querySelector(sel);
const readout = $(".readout");
const note = $(".note");
// Before the canvas: its first resize draws
let drawPending = false;
const { canvas, ctx } = wb.canvas({ context: "2d", parent: $(".chart"), onResize: () => draw() });
canvas.title = "Wheel to zoom, drag to pan, double-click to see it all; a click selects the packet";

// --- Data

/** Telemetry: absolute times, frames, actual and target degrees per joint, flags. */
let tel;
/** MOVEs in order: {seq, t, tEnd, frame, firstFrame, j, speed, reply: {t, frame, nack, status, proc} | null, ms}. */
let moves;
/** Their times, for searching. */
let moveT;
/** Requests waiting for their reply, by direction and seq. */
let pending;
/** TCP reassembly per direction. */
let streams;
/** Time of frame 1, the zero of the time axis. */
let t0;
let bad;
let generation = 0;
let sub = null;

function clear() {
  tel = { t: [], frame: [], act: [[], [], []], tgt: [[], [], []], flags: [] };
  moves = [];
  moveT = [];
  pending = new Map();
  streams = new Map();
  t0 = null;
  bad = 0;
  zoom = null;
  hover = null;
}

const u16 = (b, i) => (b[i] << 8) | b[i + 1];
const u32 = (b, i) => ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
const i32 = (b, i) => (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3];

/** An IPv4 or IPv6 packet's TCP or UDP header and payload, or null. */
function parseIp(b) {
  let at;
  let end;
  let proto;
  let src;
  let dst;
  const version = b[0] >> 4;
  if (version === 4 && b.length >= 20) {
    // Fragments after the first have no ports
    if ((u16(b, 6) & 0x1fff) !== 0) return null;
    at = (b[0] & 15) * 4;
    end = Math.min(b.length, u16(b, 2) || b.length);
    proto = b[9];
    src = b.subarray(12, 16).join(".");
    dst = b.subarray(16, 20).join(".");
  } else if (version === 6 && b.length >= 40) {
    at = 40;
    end = Math.min(b.length, 40 + u16(b, 4));
    proto = b[6];
    const hex = (o) => Array.from({ length: 8 }, (_, i) => u16(b, o + i * 2).toString(16)).join(":");
    src = hex(8);
    dst = hex(24);
    // Hop-by-hop, routing and destination options; fragments are left out
    while ((proto === 0 || proto === 43 || proto === 60) && at + 8 <= end) {
      proto = b[at];
      at += (b[at + 1] + 1) * 8;
    }
  } else return null;
  if (proto === 6 && at + 20 <= end) {
    const off = (b[at + 12] >> 4) * 4;
    if (off < 20 || at + off > end) return null;
    return { tcp: true, src, dst, sport: u16(b, at), dport: u16(b, at + 2), seq: u32(b, at + 4), flags: b[at + 13], payload: b.subarray(at + off, end) };
  }
  if (proto === 17 && at + 8 <= end) {
    return { tcp: false, src, dst, sport: u16(b, at), dport: u16(b, at + 2), payload: b.subarray(at + 8, Math.min(end, at + u16(b, at + 4))) };
  }
  return null;
}

/** One direction of a TCP connection: its bytes in order, with the frame and time each part came in. */
class Stream {
  constructor() {
    this.next = null;
    this.buf = new Uint8Array(0);
    /** Where each part ends in buf, and its frame and time. */
    this.parts = [];
  }

  push(seq, flags, data, frame, time, onMessage) {
    // SYN: a new connection on these ports
    if (flags & 0x02) {
      this.next = (seq + 1) >>> 0;
      this.buf = new Uint8Array(0);
      this.parts = [];
      return;
    }
    if (!data.length) return;
    if (this.next === null) this.next = seq;
    let d = (seq - this.next) | 0;
    // Bytes lost (or a capture that began mid-stream): start over here
    if (d > 0) {
      this.buf = new Uint8Array(0);
      this.parts = [];
      this.next = seq;
      d = 0;
    }
    // Retransmitted: only what is new
    if (d < 0) {
      if (-d >= data.length) return;
      data = data.subarray(-d);
    }
    const buf = new Uint8Array(this.buf.length + data.length);
    buf.set(this.buf);
    buf.set(data, this.buf.length);
    this.buf = buf;
    this.parts.push({ end: buf.length, frame, time });
    this.next = (this.next + data.length) >>> 0;
    this.parse(onMessage);
  }

  partAt(offset) {
    return this.parts.find((p) => p.end > offset);
  }

  parse(onMessage) {
    const b = this.buf;
    let at = 0;
    while (b.length - at >= HEADER) {
      // Out of step: on to the next header
      if (b[at] !== 0x41 || b[at + 1] !== 0x4d || b[at + 2] !== 1) {
        at++;
        bad++;
        continue;
      }
      const end = at + HEADER + u16(b, at + 6);
      if (end > b.length) break;
      onMessage(b.subarray(at, end), this.partAt(at), this.partAt(end - 1));
      at = end;
    }
    if (!at) return;
    this.buf = b.slice(at);
    this.parts = this.parts.filter((p) => p.end > at).map((p) => ({ ...p, end: p.end - at }));
  }
}

function addPacket(b, frame, time) {
  const p = parseIp(b);
  if (!p) return;
  if (!p.tcp) {
    if (p.dport === TELEMETRY) addTelemetry(p.payload, frame, time);
    return;
  }
  if (p.dport !== PORT && p.sport !== PORT) return;
  const key = `${p.src}:${p.sport}>${p.dst}:${p.dport}`;
  const back = `${p.dst}:${p.dport}>${p.src}:${p.sport}`;
  let s = streams.get(key);
  if (!s) streams.set(key, (s = new Stream()));
  s.push(p.seq, p.flags, p.payload, frame, time, (m, first, last) => addMessage(m, first, last, key, back));
}

function addTelemetry(b, frame, time) {
  if (b.length < 36 || b[0] !== 0x41 || b[1] !== 0x54 || b[2] !== 1) return bad++;
  tel.t.push(time);
  tel.frame.push(frame);
  for (let j = 0; j < 3; j++) {
    tel.act[j].push(i32(b, 12 + j * 4) / 1000);
    tel.tgt[j].push(i32(b, 24 + j * 4) / 1000);
  }
  tel.flags.push(b[3]);
}

function addMessage(m, first, last, key, back) {
  const type = m[3];
  const seq = u16(m, 4);
  const len = m.length - HEADER;
  if (type < 0x80) {
    const req = { type, seq, t: first.time, tEnd: last.time, frame: last.frame, firstFrame: first.frame, reply: null, ms: null };
    pending.set(`${key}#${seq}`, req);
    if (type === MOVE && len >= 14) {
      req.j = [0, 1, 2].map((j) => i32(m, HEADER + j * 4) / 1000);
      req.speed = u16(m, HEADER + 12);
      moves.push(req);
      moveT.push(req.t);
    }
    return;
  }
  const req = pending.get(`${back}#${seq}`);
  if (!req) return;
  pending.delete(`${back}#${seq}`);
  req.reply = { t: last.time, frame: last.frame, nack: type === NACK, status: len >= 1 ? m[HEADER] : 0, proc: type === ACK && len >= 4 ? u16(m, HEADER + 2) : null };
  req.ms = (last.time - req.t) * 1000;
}

// --- Summary

/** p50 of the MOVEs' ACK latency (nearest rank) and their rate. */
function summary() {
  const ms = moves.filter((m) => m.ms !== null).map((m) => m.ms);
  if (!ms.length) return null;
  ms.sort((a, b) => a - b);
  const p50 = ms[Math.ceil(ms.length / 2) - 1];
  const span = moves.length > 1 ? moves[moves.length - 1].t - moves[0].t : 0;
  return { p50, rate: span > 0 ? (moves.length - 1) / span : 0, n: ms.length };
}

const fmtMs = (ms) => `${ms < 1 ? ms.toFixed(2) : ms.toFixed(1)} ms`;

function summaryText() {
  const s = summary();
  if (s) return `p50 ACK latency ${fmtMs(s.p50)} · ${Math.round(s.rate)} commands/s`;
  if (tel.t.length) return `No MOVE commands yet · ${tel.t.length} telemetry packet${tel.t.length === 1 ? "" : "s"}`;
  return "";
}

let statusTimer = 0;
let statusAt = 0;
/** The summary as last worked out: also drawn above the chart. */
let statusText = "";
/** The status line, at most twice a second. */
function status() {
  clearTimeout(statusTimer);
  const wait = statusAt + 500 - performance.now();
  if (wait > 0) return void (statusTimer = setTimeout(status, wait));
  statusAt = performance.now();
  const text = summaryText();
  if (text === statusText) return;
  statusText = text;
  wb.status(text);
  draw();
}

// --- Drawing

const dark = matchMedia("(prefers-color-scheme: dark)");
/** Validated categorical slots per theme, and the status colors for the latency. */
function theme() {
  const css = getComputedStyle(document.documentElement);
  const isDark = dark.matches;
  return {
    bg: css.getPropertyValue("--wb-bg").trim() || (isDark ? "#1e1f22" : "#ffffff"),
    ink: css.getPropertyValue("--wb-fg").trim() || (isDark ? "#dfe1e5" : "#1d1d1f"),
    muted: css.getPropertyValue("--wb-muted").trim() || "#898781",
    grid: isDark ? "#2c2c2a" : "#e1e0d9",
    axis: isDark ? "#383835" : "#c3c2b7",
    joints: isDark ? ["#3987e5", "#d95926", "#199e70"] : ["#2a78d6", "#eb6834", "#1baf7a"],
    good: "#0ca30c",
    warning: "#fab219",
    critical: "#d03b3b",
  };
}

const latencyColor = (c, m) => (m.reply?.nack || m.ms >= 20 ? c.critical : m.ms >= 5 ? c.warning : c.good);

/** Where things go, in CSS pixels. */
function layout() {
  const w = canvas.clientWidth;
  const h = canvas.clientHeight;
  const left = 52;
  const right = w - 40;
  const top = 46;
  const strip = Math.max(36, Math.min(80, h * 0.14));
  const bottom = h - 24;
  const stripTop = bottom - strip;
  const plotBottom = stripTop - 30;
  return { w, h, left, right, top, plotBottom, stripTop, bottom };
}

/** Times with data: all of it, or what is zoomed in. */
let zoom = null;
function fullRange() {
  let lo = Infinity;
  let hi = -Infinity;
  if (tel.t.length) [lo, hi] = [tel.t[0], tel.t[tel.t.length - 1]];
  if (moves.length) [lo, hi] = [Math.min(lo, moves[0].t), Math.max(hi, moves[moves.length - 1].t)];
  if (!Number.isFinite(lo)) return null;
  if (hi - lo < 0.05) hi = lo + 0.05;
  return [lo, hi];
}

function niceStep(span, count) {
  const raw = span / Math.max(1, count);
  const p = 10 ** Math.floor(Math.log10(raw));
  return [1, 2, 2.5, 5, 10].map((m) => m * p).find((s) => s >= raw) ?? 10 * p;
}

const lowerBound = (arr, x) => {
  let lo = 0;
  let hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
};

/** A line through ys over times, min and max per pixel column when the points are dense, broken at gaps. */
function trace(times, ys, i0, i1, X, Y, width) {
  ctx.beginPath();
  const dense = i1 - i0 > width * 2;
  let col = null;
  let lo = 0;
  let hi = 0;
  let prev = -Infinity;
  const flush = () => {
    if (col !== null) {
      ctx.lineTo(col, lo);
      ctx.lineTo(col, hi);
    }
    col = null;
  };
  for (let i = i0; i < i1; i++) {
    const x = X(times[i]);
    const y = Y(ys[i]);
    const gap = times[i] - prev > GAP;
    prev = times[i];
    if (!dense || gap) {
      flush();
      if (gap) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
      continue;
    }
    const c = Math.round(x);
    if (c !== col) {
      flush();
      col = c;
      lo = hi = y;
      ctx.lineTo(c, y);
    } else {
      lo = Math.min(lo, y);
      hi = Math.max(hi, y);
    }
  }
  flush();
  ctx.stroke();
}

function draw() {
  if (drawPending) return;
  drawPending = true;
  requestAnimationFrame(() => {
    drawPending = false;
    paint();
  });
}

/** The scales of the last paint, for hovering and clicking. */
let view = null;

function paint() {
  const c = theme();
  const dpr = canvas.width / Math.max(1, canvas.clientWidth);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = c.bg;
  ctx.fillRect(0, 0, canvas.clientWidth, canvas.clientHeight);
  const full = fullRange();
  if (!full) return void (view = null);
  const L = layout();
  const [a, b] = zoom ?? full;
  const X = (t) => L.left + ((t - a) / (b - a)) * (L.right - L.left);
  const i0 = Math.max(0, lowerBound(tel.t, a) - 1);
  const i1 = Math.min(tel.t.length, lowerBound(tel.t, b) + 1);

  // Joint range of what is in view, with room
  let lo = Infinity;
  let hi = -Infinity;
  for (let j = 0; j < 3; j++) {
    for (let i = i0; i < i1; i++) {
      lo = Math.min(lo, tel.act[j][i], tel.tgt[j][i]);
      hi = Math.max(hi, tel.act[j][i], tel.tgt[j][i]);
    }
  }
  if (!Number.isFinite(lo)) [lo, hi] = [-10, 10];
  if (hi - lo < 2) [lo, hi] = [(lo + hi) / 2 - 1, (lo + hi) / 2 + 1];
  const pad = (hi - lo) * 0.06;
  [lo, hi] = [lo - pad, hi + pad];
  const Y = (v) => L.plotBottom - ((v - lo) / (hi - lo)) * (L.plotBottom - L.top);
  const latY = (ms) => L.bottom - ((Math.log10(Math.min(LAT_MAX, Math.max(LAT_MIN, ms))) - Math.log10(LAT_MIN)) / Math.log10(LAT_MAX / LAT_MIN)) * (L.bottom - L.stripTop);
  view = { L, a, b, X, Y, latY };

  ctx.font = "11px system-ui, sans-serif";
  ctx.textBaseline = "middle";
  // Grid and axes
  ctx.lineWidth = 1;
  const yStep = niceStep(hi - lo, Math.max(2, Math.floor((L.plotBottom - L.top) / 50)));
  ctx.textAlign = "right";
  for (let v = Math.ceil(lo / yStep) * yStep; v <= hi; v += yStep) {
    const y = Math.round(Y(v)) + 0.5;
    ctx.strokeStyle = Math.abs(v) < yStep / 1e6 ? c.axis : c.grid;
    ctx.beginPath();
    ctx.moveTo(L.left, y);
    ctx.lineTo(L.right, y);
    ctx.stroke();
    ctx.fillStyle = c.muted;
    ctx.fillText(`${+v.toFixed(6)}°`, L.left - 6, y);
  }
  const xStep = niceStep(b - a, Math.max(2, Math.floor((L.right - L.left) / 90)));
  ctx.textAlign = "center";
  const digits = Math.max(0, -Math.floor(Math.log10(xStep) + 1e-9));
  for (let t = Math.ceil((a - t0) / xStep) * xStep; t <= b - t0; t += xStep) {
    const x = Math.round(X(t + t0)) + 0.5;
    ctx.strokeStyle = c.grid;
    ctx.beginPath();
    ctx.moveTo(x, L.top);
    ctx.lineTo(x, L.plotBottom);
    ctx.moveTo(x, L.stripTop);
    ctx.lineTo(x, L.bottom);
    ctx.stroke();
    ctx.fillStyle = c.muted;
    ctx.fillText(`${t.toFixed(digits)} s`, x, L.bottom + 12);
  }
  // The strip's decades
  ctx.textAlign = "right";
  for (const ms of [0.1, 1, 10]) {
    const y = Math.round(latY(ms)) + 0.5;
    ctx.strokeStyle = c.grid;
    ctx.beginPath();
    ctx.moveTo(L.left, y);
    ctx.lineTo(L.right, y);
    ctx.stroke();
    ctx.fillStyle = c.muted;
    ctx.fillText(`${ms} ms`, L.left - 6, y);
  }
  ctx.strokeStyle = c.axis;
  ctx.beginPath();
  ctx.moveTo(L.left, L.plotBottom + 0.5);
  ctx.lineTo(L.right, L.plotBottom + 0.5);
  ctx.moveTo(L.left, L.bottom + 0.5);
  ctx.lineTo(L.right, L.bottom + 0.5);
  ctx.stroke();

  // Joints: target thin under actual thick
  ctx.save();
  ctx.beginPath();
  ctx.rect(L.left, L.top - 2, L.right - L.left, L.plotBottom - L.top + 4);
  ctx.clip();
  ctx.lineJoin = "round";
  ctx.globalAlpha = 0.75;
  ctx.lineWidth = 1;
  for (let j = 0; j < 3; j++) {
    ctx.strokeStyle = c.joints[j];
    trace(tel.t, tel.tgt[j], i0, i1, X, Y, L.right - L.left);
  }
  ctx.globalAlpha = 1;
  ctx.lineWidth = 2;
  for (let j = 0; j < 3; j++) {
    ctx.strokeStyle = c.joints[j];
    trace(tel.t, tel.act[j], i0, i1, X, Y, L.right - L.left);
  }
  ctx.restore();
  // Direct labels at the lines' ends, kept apart
  if (i1 > i0) {
    const ends = [0, 1, 2].map((j) => ({ j, y: Y(tel.act[j][i1 - 1]) })).sort((p, q) => p.y - q.y);
    for (let k = 1; k < ends.length; k++) ends[k].y = Math.max(ends[k].y, ends[k - 1].y + 13);
    ctx.textAlign = "left";
    for (const e of ends) {
      ctx.fillStyle = c.joints[e.j];
      ctx.fillRect(L.right + 5, Math.min(L.plotBottom, Math.max(L.top, e.y)) - 1.5, 8, 3);
      ctx.fillStyle = c.ink;
      ctx.fillText(`J${e.j + 1}`, L.right + 16, Math.min(L.plotBottom, Math.max(L.top, e.y)));
    }
  }

  // MOVEs: per pixel column the slowest
  const m0 = lowerBound(moveT, a);
  const cols = new Map();
  for (let i = m0; i < moves.length && moves[i].t <= b; i++) {
    const m = moves[i];
    const x = Math.round(X(m.t));
    const worst = cols.get(x);
    const rank = (n) => (n.reply ? (n.reply.nack ? Infinity : n.ms) : -1);
    if (!worst || rank(m) > rank(worst)) cols.set(x, m);
  }
  for (const [x, m] of cols) {
    if (!m.reply) {
      ctx.fillStyle = c.muted;
      ctx.fillRect(x - 1, L.bottom - 4, 2, 4);
      continue;
    }
    const y = m.reply.nack ? L.stripTop : latY(m.ms);
    ctx.fillStyle = latencyColor(c, m);
    ctx.fillRect(x - 1, y, 2, L.bottom - y);
  }

  // Hover: a crosshair, the MOVE under it ringed
  if (hover) {
    ctx.strokeStyle = c.muted;
    ctx.lineWidth = 1;
    ctx.setLineDash([3, 3]);
    const x = Math.round(hover.x) + 0.5;
    ctx.beginPath();
    ctx.moveTo(x, L.top);
    ctx.lineTo(x, L.plotBottom);
    ctx.moveTo(x, L.stripTop);
    ctx.lineTo(x, L.bottom);
    ctx.stroke();
    ctx.setLineDash([]);
    if (hover.move) {
      const m = hover.move;
      const mx = X(m.t);
      ctx.strokeStyle = c.ink;
      ctx.strokeRect(Math.round(mx) - 3.5, L.stripTop - 0.5, 7, L.bottom - L.stripTop + 1);
    }
  }

  // Legends: joints and what thick and thin mean; the summary; the latency colors
  ctx.textAlign = "left";
  ctx.font = "12px system-ui, sans-serif";
  let x = L.left;
  const y1 = 16;
  for (let j = 0; j < 3; j++) {
    ctx.fillStyle = c.joints[j];
    ctx.fillRect(x, y1 - 1.5, 14, 3);
    ctx.fillStyle = c.ink;
    ctx.fillText(`J${j + 1}`, x + 18, y1);
    x += 18 + ctx.measureText(`J${j + 1}`).width + 14;
  }
  ctx.fillStyle = c.muted;
  ctx.fillRect(x, y1 - 1, 14, 2);
  ctx.fillText("actual", x + 18, y1);
  x += 18 + ctx.measureText("actual").width + 12;
  ctx.globalAlpha = 0.75;
  ctx.fillRect(x, y1 - 0.5, 14, 1);
  ctx.globalAlpha = 1;
  ctx.fillText("target (degrees)", x + 18, y1);
  ctx.textAlign = "right";
  ctx.font = "600 12px system-ui, sans-serif";
  ctx.fillStyle = c.ink;
  ctx.fillText(statusText, L.right, y1);
  ctx.font = "11px system-ui, sans-serif";
  ctx.fillStyle = c.muted;
  const skipped = bad ? `${bad} malformed bytes or packets skipped · ` : "";
  ctx.fillText(skipped + (zoom ? "zoomed in · double-click to see it all" : "wheel to zoom · drag to pan · click to select the packet"), L.right, y1 + 16);

  const y2 = L.stripTop - 12;
  ctx.textAlign = "left";
  ctx.fillStyle = c.ink;
  ctx.fillText("MOVE → ACK latency, from the MOVE's first byte (log scale)", L.left, y2);
  ctx.textAlign = "right";
  let rx = L.right;
  for (const [label, color] of [
    ["≥ 20 ms or NACK", c.critical],
    ["5–20 ms", c.warning],
    ["< 5 ms", c.good],
  ]) {
    ctx.fillStyle = c.ink;
    ctx.fillText(label, rx, y2);
    rx -= ctx.measureText(label).width + 6;
    ctx.fillStyle = color;
    ctx.fillRect(rx - 8, y2 - 4, 8, 8);
    rx -= 22;
  }
}

// --- Hover, zoom, pan, click

let hover = null;

/** The MOVE nearest x within a few pixels, or null. */
function moveAt(x) {
  if (!view || !moves.length) return null;
  const t = view.a + ((x - view.L.left) / (view.L.right - view.L.left)) * (view.b - view.a);
  const i = lowerBound(moveT, t);
  let best = null;
  for (const k of [i - 1, i]) {
    const m = moves[k];
    if (m && Math.abs(view.X(m.t) - x) <= 6 && (!best || Math.abs(m.t - t) < Math.abs(best.t - t))) best = m;
  }
  return best;
}

/** The telemetry sample nearest x, or -1. */
function telemetryAt(x) {
  if (!view || !tel.t.length) return -1;
  const t = view.a + ((x - view.L.left) / (view.L.right - view.L.left)) * (view.b - view.a);
  const i = lowerBound(tel.t, t);
  if (i <= 0) return 0;
  if (i >= tel.t.length) return tel.t.length - 1;
  return t - tel.t[i - 1] < tel.t[i] - t ? i - 1 : i;
}

const deg = (v) => `${v.toFixed(2)}°`;
const line = (...children) => wb.h("div", {}, ...children);
const muted = (text) => wb.h("span", { class: "muted" }, text);

function showReadout(px, py) {
  const L = view.L;
  const inStrip = py >= L.stripTop - 20;
  const m = moveAt(px);
  hover = { x: px, move: m && (inStrip || !tel.t.length) ? m : null };
  const rows = [];
  if (hover.move) {
    const mv = hover.move;
    rows.push(line(wb.h("span", { class: "head" }, `MOVE seq=${mv.seq}`), muted(` · frame ${mv.frame}${mv.firstFrame !== mv.frame ? `, began in ${mv.firstFrame}` : ""}`)));
    rows.push(line(`j1 ${deg(mv.j[0])}  j2 ${deg(mv.j[1])}  j3 ${deg(mv.j[2])} · ${mv.speed} °/s`));
    rows.push(line(muted(`sent at ${(mv.t - t0).toFixed(4)} s`)));
    if (mv.tEnd - mv.t > 0.0005) rows.push(line(`its last byte left ${fmtMs((mv.tEnd - mv.t) * 1000)} after its first`));
    if (mv.reply) {
      const r = mv.reply;
      rows.push(line(`${r.nack ? "NACK" : "ACK"} in frame ${r.frame}, ${fmtMs(mv.ms)} after the first byte`));
      rows.push(line(muted(`${fmtMs((r.t - mv.tEnd) * 1000)} after the last${r.proc !== null ? ` · the device took ${(r.proc / 1000).toFixed(3)} ms` : ""}`)));
    } else rows.push(line(muted("no ACK in the capture")));
    rows.push(line(muted("click: select the MOVE")));
  } else {
    const i = telemetryAt(px);
    if (i < 0) return hideReadout();
    const c = theme();
    const f = tel.flags[i];
    rows.push(line(wb.h("span", { class: "head" }, `${(tel.t[i] - t0).toFixed(4)} s`), muted(` · telemetry frame ${tel.frame[i]}${f & 1 ? " · moving" : f & 2 ? " · reached" : ""}`)));
    for (let j = 0; j < 3; j++) {
      rows.push(line(wb.h("span", { class: "swatch", style: { background: c.joints[j] } }), `J${j + 1}  ${deg(tel.act[j][i])}`, muted(`  target ${deg(tel.tgt[j][i])}`)));
    }
    rows.push(line(muted("click: select this telemetry packet")));
  }
  readout.replaceChildren(...rows);
  readout.hidden = false;
  const r = readout.getBoundingClientRect();
  const left = px + 14 + r.width > L.w ? px - 14 - r.width : px + 14;
  const top = Math.min(L.h - r.height - 4, Math.max(4, py - r.height / 2));
  readout.style.left = `${Math.max(4, left)}px`;
  readout.style.top = `${top}px`;
  draw();
}

function hideReadout() {
  readout.hidden = true;
  if (hover) {
    hover = null;
    draw();
  }
}

let drag = null;
canvas.addEventListener("pointerdown", (e) => {
  drag = { x: e.clientX, moved: false, range: zoom ?? fullRange() };
  canvas.setPointerCapture(e.pointerId);
});
canvas.addEventListener("pointermove", (e) => {
  const r = canvas.getBoundingClientRect();
  if (drag?.range && view) {
    const dx = e.clientX - drag.x;
    if (Math.abs(dx) > 3) drag.moved = true;
    if (drag.moved) {
      const full = fullRange();
      const span = drag.range[1] - drag.range[0];
      // Panning only means something when zoomed in
      if (full && span < full[1] - full[0]) {
        canvas.classList.add("panning");
        const dt = (-dx / (view.L.right - view.L.left)) * span;
        const a = Math.max(full[0], Math.min(full[1] - span, drag.range[0] + dt));
        zoom = [a, a + span];
      }
    }
  }
  if (view) showReadout(e.clientX - r.left, e.clientY - r.top);
});
canvas.addEventListener("pointerup", (e) => {
  const d = drag;
  drag = null;
  canvas.classList.remove("panning");
  if (!d || d.moved || !view) return;
  const r = canvas.getBoundingClientRect();
  const px = e.clientX - r.left;
  const m = hover?.move;
  const i = telemetryAt(px);
  const frame = m ? m.frame : i >= 0 ? tel.frame[i] : null;
  if (frame) wb.select(frame).catch(() => {});
});
canvas.addEventListener("pointerleave", () => {
  if (!drag) hideReadout();
});
canvas.addEventListener(
  "wheel",
  (e) => {
    e.preventDefault();
    const full = fullRange();
    if (!full || !view) return;
    const [a, b] = zoom ?? full;
    const r = canvas.getBoundingClientRect();
    const at = a + ((e.clientX - r.left - view.L.left) / (view.L.right - view.L.left)) * (b - a);
    const span = Math.min(full[1] - full[0], Math.max(0.02, (b - a) * Math.exp(e.deltaY * 0.0015)));
    if (span >= full[1] - full[0]) zoom = null;
    else {
      const lo = Math.max(full[0], Math.min(full[1] - span, at - ((at - a) / (b - a)) * span));
      zoom = [lo, lo + span];
    }
    draw();
  },
  { passive: false },
);
canvas.addEventListener("dblclick", () => {
  zoom = null;
  draw();
});

// --- Reading

let isReady = false;
/** Tells WireBuddy the panel works, once there is something to see (or nothing to wait for). */
const ready = () => {
  if (!isReady) wb.ready();
  isReady = true;
};

function message(text) {
  note.textContent = text;
  note.hidden = !text;
}

/** The time of frame 1, so times read as in WireBuddy's Time column. */
async function firstTime(page) {
  try {
    const p = await wb.packets({ frames: [[1, 1]], epoch: page.epoch });
    if (p.n) return p.times[0];
  } catch {
    // another capture by now: the reset that follows starts over
  }
  return page.times[0];
}

function start() {
  generation++;
  const g = generation;
  sub?.close();
  clear();
  if (statusText) wb.status((statusText = ""));
  hideReadout();
  draw();
  if (!wb.view.file) {
    message(`Open a capture with ARMC traffic: commands on TCP port ${PORT}, telemetry on UDP port ${TELEMETRY}.`);
    return ready();
  }
  message("Reading the ARMC traffic…");
  setTimeout(() => {
    if (g !== generation || tel.t.length || moves.length) return;
    message(`No ARMC traffic in this capture yet (TCP port ${PORT}, UDP port ${TELEMETRY}).`);
    ready();
  }, 3000);
  const handlers = {
    async batch(page) {
      if (g !== generation) return;
      if (t0 === null) t0 = await firstTime(page);
      if (g !== generation) return;
      for (let i = 0; i < page.n; i++) addPacket(page.bytes(i), page.frames[i], page.times[i]);
      if (!tel.t.length && !moves.length) return;
      message("");
      status();
      draw();
      ready();
    },
    error(e) {
      if (g === generation && e.code === "bad-args" && /^match /.test(e.message)) sub = wb.subscribe(slowQuery, handlers);
    },
  };
  sub = wb.subscribe(query, handlers);
}

// A telemetry packet or a MOVE's (or its ACK's) selected in WireBuddy: the crosshair there
wb.on("select", (frame) => {
  if (frame == null || !view) return;
  const m = moves.find((x) => x.frame === frame || x.firstFrame === frame || x.reply?.frame === frame);
  const i = m ? -1 : lowerBound(tel.frame, frame);
  if (!m && tel.frame[i] !== frame) return;
  hover = { x: view.X(m ? m.t : tel.t[i]), move: m ?? null };
  readout.hidden = true;
  draw();
});
wb.on("theme", () => draw());
wb.on("reset", start);
start();
