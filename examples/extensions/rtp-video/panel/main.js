// H.264 video sent over RTP, played with WebCodecs. The RTP header is parsed here, the
// payload depacketized (RFC 6184: single NAL units, STAP-A, FU-A) into access units in
// Annex B form, and those decoded and drawn at the pace of their RTP timestamps.

const CLOCK = 90000;
/** Decoded pictures waiting to be drawn, plus chunks in the decoder. */
const AHEAD = 8;
const STATUS_MS = 500;
const LIVE_LOOK_MS = 2000;

// --- The panel's queries, in one place

/** The RTP streams Wireshark found; this extension's Lua decodes UDP port 5004 as RTP. */
async function listStreams() {
  const tap = await wb.tap("rtp-streams");
  return (tap?.streams ?? []).map((s) => ({ ...s, ssrc: Number(s.ssrc) }));
}

/** One stream's packets: the UDP payload, so RTP's own header too. */
function streamQuery(s) {
  const ip = s.ipver === 6 ? "ipv6" : "ip";
  return { filter: `${ip}.src == ${s.saddr} && udp.srcport == ${s.sport} && ${ip}.dst == ${s.daddr} && udp.dstport == ${s.dport}`, bytes: "payload" };
}

// --- Page

const $ = (sel) => document.querySelector(sel);
const picker = $(".streams");
const playButton = $(".play");
const seek = $(".seek");
const stateLine = $(".state");
const note = $(".note");
// Declared first: wb.canvas calls onResize before it returns
let ctx = null;
({ ctx } = wb.canvas({ parent: $(".screen"), onResize: () => draw() }));

let streams = [];
let stream = null;
let sub = null;
/** Bumped whenever the stream or capture changes: older async work drops its results. */
let generation = 0;

/** Access units in decoding order: {time (s), key, data (Annex B), first, last (frames)}. */
let units = [];
/** Unit index by chunk timestamp (µs). */
let byTime = new Map();
/** All of the stream read, as far as the file goes now. */
let complete = false;
let depack = null;
let decoder = null;
let codec = "";
/** Index of the next unit to decode, and of the picture shown. */
let next = 0;
let shown = -1;
/** Pictures before this unit are decoded but not drawn (after a seek). */
let skipUntil = 0;
/** The decoder was flushed at the end of the file (and then needs an IDR to go on). */
let flushing = null;
let drained = false;
let keyNeeded = false;
let queue = [];
let current = null;
let decoded = 0;
let playing = false;
/** performance.now() at the stream's time 0 while playing; the position in seconds when paused. */
let clockStart = 0;
let pausedAt = 0;

const hex2 = (n) => n.toString(16).padStart(2, "0");
const show = (text) => (note.textContent = text);
const micros = (u) => Math.round(u.time * 1e6);

// --- RTP and RFC 6184

function parseRtp(b) {
  if (b.length < 12 || b[0] >> 6 !== 2) return null;
  let at = 12 + 4 * (b[0] & 15);
  if (b[0] & 0x10) {
    if (b.length < at + 4) return null;
    at += 4 + 4 * ((b[at + 2] << 8) | b[at + 3]);
  }
  const end = b[0] & 0x20 ? b.length - b[b.length - 1] : b.length;
  if (at >= end) return null;
  return {
    marker: b[1] >> 7,
    seq: (b[2] << 8) | b[3],
    ts: ((b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7]) >>> 0,
    ssrc: ((b[8] << 24) | (b[9] << 16) | (b[10] << 8) | b[11]) >>> 0,
    payload: b.subarray(at, end),
  };
}

/** Turns one stream's RTP packets, in order, into access units. */
function depacketizer(onUnit) {
  let seq = null;
  let ts = null;
  let base = null;
  let ext = 0;
  let nals = [];
  let first = 0;
  let last = 0;
  let fu = null;
  /** After a loss, pictures wait for the next IDR. */
  let needKey = true;
  let lost = 0;
  const close = () => {
    const key = nals.some((n) => (n[0] & 31) === 5);
    if (key) needKey = false;
    if (nals.length && !needKey) {
      const data = new Uint8Array(nals.reduce((a, n) => a + 4 + n.length, 0));
      let at = 0;
      for (const n of nals) {
        data.set([0, 0, 0, 1], at);
        data.set(n, at + 4);
        at += 4 + n.length;
      }
      onUnit({ time: (ext - base) / CLOCK, key, data, first, last, sps: nals.find((n) => (n[0] & 31) === 7) ?? null });
    }
    nals = [];
    fu = null;
  };
  return {
    get lost() {
      return lost;
    },
    push(r, frame) {
      if (seq !== null && r.seq !== ((seq + 1) & 0xffff)) {
        lost += (r.seq - seq - 1) & 0xffff;
        nals = [];
        fu = null;
        needKey = true;
      }
      seq = r.seq;
      if (ts !== null && r.ts !== ts) close();
      // Timestamps wrap at 32 bits
      ext = ts === null ? r.ts : ext + ((r.ts - ts) | 0);
      base ??= ext;
      ts = r.ts;
      if (!nals.length && !fu) first = frame;
      last = frame;
      const p = r.payload;
      const type = p[0] & 31;
      if (type >= 1 && type <= 23) nals.push(p.slice());
      else if (type === 24) {
        // STAP-A: NAL units, each after its 16-bit size
        for (let at = 1; at + 2 <= p.length; ) {
          const n = (p[at] << 8) | p[at + 1];
          at += 2;
          if (at + n > p.length) break;
          nals.push(p.slice(at, at + n));
          at += n;
        }
      } else if (type === 28 && p.length > 2) {
        // FU-A: the NAL header rebuilt from the indicator's F and NRI and the fragment's type
        if (p[1] & 0x80) fu = [Uint8Array.of((p[0] & 0xe0) | (p[1] & 31))];
        if (fu) fu.push(p.slice(2));
        if (fu && p[1] & 0x40) {
          const nal = new Uint8Array(fu.reduce((a, x) => a + x.length, 0));
          fu.reduce((at, x) => (nal.set(x, at), at + x.length), 0);
          nals.push(nal);
          fu = null;
        }
      }
      if (r.marker) close();
    },
  };
}

// --- Decoding and drawing

async function makeDecoder(sps) {
  if (typeof VideoDecoder === "undefined") throw new Error("This browser has no H.264 decoder (no WebCodecs VideoDecoder).");
  // avc1.PPCCLL: profile, constraint flags and level from the SPS; Annex B needs no description
  codec = `avc1.${hex2(sps[1])}${hex2(sps[2])}${hex2(sps[3])}`;
  const config = { codec, optimizeForLatency: true };
  if (!(await VideoDecoder.isConfigSupported(config)).supported) throw new Error(`This browser has no H.264 decoder for ${codec}.`);
  const d = new VideoDecoder({
    output: (frame) => {
      const i = byTime.get(frame.timestamp) ?? -1;
      if (d !== decoder || i < skipUntil) return frame.close();
      decoded++;
      queue.push({ frame, i });
    },
    error: (e) => {
      if (d === decoder) show(`Decoding failed: ${e.message}`);
    },
  });
  d.configure(config);
  return d;
}

/** Decodes again from the IDR at or before unit `i`, drawing from `i` on. */
function restartAt(i) {
  for (const q of queue) q.frame.close();
  queue = [];
  let k = i;
  while (k > 0 && !units[k].key) k--;
  next = k;
  skipUntil = i;
  flushing = null;
  drained = keyNeeded = false;
  if (decoder?.state === "configured") {
    decoder.reset();
    decoder.configure({ codec, optimizeForLatency: true });
  }
}

function feed() {
  if (decoder?.state !== "configured") return;
  while (next < units.length && decoder.decodeQueueSize + queue.length < AHEAD) {
    const u = units[next++];
    if (keyNeeded && !u.key) continue;
    keyNeeded = drained = false;
    decoder.decode(new EncodedVideoChunk({ type: u.key ? "key" : "delta", timestamp: micros(u), data: u.data }));
  }
  // The end of the file: the decoder hands out the pictures it still holds
  if (next >= units.length && complete && !wb.view.live && !flushing && !drained) {
    const f = (flushing = decoder.flush().then(
      () => {
        if (flushing !== f) return;
        flushing = null;
        drained = keyNeeded = true;
      },
      () => {},
    ));
  }
}

function draw() {
  if (!ctx) return;
  const c = ctx.canvas;
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, c.width, c.height);
  if (!current) return;
  const w = current.displayWidth;
  const h = current.displayHeight;
  const scale = Math.min(c.width / w, c.height / h);
  ctx.drawImage(current, (c.width - w * scale) / 2, (c.height - h * scale) / 2, w * scale, h * scale);
}

/** Shows a decoded picture and closes the one before. */
function present(q) {
  current?.close();
  current = q.frame;
  shown = q.i;
  if (document.activeElement !== seek) seek.value = String(shown);
  draw();
}

function tick(g) {
  if (g !== generation) return;
  requestAnimationFrame(() => tick(g));
  feed();
  if (!playing) {
    if (queue.length && queue[0].i <= skipUntil) present(queue.shift());
    return;
  }
  const now = (performance.now() - clockStart) / 1000;
  while (queue.length && units[queue[0].i].time <= now) present(queue.shift());
  if (queue.length) return;
  if (drained) setPlaying(false);
  // Waiting for more of the stream: the clock waits too
  else if (next >= units.length && shown >= 0) clockStart = performance.now() - units[shown].time * 1000;
}

function setPlaying(on) {
  // Play at the end starts over
  if (on && drained && !queue.length) {
    restartAt(0);
    shown = -1;
    pausedAt = 0;
  }
  playing = on && !!decoder;
  if (playing) clockStart = performance.now() - pausedAt * 1000;
  else if (shown >= 0) pausedAt = units[shown].time;
  playButton.textContent = playing ? "Pause" : "Play";
}

let lastStatus = "";
function status() {
  const span = units.length > 1 ? units[units.length - 1].time - units[0].time : 0;
  const fps = span > 0 ? ((units.length - 1) / span).toFixed(1).replace(/\.0$/, "") : "?";
  const lost = depack?.lost ? ` · lost ${depack.lost} packets` : "";
  const at = shown >= 0 ? units[shown].time : 0;
  stateLine.textContent = `${shown + 1} / ${units.length} · ${wb.fmt.duration(at)} · ${fps} fps · ${decoded} decoded${lost}`;
  const text = `${units.length} pictures · ${fps} fps · ${codec || "H.264"}${lost}`;
  if (text !== lastStatus) wb.status(text);
  lastStatus = text;
}
setInterval(() => stream && status(), STATUS_MS);

// --- Streams and data

function stop() {
  generation++;
  sub?.close();
  sub = null;
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = null;
  for (const q of queue) q.frame.close();
  queue = [];
  current?.close();
  current = null;
  units = [];
  byTime = new Map();
  complete = false;
  next = 0;
  shown = -1;
  skipUntil = 0;
  flushing = null;
  drained = keyNeeded = false;
  decoded = 0;
  playing = false;
  pausedAt = 0;
  playButton.textContent = "Play";
  playButton.disabled = seek.disabled = true;
  seek.max = seek.value = "0";
  stateLine.textContent = "";
  draw();
}

function play(s) {
  stop();
  stream = s;
  const g = generation;
  tick(g);
  depack = depacketizer((u) => {
    byTime.set(micros(u), units.length);
    units.push(u);
  });
  let unsupported = false;
  let read = 0;
  show("Reading the stream…");
  sub = wb.subscribe(streamQuery(s), {
    async batch(page) {
      if (g !== generation) return;
      for (let i = 0; i < page.n; i++) {
        const r = parseRtp(page.bytes(i));
        if (r?.ssrc === s.ssrc) depack.push(r, page.frames[i]);
      }
      read += page.n;
      // An empty last page never comes here: the count tells too
      complete = !page.pending && (page.done || (page.total !== null && read >= page.total));
      if (!units.length) return;
      seek.max = String(units.length - 1);
      seek.disabled = false;
      if (!decoder && !unsupported) {
        const sps = units.find((u) => u.sps)?.sps;
        if (!sps) return show("Waiting for the stream's parameters (SPS)…");
        try {
          const d = await makeDecoder(sps);
          if (g !== generation) return d.close();
          decoder = d;
          playButton.disabled = false;
          show("");
          setPlaying(true);
        } catch (e) {
          unsupported = true;
          show(e.message);
          // The agent hears it too
          console.warn(e.message);
        }
      }
      status();
    },
  });
}

async function start() {
  stop();
  stream = null;
  streams = [];
  const g = generation;
  picker.replaceChildren();
  $(".live").hidden = !wb.view.live;
  if (!wb.view.file) return show("Open a capture with H.264 video over RTP.");
  try {
    streams = await listStreams();
  } catch (e) {
    if (["stale", "no-capture"].includes(e.code)) return;
    return show(`Could not list the RTP streams: ${e.message}`);
  }
  if (g !== generation) return;
  if (!streams.length) return show("No RTP streams yet. This extension decodes UDP port 5004 as RTP; for another port, change rtp-h264.lua.");
  for (const [i, s] of streams.entries()) {
    picker.append(wb.h("option", { value: String(i) }, `${s.saddr}:${s.sport} → ${s.daddr}:${s.dport} · SSRC 0x${s.ssrc.toString(16)} · ${s.payload} · ${s.pkts} packets`));
  }
  // The H.264 stream with the most packets
  let pick = 0;
  for (const [i, s] of streams.entries()) {
    const better = /h264/i.test(s.payload) && (!/h264/i.test(streams[pick].payload) || s.pkts > streams[pick].pkts);
    if (better) pick = i;
  }
  picker.value = String(pick);
  play(streams[pick]);
}

picker.addEventListener("change", () => play(streams[Number(picker.value)]));
playButton.addEventListener("click", () => setPlaying(!playing));
seek.addEventListener("input", () => {
  const i = Number(seek.value);
  restartAt(i);
  pausedAt = units[i]?.time ?? 0;
  if (playing) clockStart = performance.now() - pausedAt * 1000;
});
document.addEventListener("keydown", (e) => {
  if (e.key === " " && e.target === document.body && !playButton.disabled) {
    e.preventDefault();
    setPlaying(!playing);
  }
});

// A packet of this stream selected in WireBuddy: show its picture
wb.on("select", (frame) => {
  if (frame == null || !decoder) return;
  const i = units.findIndex((u) => frame >= u.first && frame <= u.last);
  if (i < 0) return;
  setPlaying(false);
  restartAt(i);
  pausedAt = units[i].time;
});
wb.on("view", (v) => ($(".live").hidden = !v.live));
wb.on("reset", start);
// A live capture: look for streams that start later
let liveTimer = 0;
wb.on("packets", () => {
  if (streams.length) return;
  clearTimeout(liveTimer);
  liveTimer = setTimeout(start, LIVE_LOOK_MS);
});

await start();
wb.ready();
