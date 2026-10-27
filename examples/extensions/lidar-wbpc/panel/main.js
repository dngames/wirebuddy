// Scans of the wbpc lidar protocol (see ../wbpc.lua) as a point cloud in WebGL2. Packets
// are parsed here, each scan's parts put together, and the point records uploaded to the
// GPU as they are: i16 x, y, z in cm, u8 intensity, u8 ring, 8 bytes each.

/** From extension.json's params: the port wbpc.lua decodes too. */
const PORT = Number(wb.params.port ?? 7502);
const HEADER = 16;
const RECORD = 8;
const PER_PACKET = 172;
/** Scans kept; older ones are dropped. */
const MAX_SCANS = 1000;

// --- The panel's query, in one place

/** The sensor's packets: their UDP payload. */
const query = { filter: `udp.dstport == ${PORT}`, bytes: "payload" };

// --- Page

const $ = (sel) => document.querySelector(sel);
const scrub = $(".scrub");
const playButton = $(".play");
const colorBy = $(".color");
const info = $(".scan");

/** Scans in the order they came: {id, parts, counts, got, data, first, last, time}. */
let scans = [];
let byId = new Map();
let index = -1;
let playing = false;
/** Following the newest scan of a live capture. */
let follow = true;
let bad = 0;
let generation = 0;
let isReady = false;
/** Tells WireBuddy the panel works, once there is something to see (or nothing to wait for). */
const ready = () => {
  if (!isReady) wb.ready();
  isReady = true;
};
let statusTimer = 0;
let statusAt = 0;
/** The status line, at most twice a second. */
function status(text) {
  clearTimeout(statusTimer);
  const wait = statusAt + 500 - performance.now();
  if (wait > 0) return void (statusTimer = setTimeout(() => status(text), wait));
  statusAt = performance.now();
  wb.status(text);
}

// --- WebGL

let gl = null;
try {
  ({ gl } = wb.canvas({ context: "webgl2", parent: $(".view"), onResize: () => render() }));
} catch (e) {
  info.textContent = `This browser has no WebGL2: ${e.message}`;
}

function program(vs, fs) {
  const p = gl.createProgram();
  for (const [type, src] of [
    [gl.VERTEX_SHADER, vs],
    [gl.FRAGMENT_SHADER, fs],
  ]) {
    const s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
    gl.attachShader(p, s);
  }
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p));
  return p;
}

const pointsVs = `#version 300 es
layout(location = 0) in vec3 pos;
layout(location = 1) in float intensity;
layout(location = 2) in float ring;
uniform mat4 mvp;
uniform int mode;
uniform vec2 zRange;
uniform float size;
out vec3 color;
vec3 ramp(float t) {
  t = clamp(t, 0.0, 1.0) * 4.0;
  vec3 c0 = vec3(0.20, 0.25, 0.65), c1 = vec3(0.10, 0.65, 0.90), c2 = vec3(0.35, 0.85, 0.40), c3 = vec3(0.98, 0.85, 0.25), c4 = vec3(0.95, 0.30, 0.20);
  return t < 1.0 ? mix(c0, c1, t) : t < 2.0 ? mix(c1, c2, t - 1.0) : t < 3.0 ? mix(c2, c3, t - 2.0) : mix(c3, c4, t - 3.0);
}
void main() {
  vec3 p = pos * 0.01;
  gl_Position = mvp * vec4(p, 1.0);
  gl_PointSize = clamp(size / gl_Position.w, 1.5, 6.0);
  float t = mode == 0 ? intensity : mode == 1 ? (p.z - zRange.x) / max(zRange.y - zRange.x, 0.1) : fract(ring * 0.618);
  color = ramp(t);
}`;
const pointsFs = `#version 300 es
precision mediump float;
in vec3 color;
out vec4 outColor;
void main() {
  vec2 d = gl_PointCoord - 0.5;
  if (dot(d, d) > 0.25) discard;
  outColor = vec4(color, 1.0);
}`;
const linesVs = `#version 300 es
layout(location = 0) in vec3 pos;
layout(location = 1) in vec4 rgba;
uniform mat4 mvp;
out vec4 color;
void main() {
  gl_Position = mvp * vec4(pos, 1.0);
  color = rgba;
}`;
const linesFs = `#version 300 es
precision mediump float;
in vec4 color;
out vec4 outColor;
void main() {
  outColor = color;
}`;

let points = null;
let lines = null;
if (gl) {
  points = { prog: program(pointsVs, pointsFs), vao: gl.createVertexArray(), buf: gl.createBuffer(), count: 0, zRange: [0, 1] };
  points.u = Object.fromEntries(["mvp", "mode", "zRange", "size"].map((n) => [n, gl.getUniformLocation(points.prog, n)]));
  gl.bindVertexArray(points.vao);
  gl.bindBuffer(gl.ARRAY_BUFFER, points.buf);
  // The records as they came: three shorts, intensity normalized to 0..1, the ring as a number
  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0, 3, gl.SHORT, false, RECORD, 0);
  gl.enableVertexAttribArray(1);
  gl.vertexAttribPointer(1, 1, gl.UNSIGNED_BYTE, true, RECORD, 6);
  gl.enableVertexAttribArray(2);
  gl.vertexAttribPointer(2, 1, gl.UNSIGNED_BYTE, false, RECORD, 7);

  lines = { prog: program(linesVs, linesFs), vao: gl.createVertexArray(), buf: gl.createBuffer(), count: 0, ground: NaN };
  lines.mvp = gl.getUniformLocation(lines.prog, "mvp");
  gl.bindVertexArray(lines.vao);
  gl.bindBuffer(gl.ARRAY_BUFFER, lines.buf);
  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0, 3, gl.FLOAT, false, 28, 0);
  gl.enableVertexAttribArray(1);
  gl.vertexAttribPointer(1, 4, gl.FLOAT, false, 28, 12);
  gl.bindVertexArray(null);
}

/** A 1 m grid on the ground (metres) and the sensor's axes. */
function groundLines(z) {
  const v = [];
  const line = (a, b, c) => v.push(...a, ...c, ...b, ...c);
  const grid = [0.6, 0.65, 0.7, 0.18];
  for (let i = -20; i <= 20; i++) {
    line([i, -20, z], [i, 20, z], grid);
    line([-20, i, z], [20, i, z], grid);
  }
  line([0, 0, 0], [1, 0, 0], [1, 0.3, 0.3, 1]);
  line([0, 0, 0], [0, 1, 0], [0.3, 1, 0.3, 1]);
  line([0, 0, 0], [0, 0, 1], [0.4, 0.6, 1, 1]);
  return new Float32Array(v);
}

// --- Camera: orbiting a target, z up

const home = { yaw: -2.3, pitch: 0.55, dist: 22, target: [0, 0, 0] };
const cam = structuredClone(home);

function perspective(fovy, aspect, near, far) {
  const f = 1 / Math.tan(fovy / 2);
  const nf = 1 / (near - far);
  return [f / aspect, 0, 0, 0, 0, f, 0, 0, 0, 0, (far + near) * nf, -1, 0, 0, 2 * far * near * nf, 0];
}

function lookAt(eye, at) {
  const sub = (a, b) => a.map((x, i) => x - b[i]);
  const norm = (a) => a.map((x) => x / Math.hypot(...a));
  const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
  const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
  const z = norm(sub(eye, at));
  const x = norm(cross([0, 0, 1], z));
  const y = cross(z, x);
  return [x[0], y[0], z[0], 0, x[1], y[1], z[1], 0, x[2], y[2], z[2], 0, -dot(x, eye), -dot(y, eye), -dot(z, eye), 1];
}

function multiply(a, b) {
  const out = new Float32Array(16);
  for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) for (let k = 0; k < 4; k++) out[c * 4 + r] += a[k * 4 + r] * b[c * 4 + k];
  return out;
}

const eye = () => {
  const { yaw, pitch, dist, target } = cam;
  return [target[0] + dist * Math.cos(pitch) * Math.cos(yaw), target[1] + dist * Math.cos(pitch) * Math.sin(yaw), target[2] + dist * Math.sin(pitch)];
};

// --- Drawing

let pending = false;
function render() {
  if (!gl || pending) return;
  pending = true;
  requestAnimationFrame(() => {
    pending = false;
    const c = gl.canvas;
    gl.viewport(0, 0, c.width, c.height);
    gl.clearColor(0.07, 0.08, 0.1, 1);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
    const mvp = multiply(perspective(0.9, c.width / c.height, 0.1, 500), lookAt(eye(), cam.target));
    if (lines.count) {
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.disable(gl.DEPTH_TEST);
      gl.useProgram(lines.prog);
      gl.uniformMatrix4fv(lines.mvp, false, mvp);
      gl.bindVertexArray(lines.vao);
      gl.drawArrays(gl.LINES, 0, lines.count);
      gl.disable(gl.BLEND);
    }
    if (points.count) {
      gl.enable(gl.DEPTH_TEST);
      gl.useProgram(points.prog);
      gl.uniformMatrix4fv(points.u.mvp, false, mvp);
      gl.uniform1i(points.u.mode, Number(colorBy.value));
      gl.uniform2f(points.u.zRange, ...points.zRange);
      gl.uniform1f(points.u.size, 30 * (devicePixelRatio || 1) * (c.height / 600));
      gl.bindVertexArray(points.vao);
      gl.drawArrays(gl.POINTS, 0, points.count);
    }
    gl.bindVertexArray(null);
  });
}

/** Uploads scan `s`: its parts' records one after the other. */
function upload(s) {
  const total = s.counts.reduce((a, n) => a + n, 0);
  const packed = new Uint8Array(total * RECORD);
  let at = 0;
  for (let p = 0; p < s.parts; p++) {
    packed.set(s.data.subarray(p * PER_PACKET * RECORD, (p * PER_PACKET + s.counts[p]) * RECORD), at);
    at += s.counts[p] * RECORD;
  }
  const v = new Int16Array(packed.buffer);
  let lo = Infinity;
  let hi = -Infinity;
  for (let i = 2; i < v.length; i += 4) {
    lo = Math.min(lo, v[i]);
    hi = Math.max(hi, v[i]);
  }
  points.zRange = total ? [lo / 100, hi / 100] : [0, 1];
  points.count = total;
  gl.bindBuffer(gl.ARRAY_BUFFER, points.buf);
  gl.bufferData(gl.ARRAY_BUFFER, packed, gl.DYNAMIC_DRAW);
  // The grid on the lowest point, moved only when the ground does
  const ground = total ? Math.round(lo / 10) / 10 : 0;
  if (ground !== lines.ground) {
    const v = groundLines(ground);
    lines.ground = ground;
    lines.count = v.length / 7;
    gl.bindBuffer(gl.ARRAY_BUFFER, lines.buf);
    gl.bufferData(gl.ARRAY_BUFFER, v, gl.STATIC_DRAW);
  }
  return total;
}

const complete = (s) => s.got.every(Boolean);

function rate() {
  const done = scans.filter(complete);
  if (done.length < 2) return "";
  const span = done[done.length - 1].time - done[0].time;
  return span > 0 ? ` · ${((done.length - 1) / span).toFixed(1)} scans/s` : "";
}

function showScan(i) {
  if (!scans.length) return;
  index = Math.max(0, Math.min(scans.length - 1, i));
  const s = scans[index];
  const n = gl ? upload(s) : s.counts.reduce((a, x) => a + x, 0);
  scrub.value = String(index);
  const missing = s.got.filter((g) => !g).length;
  const text = `scan ${s.id} · ${index + 1} of ${scans.length} · ${n} points${missing ? ` · ${missing} of ${s.parts} parts missing` : ""}${rate()}`;
  info.textContent = `${text} · frames ${s.first}–${s.last}${bad ? ` · ${bad} bad packet${bad === 1 ? "" : "s"} skipped` : ""}`;
  status(text);
  render();
  ready();
}

// --- Data

function addPacket(b, frame, time) {
  if (b.length < HEADER || b[0] !== 0x57 || b[1] !== 0x42 || b[2] !== 0x50 || b[3] !== 0x43) return bad++;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const id = dv.getUint32(4, true);
  const part = dv.getUint16(8, true);
  const parts = dv.getUint16(10, true);
  const n = dv.getUint16(12, true);
  if (!parts || part >= parts || n > PER_PACKET || b.length < HEADER + n * RECORD) return bad++;
  let s = byId.get(id);
  if (!s) {
    s = { id, parts, counts: new Uint16Array(parts), got: new Uint8Array(parts), data: new Uint8Array(parts * PER_PACKET * RECORD), first: frame, last: frame, time };
    byId.set(id, s);
    scans.push(s);
    if (scans.length > MAX_SCANS) {
      byId.delete(scans.shift().id);
      index--;
    }
  }
  if (s.parts !== parts) return bad++;
  s.data.set(b.subarray(HEADER, HEADER + n * RECORD), part * PER_PACKET * RECORD);
  s.counts[part] = n;
  s.got[part] = 1;
  s.last = frame;
}

let sub = null;
function start() {
  generation++;
  const g = generation;
  sub?.close();
  scans = [];
  byId = new Map();
  index = -1;
  bad = 0;
  follow = true;
  setPlaying(false);
  scrub.max = "0";
  if (points) points.count = 0;
  render();
  if (!wb.view.file) {
    info.textContent = `Open a capture with wbpc packets (UDP port ${PORT}).`;
    return ready();
  }
  info.textContent = "Reading the scans…";
  setTimeout(() => {
    if (g !== generation || scans.length) return;
    info.textContent = `No wbpc scans yet (UDP port ${PORT}).`;
    ready();
  }, 3000);
  sub = wb.subscribe(query, {
    batch(page) {
      if (g !== generation) return;
      for (let i = 0; i < page.n; i++) addPacket(page.bytes(i), page.frames[i], page.times[i]);
      scrub.max = String(Math.max(0, scans.length - 1));
      // The newest complete scan while following a live capture
      if (follow && page.live) {
        let i = scans.length - 1;
        while (i > 0 && !complete(scans[i])) i--;
        showScan(i);
      } else showScan(Math.max(index, 0));
    },
  });
}

// --- Controls

let timer = 0;
function setPlaying(on) {
  playing = on && scans.length > 1;
  playButton.textContent = playing ? "Pause" : "Play";
  clearTimeout(timer);
  if (playing) step();
}

/** The next scan, after as long as the sensor took between them. */
function step() {
  const at = index;
  const nextIndex = at + 1 >= scans.length ? 0 : at + 1;
  const wait = nextIndex > at ? Math.min(1, Math.max(0.02, scans[nextIndex].time - scans[at].time)) : 0.5;
  timer = setTimeout(() => {
    if (!playing) return;
    showScan(nextIndex);
    step();
  }, wait * 1000);
}

const go = (i) => {
  follow = i >= scans.length - 1;
  showScan(i);
};
$(".prev").addEventListener("click", () => go(index - 1));
$(".next").addEventListener("click", () => go(index + 1));
playButton.addEventListener("click", () => setPlaying(!playing));
scrub.addEventListener("input", () => go(Number(scrub.value)));
colorBy.addEventListener("change", render);
document.addEventListener("keydown", (e) => {
  if (e.target instanceof HTMLInputElement || e.target instanceof HTMLSelectElement) return;
  if (e.key === "ArrowLeft") go(index - 1);
  else if (e.key === "ArrowRight") go(index + 1);
  else if (e.key === " ") setPlaying(!playing);
  else return;
  e.preventDefault();
});

// Orbit, pan and zoom
if (gl) {
  const c = gl.canvas;
  let drag = null;
  c.addEventListener("pointerdown", (e) => {
    drag = { x: e.clientX, y: e.clientY, pan: e.shiftKey || e.button === 2 };
    c.setPointerCapture(e.pointerId);
  });
  c.addEventListener("pointermove", (e) => {
    if (!drag) return;
    const dx = e.clientX - drag.x;
    const dy = e.clientY - drag.y;
    drag.x = e.clientX;
    drag.y = e.clientY;
    if (drag.pan) {
      const k = cam.dist * 0.0015;
      cam.target[0] += (Math.sin(cam.yaw) * dx - Math.cos(cam.yaw) * dy * Math.sin(cam.pitch)) * k;
      cam.target[1] += (-Math.cos(cam.yaw) * dx - Math.sin(cam.yaw) * dy * Math.sin(cam.pitch)) * k;
      cam.target[2] += dy * Math.cos(cam.pitch) * k;
    } else {
      cam.yaw -= dx * 0.006;
      cam.pitch = Math.max(-1.5, Math.min(1.5, cam.pitch + dy * 0.006));
    }
    render();
  });
  c.addEventListener("pointerup", () => (drag = null));
  c.addEventListener("contextmenu", (e) => e.preventDefault());
  c.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      cam.dist = Math.max(1, Math.min(300, cam.dist * Math.exp(e.deltaY * 0.0012)));
      render();
    },
    { passive: false },
  );
  c.addEventListener("dblclick", () => {
    Object.assign(cam, structuredClone(home));
    render();
  });
}

// A packet selected in WireBuddy: its scan
wb.on("select", (frame) => {
  if (frame == null) return;
  const i = scans.findIndex((s) => frame >= s.first && frame <= s.last);
  if (i >= 0) go(i);
});
if (gl) {
  wb.on("reset", start);
  start();
} else ready();
