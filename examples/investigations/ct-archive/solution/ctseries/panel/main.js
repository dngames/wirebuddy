// CT images stored over DICOM, read from Wireshark's export objects, one association at a time (the
// latest, or the one picked): an axial viewer per series; sagittal reformats of the series as sent
// and as the archive keeps it (per SOP Instance UID the last image received, stacked by instance
// number, the way a viewer that trusts the series does); and every C-STORE in capture order, red
// where a SOP Instance UID comes more than once.
// The datasets are parsed here, Explicit VR Little Endian only.

const WINDOWS = { brain: { width: 80, level: 40 }, bone: { width: 2000, level: 500 } };
const EXPLICIT_LE = "1.2.840.10008.1.2.1";
const LONG_VRS = new Set(["OB", "OD", "OF", "OL", "OV", "OW", "SQ", "SV", "UC", "UN", "UR", "UT", "UV"]);
/** Objects read at once. */
const LOADS = 4;
/** Frames asked for in one query. */
const QUERY_FRAMES = 5000;
const REFRESH_MS = 2000;

// --- Page

const $ = (sel) => document.querySelector(sel);
const readout = $(".readout");
const note = $(".note");
const seriesBar = $(".series");
const slider = $(".slice");
const associationPicker = $(".association");
let drawPending = false;
const { canvas, ctx } = wb.canvas({ context: "2d", parent: $(".view"), onResize: () => draw() });
// Painted now: a hidden page gets no animation frames
wb.onSnapshot(() => {
  paint();
  return canvas;
});

// --- Data

/** C-STOREs in capture order, as their objects are listed: {n, id, frame, size, association, ...what the dataset says}. */
let stores = [];
let listed = new Set();
/** A DICOM association per TCP connection, in capture order: {stream, stores}. */
let associations = [];
let pickedAssociation = null;
let userPickedAssociation = false;
/** Series by UID, in series number order: {uid, number, description, thickness, color, sent, kept, lost}. */
let series = [];
let distinct = 0;
let overwritten = 0;
let shown = null;
let pickedSeries = null;
let userPicked = false;
let windowName = "brain";
let generation = 0;
let unreadable = 0;
/** Reformat pictures by series UID, window and kind, made when needed. */
let pictures = new Map();

function clear() {
  stores = [];
  listed = new Set();
  associations = [];
  pickedAssociation = null;
  userPickedAssociation = false;
  series = [];
  distinct = overwritten = unreadable = 0;
  shown = pickedSeries = null;
  userPicked = false;
  pictures = new Map();
  hover = null;
}

const latin1 = new TextDecoder("latin1");
const str = (v) => (v ? latin1.decode(v).replace(/[\0 ]+$/, "").trim() : "");

/** A DICOM Part 10 file's elements by tag (0xggggeeee), or why it can't be read. */
function parse(b) {
  if (b.length < 132 || latin1.decode(b.subarray(128, 132)) !== "DICM") return "not a DICOM file";
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const el = new Map();
  for (let at = 132; at + 8 <= b.length; ) {
    const tag = ((dv.getUint16(at, true) << 16) | dv.getUint16(at + 2, true)) >>> 0;
    // Past the file meta information: the dataset, in the transfer syntax it names
    if (tag >>> 16 !== 2 && str(el.get(0x00020010)).split(" ")[0] !== EXPLICIT_LE) return "not Explicit VR Little Endian";
    const long = LONG_VRS.has(latin1.decode(b.subarray(at + 4, at + 6)));
    const length = long ? dv.getUint32(at + 8, true) : dv.getUint16(at + 6, true);
    at += long ? 12 : 8;
    // Undefined lengths (sequences) end what this reads
    if (length === 0xffffffff || at + length > b.length) break;
    el.set(tag, b.subarray(at, at + length));
    at += length;
  }
  return el;
}

/** What a C-STORE's dataset says: UIDs, series, position and the image in HU (or null). */
function describe(el) {
  const num = (tag, i = 0) => Number(str(el.get(tag)).split("\\")[i]);
  const u16 = (tag) => (el.get(tag)?.length >= 2 ? el.get(tag)[0] | (el.get(tag)[1] << 8) : NaN);
  const rows = u16(0x00280010);
  const cols = u16(0x00280011);
  const px = el.get(0x7fe00010);
  let image = null;
  if (rows > 0 && cols > 0 && u16(0x00280100) === 16 && u16(0x00280002) !== 3 && px?.length >= rows * cols * 2) {
    const copy = px.slice(0, rows * cols * 2).buffer;
    const raw = u16(0x00280103) === 1 ? new Int16Array(copy) : new Uint16Array(copy);
    const slope = num(0x00281053) || 1;
    const intercept = num(0x00281052) || 0;
    const hu = new Float32Array(raw.length);
    for (let i = 0; i < raw.length; i++) hu[i] = raw[i] * slope + intercept;
    image = { rows, cols, hu, spacing: [num(0x00280030, 0) || 1, num(0x00280030, 1) || 1] };
  }
  const z = num(0x00201041);
  return {
    sop: str(el.get(0x00080018)),
    series: str(el.get(0x0020000e)),
    number: str(el.get(0x00200011)),
    description: str(el.get(0x0008103e)),
    thickness: num(0x00180050),
    instance: num(0x00200013),
    location: Number.isFinite(z) ? z : num(0x00200032, 2),
    image,
  };
}

/** The shown association's collisions, series, and what the archive keeps: per SOP Instance UID the last C-STORE. */
function derive() {
  const read = (pickedAssociation?.stores ?? []).filter((s) => s.sop);
  const byUid = new Map();
  for (const s of read) {
    if (!byUid.has(s.sop)) byUid.set(s.sop, []);
    byUid.get(s.sop).push(s);
  }
  for (const s of read) {
    s.same = byUid.get(s.sop);
    s.kept = s.same.at(-1) === s;
  }
  distinct = byUid.size;
  overwritten = read.length - distinct;
  const groups = new Map();
  for (const s of read) {
    if (!s.image) continue;
    if (!groups.has(s.series)) groups.set(s.series, { uid: s.series, number: s.number, description: s.description, thickness: s.thickness, sent: [] });
    groups.get(s.series).sent.push(s);
  }
  series = [...groups.values()].sort((a, b) => Number(a.number) - Number(b.number) || a.uid.localeCompare(b.uid));
  const c = theme();
  series.forEach((g, i) => {
    g.sent.sort((a, b) => a.instance - b.instance || a.n - b.n);
    g.kept = g.sent.filter((s) => s.kept);
    g.lost = g.sent.length - g.kept.length;
    g.color = c.series[i % c.series.length];
    const z = g.sent.map((s) => s.location).filter(Number.isFinite);
    const steps = z.slice(1).map((v, i) => Math.abs(v - z[i])).sort((a, b) => a - b);
    g.spacing = steps[steps.length >> 1] || g.thickness || 1;
    g.up = z.length < 2 || z.at(-1) >= z[0];
  });
  pictures = new Map();
  if (!series.some((g) => g.uid === pickedSeries)) pickedSeries = defaultSeries()?.uid ?? null;
  // Until the user picks one: the series' middle image
  const g = current();
  if (g && !(userPicked && g.sent.includes(shown))) shown = g.sent[g.sent.length >> 1];
  bar();
}

/** The series with the most images lost, else the largest. */
function defaultSeries() {
  return [...series].sort((a, b) => b.lost - a.lost || b.sent.length - a.sent.length)[0];
}

const current = () => series.find((g) => g.uid === pickedSeries) ?? null;
const mm = (v) => `${Number.isFinite(v) ? +v.toFixed(3) : "?"} mm`;

// --- Toolbar

function bar() {
  const labels = associations.map((a, i) => `Association ${i + 1} · ${a.stores.length} C-STOREs`);
  if (labels.join("\n") !== [...associationPicker.options].map((o) => o.textContent).join("\n")) {
    associationPicker.replaceChildren(...labels.map((label, i) => wb.h("option", { value: String(i) }, label)));
  }
  associationPicker.value = String(associations.indexOf(pickedAssociation));
  associationPicker.hidden = associations.length < 2;
  seriesBar.replaceChildren(
    ...series.map((g) =>
      wb.h(
        "button",
        {
          type: "button",
          class: g.uid === pickedSeries ? "on" : "",
          title: `${g.description || "series"}: ${g.sent.length} images sent, ${g.kept.length} kept`,
          onclick: () => pick(g, null),
        },
        `Series ${g.number || "?"} · ${mm(g.thickness)}`,
      ),
    ),
  );
  const g = current();
  slider.max = String(Math.max(0, (g?.sent.length ?? 1) - 1));
  slider.disabled = !g;
  if (g) slider.value = String(Math.max(0, g.sent.indexOf(shown)));
  for (const b of document.querySelectorAll(".windows button")) b.classList.toggle("on", b.dataset.window === windowName);
}

/** Shows an association: its C-STOREs, their collisions and series. */
function showAssociation(a) {
  userPickedAssociation = true;
  pickedAssociation = a;
  derive();
  status();
}

/** Shows a series, at image `s` or the one nearest the image shown before. */
function pick(g, s) {
  userPicked = true;
  pickedSeries = g.uid;
  const z = shown?.location ?? 0;
  shown = s ?? g.sent.reduce((best, t) => (Math.abs(t.location - z) < Math.abs(best.location - z) ? t : best), g.sent[0]) ?? null;
  bar();
  draw();
}

associationPicker.addEventListener("change", () => {
  showAssociation(associations[Number(associationPicker.value)] ?? pickedAssociation);
  draw();
});
slider.addEventListener("input", () => {
  const g = current();
  if (!g) return;
  shown = g.sent[Number(slider.value)] ?? null;
  draw();
});
for (const b of document.querySelectorAll(".windows button")) {
  b.addEventListener("click", () => {
    windowName = b.dataset.window;
    bar();
    draw();
  });
}

// --- Status

let statusTimer = 0;
let statusAt = 0;
let statusText = "";
function summary() {
  const done = stores.filter((s) => s.sop || s.failed).length;
  if (done < stores.length) return `Reading the images: ${done} of ${stores.length}`;
  if (!pickedAssociation) return "";
  const which = associations.length > 1 ? `Association ${associations.indexOf(pickedAssociation) + 1} of ${associations.length} · ` : "";
  return `${which}${pickedAssociation.stores.length} C-STOREs · ${distinct} SOP Instance UIDs · ${overwritten ? `${overwritten} overwritten` : "none overwritten"}`;
}
/** The status line, at most twice a second. */
function status() {
  clearTimeout(statusTimer);
  const wait = statusAt + 500 - performance.now();
  if (wait > 0) return void (statusTimer = setTimeout(status, wait));
  statusAt = performance.now();
  const text = summary();
  if (text !== statusText) wb.status((statusText = text));
}

// --- Drawing

const dark = matchMedia("(prefers-color-scheme: dark)");
function theme() {
  const css = getComputedStyle(document.documentElement);
  const isDark = dark.matches;
  return {
    bg: css.getPropertyValue("--wb-bg").trim() || (isDark ? "#1e1f22" : "#ffffff"),
    ink: css.getPropertyValue("--wb-fg").trim() || (isDark ? "#dfe1e5" : "#1d1d1f"),
    muted: css.getPropertyValue("--wb-muted").trim() || "#898781",
    accent: css.getPropertyValue("--wb-accent").trim() || "#2e6fd8",
    axis: isDark ? "#383835" : "#c3c2b7",
    series: isDark ? ["#3987e5", "#199e70", "#9b6fe0", "#d39a1a"] : ["#2a78d6", "#1baf7a", "#8a5cd1", "#c98a00"],
    critical: "#d03b3b",
  };
}

/** A grey value 0..255 for HU in the chosen window. */
function grey(hu) {
  const w = WINDOWS[windowName];
  return Math.max(0, Math.min(255, ((hu - (w.level - w.width / 2)) / w.width) * 255));
}

/** An offscreen canvas of w x h filled per pixel by value(x, y) in HU. */
function picture(w, h, value) {
  const c = document.createElement("canvas");
  c.width = Math.max(1, w);
  c.height = Math.max(1, h);
  const g = c.getContext("2d");
  const data = g.createImageData(c.width, c.height);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const v = grey(value(x, y));
      const i = (y * w + x) * 4;
      data.data[i] = data.data[i + 1] = data.data[i + 2] = v;
      data.data[i + 3] = 255;
    }
  }
  g.putImageData(data, 0, 0);
  return c;
}

/** The mid-sagittal plane of `list` stacked in order, the first image at the bottom when z goes up. */
function reformat(g, kind) {
  const key = `${g.uid}|${windowName}|${kind}`;
  if (pictures.has(key)) return pictures.get(key);
  const list = g[kind];
  const rows = list[0].image.rows;
  const at = (k) => list[g.up ? list.length - 1 - k : k].image;
  const p = picture(rows, list.length, (x, y) => {
    const im = at(y);
    return x < im.rows ? im.hu[x * im.cols + (im.cols >> 1)] : -1000;
  });
  pictures.set(key, p);
  return p;
}

function draw() {
  if (drawPending) return;
  drawPending = true;
  requestAnimationFrame(() => {
    drawPending = false;
    paint();
  });
}

/** Where things are in the last paint, for hovering and clicking. */
let view = null;
let hover = null;

function paint() {
  const c = theme();
  const W = canvas.clientWidth;
  const H = canvas.clientHeight;
  const dpr = canvas.width / Math.max(1, W);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = c.bg;
  ctx.fillRect(0, 0, W, H);
  view = null;
  if (!pickedAssociation) return;
  ctx.textBaseline = "middle";
  const pad = 12;
  const tickBottom = H - 26;
  const tickTop = tickBottom - 18;
  const top = 10;
  const bottom = tickTop - 46;
  view = { strip: { left: pad, right: W - pad, top: tickTop - 12, bottom: tickBottom }, reformats: [] };
  const g = current();
  if (g && bottom - top > 80) paintImages(c, g, pad, top, W - pad, bottom);
  paintStrip(c, pad, W - pad, tickTop, tickBottom, H);
}

function text(s, x, y, { color, font = "12px system-ui, sans-serif", align = "left", max } = {}) {
  ctx.font = font;
  ctx.textAlign = align;
  ctx.fillStyle = color;
  ctx.fillText(s, x, y, max);
}

function paintImages(c, g, left, top, right, bottom) {
  const box = Math.min(bottom - top - 54, (right - left) * 0.4);
  const s = shown;
  // The axial image, square, with what it is above and below
  const im = s.image;
  const ax = { x: left, y: top + 18, w: box, h: box };
  const fit = Math.min(box / (im.cols * im.spacing[1]), box / (im.rows * im.spacing[0]));
  const iw = im.cols * im.spacing[1] * fit;
  const ih = im.rows * im.spacing[0] * fit;
  ctx.fillStyle = "#000";
  ctx.fillRect(ax.x, ax.y, ax.w, ax.h);
  ctx.imageSmoothingEnabled = true;
  ctx.drawImage(picture(im.cols, im.rows, (x, y) => im.hu[y * im.cols + x]), ax.x + (box - iw) / 2, ax.y + (box - ih) / 2, iw, ih);
  const index = g.sent.indexOf(s);
  text(`Series ${g.number} · ${g.description || "?"} · image ${index + 1} of ${g.sent.length}`, ax.x, top + 6, { color: c.ink, font: "600 12px system-ui, sans-serif", max: box });
  text(`instance ${s.instance} · ${mm(s.location)} · C-STORE ${s.n}, frame ${s.frame}`, ax.x, ax.y + box + 14, { color: c.muted, max: box });
  if (!s.kept) {
    const by = s.same.at(-1);
    text(`Overwritten by C-STORE ${by.n} (instance ${by.instance}): same SOP Instance UID`, ax.x, ax.y + box + 32, { color: c.critical, max: box });
  } else if (s.same.length > 1) {
    text(`Kept: it overwrote ${s.same.length - 1} C-STORE${s.same.length > 2 ? "s" : ""} with its SOP Instance UID`, ax.x, ax.y + box + 32, { color: c.critical, max: box });
  }
  view.axial = ax;

  // Both reformats at one scale: side by side, or stacked where that shows them larger
  const rx = ax.x + box + 28;
  const areaW = right - rx;
  const areaH = bottom - top;
  if (areaW < 120) return;
  const fovY = im.rows * im.spacing[0];
  const [zSent, zKept] = [g.sent.length * g.spacing, g.kept.length * g.spacing];
  const side = Math.min((areaW - 24) / 2 / fovY, (areaH - 36) / zSent);
  const stack = Math.min(areaW / fovY, (areaH - 80) / (zSent + zKept));
  const stacked = stack > side;
  const scale = Math.max(side, stack);
  const rw = fovY * scale;
  const rowH = g.spacing * scale;
  const base = top + 18 + zSent * scale + (stacked ? 0 : (areaH - 36 - zSent * scale) / 2);
  const kinds = [
    ["sent", `As sent · ${g.sent.length} images`, rx, base],
    ["kept", `As the archive keeps it · ${g.kept.length} images`, stacked ? rx : rx + rw + 24, stacked ? base + 44 + zKept * scale : base],
  ];
  kinds.forEach(([kind, title, x, baseline], i) => {
    const list = g[kind];
    const row = (k) => (g.up ? list.length - 1 - k : k);
    const y = baseline - list.length * rowH;
    text(title, x, (stacked ? y : baseline - zSent * scale) - 12, { color: i && g.lost ? c.critical : c.ink, font: "600 12px system-ui, sans-serif", max: rw });
    if (!list.length) return;
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(reformat(g, kind), x, y, rw, list.length * rowH);
    view.reformats.push({ x, y, w: rw, h: list.length * rowH, list, row });
    // The axial image's place
    const k = list.indexOf(s);
    if (k >= 0) {
      const ry = Math.round(y + (row(k) + 0.5) * rowH) + 0.5;
      ctx.strokeStyle = c.accent;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x - 6, ry);
      ctx.lineTo(x + rw + 6, ry);
      ctx.stroke();
    }
    if (kind === "sent" && g.lost) {
      // A mark beside each image the archive lost
      ctx.fillStyle = c.critical;
      list.forEach((t, j) => {
        if (!t.kept) ctx.fillRect(x + rw + 3, y + row(j) * rowH, 5, Math.max(1, rowH));
      });
      text(`red: overwritten, ${g.lost} images not in the archive`, x, baseline + 12, { color: c.critical, max: rw });
    } else if (kind === "kept") {
      const squash = list.length / g.sent.length;
      text(squash < 1 ? `stacked by instance number: ${Math.round(squash * 100)}% of the height` : "the same images", x, baseline + 12, { color: squash < 1 ? c.critical : c.muted, max: rw });
    }
  });
}

/** The association's C-STOREs in capture order: series colors, red where a SOP Instance UID repeats, the repeats linked. */
function paintStrip(c, left, right, tickTop, tickBottom, H) {
  const list = pickedAssociation.stores;
  const n = list.length;
  const step = (right - left) / n;
  const w = Math.max(1, Math.min(8, step - (step > 3 ? 1 : 0)));
  const X = (s) => left + (s.n - 0.5) * step;
  const color = (s) => (s.same?.length > 1 ? c.critical : (series.find((g) => g.uid === s.series)?.color ?? c.muted));
  text("C-STOREs in capture order", left, tickTop - 24, { color: c.ink, font: "600 12px system-ui, sans-serif" });
  for (const s of list) {
    const x = Math.round(X(s) - w / 2);
    ctx.fillStyle = color(s);
    if (!s.sop) {
      ctx.fillStyle = c.axis;
      ctx.fillRect(x, tickBottom - 4, w, 4);
    } else if (s.kept === false) {
      // Overwritten: an outline
      ctx.strokeStyle = c.critical;
      ctx.lineWidth = 1;
      ctx.strokeRect(x + 0.5, tickTop + 0.5, Math.max(1, w - 1), tickBottom - tickTop - 1);
    } else ctx.fillRect(x, tickTop, w, tickBottom - tickTop);
  }
  // Each repeat linked to the C-STORE before it with that UID
  ctx.strokeStyle = c.critical;
  ctx.lineWidth = 1.25;
  for (const s of list) {
    const k = s.same?.indexOf(s) ?? 0;
    if (k < 1) continue;
    const a = X(s.same[k - 1]);
    const b = X(s);
    const lift = Math.min(10, 3 + (b - a) / 4);
    ctx.beginPath();
    ctx.moveTo(a, tickTop - 1);
    ctx.bezierCurveTo(a, tickTop - lift, b, tickTop - lift, b, tickTop - 1);
    ctx.stroke();
  }
  if (shown?.association === pickedAssociation) {
    const x = X(shown);
    ctx.fillStyle = c.accent;
    ctx.beginPath();
    ctx.moveTo(x, tickBottom + 2);
    ctx.lineTo(x - 5, tickBottom + 9);
    ctx.lineTo(x + 5, tickBottom + 9);
    ctx.fill();
  }
  if (hover?.association === pickedAssociation) {
    const x = Math.round(X(hover)) + 0.5;
    ctx.strokeStyle = c.ink;
    ctx.lineWidth = 1;
    ctx.strokeRect(x - w / 2 - 2, tickTop - 2.5, w + 4, tickBottom - tickTop + 5);
  }
  // Legend: series, then the repeats
  let x = left;
  const y = H - 9;
  ctx.font = "11px system-ui, sans-serif";
  const key = (label, paintSwatch) => {
    paintSwatch(x, y);
    text(label, x + 14, y, { color: c.ink, font: "11px system-ui, sans-serif" });
    x += 14 + ctx.measureText(label).width + 14;
  };
  for (const g of series) {
    key(`series ${g.number} (${mm(g.thickness)})`, (sx, sy) => {
      ctx.fillStyle = g.color;
      ctx.fillRect(sx, sy - 5, 9, 10);
    });
  }
  if (overwritten) {
    key("same SOP Instance UID: kept", (sx, sy) => {
      ctx.fillStyle = c.critical;
      ctx.fillRect(sx, sy - 5, 9, 10);
    });
    key("overwritten", (sx, sy) => {
      ctx.strokeStyle = c.critical;
      ctx.strokeRect(sx + 0.5, sy - 4.5, 8, 9);
    });
  }
  const skipped = unreadable ? ` · ${unreadable} not readable here` : "";
  text(`click: show it and select its packet${skipped}`, right, y, { color: c.muted, font: "11px system-ui, sans-serif", align: "right" });
}

// --- Hover and clicks

const line = (...children) => wb.h("div", {}, ...children);
const muted = (s) => wb.h("span", { class: "muted" }, s);

/** The C-STORE under x in the strip, or null. */
function storeAt(px, py) {
  const st = view?.strip;
  // The strip of a capture already gone stays painted until the next frame
  if (!st || !pickedAssociation || py < st.top - 6 || py > st.bottom + 10 || px < st.left || px > st.right) return null;
  const list = pickedAssociation.stores;
  return list[Math.min(list.length - 1, Math.floor(((px - st.left) / (st.right - st.left)) * list.length))] ?? null;
}

/** The image under a point on a reformat, or null. */
function reformatAt(px, py) {
  for (const r of view?.reformats ?? []) {
    if (px < r.x || px > r.x + r.w || py < r.y || py > r.y + r.h) continue;
    const k = Math.min(r.list.length - 1, Math.floor(((py - r.y) / r.h) * r.list.length));
    return r.list[r.row(k)];
  }
  return null;
}

function showReadout(px, py) {
  const s = storeAt(px, py);
  if (s !== hover) {
    hover = s;
    draw();
  }
  if (!s) return void (readout.hidden = true);
  const rows = [line(wb.h("span", { class: "head" }, `C-STORE ${s.n}`), muted(` · frame ${s.frame} · ${wb.fmt.bytes(s.size)}`))];
  if (s.failed) rows.push(line(muted(s.failed)));
  else if (!s.same) rows.push(line(muted("reading its image…")));
  else {
    rows.push(line(`series ${s.number || "?"} · instance ${s.instance} · ${mm(s.location)}`));
    rows.push(line(muted(`SOP Instance UID ${s.sop}`)));
    if (s.same.length > 1) {
      const others = s.same.filter((o) => o !== s).map((o) => `C-STORE ${o.n} (instance ${o.instance}, ${mm(o.location)})`);
      rows.push(line(wb.h("span", { class: "bad" }, `Same UID as ${others.join(", ")}: ${s.kept ? "the archive keeps this one" : "overwritten"}`)));
    }
  }
  rows.push(line(muted("click: show it and select its packet")));
  readout.replaceChildren(...rows);
  readout.hidden = false;
  const r = readout.getBoundingClientRect();
  const at = canvas.getBoundingClientRect();
  const left = px + 14 + r.width > at.width ? px - 14 - r.width : px + 14;
  readout.style.left = `${Math.max(4, at.left + left)}px`;
  readout.style.top = `${Math.max(4, at.top + py - r.height - 12)}px`;
}

canvas.addEventListener("pointermove", (e) => {
  const r = canvas.getBoundingClientRect();
  showReadout(e.clientX - r.left, e.clientY - r.top);
});
canvas.addEventListener("pointerleave", () => {
  readout.hidden = true;
  if (hover) {
    hover = null;
    draw();
  }
});
canvas.addEventListener("click", (e) => {
  const r = canvas.getBoundingClientRect();
  const px = e.clientX - r.left;
  const py = e.clientY - r.top;
  const s = storeAt(px, py);
  if (s) {
    // Right after the click: WireBuddy lets a panel select a packet only then
    wb.select(s.frame).catch(() => {});
    const g = series.find((x) => x.uid === s.series);
    if (g && s.image) pick(g, s);
    return;
  }
  const t = reformatAt(px, py);
  if (t) pick(current(), t);
});
canvas.addEventListener(
  "wheel",
  (e) => {
    const a = view?.axial;
    const r = canvas.getBoundingClientRect();
    const g = current();
    if (!a || !g || e.clientX - r.left > a.x + a.w || e.clientY - r.top < a.y || e.clientY - r.top > a.y + a.h) return;
    e.preventDefault();
    const k = Math.max(0, Math.min(g.sent.length - 1, g.sent.indexOf(shown) + Math.sign(e.deltaY)));
    pick(g, g.sent[k]);
  },
  { passive: false },
);

// --- Reading

let isReady = false;
/** Tells WireBuddy the panel works, once there is something to see (or nothing to wait for). */
const ready = () => {
  if (!isReady) wb.ready();
  isReady = true;
};

function message(s) {
  note.textContent = s;
  note.hidden = !s;
}

const queue = [];
let loading = 0;

function pump() {
  while (loading < LOADS && queue.length) {
    const s = queue.shift();
    loading++;
    load(s).finally(() => {
      loading--;
      pump();
    });
  }
}

let deriveTimer = 0;
async function load(s) {
  const g = generation;
  try {
    const file = await wb.object(s.id);
    if (g !== generation) return;
    const el = parse(file.bytes);
    if (typeof el === "string") throw new Error(el);
    Object.assign(s, describe(el));
    if (!s.sop) throw new Error("no SOP Instance UID");
  } catch (e) {
    if (g !== generation || e?.code === "stale") return;
    s.failed = `not readable here: ${e.message}`;
    unreadable++;
  }
  // Worked out again a few times a second while images come in
  if (!deriveTimer) {
    deriveTimer = setTimeout(() => {
      deriveTimer = 0;
      if (g !== generation) return;
      derive();
      status();
      // Now, so that ready means drawn, also on a hidden page
      paint();
      if (series.length || !queue.length) {
        message(series.length ? "" : "No CT images in the DICOM objects of this capture.");
        ready();
      }
    }, queue.length || loading > 1 ? 250 : 0);
  }
}

/** The TCP connection (tcp.stream) of each object's frame, by frame. */
async function connections(objects) {
  const out = new Map();
  for (let i = 0; i < objects.length; i += QUERY_FRAMES) {
    const page = await wb.all({ frames: objects.slice(i, i + QUERY_FRAMES).map((o) => [o.frame, o.frame]), fields: ["tcp.stream"] });
    page.frames.forEach((frame, k) => out.set(frame, page.fields["tcp.stream"][k]));
  }
  return out;
}

async function refresh() {
  const g = generation;
  if (!wb.view.file) {
    message("Open a capture with DICOM C-STOREs of CT images, e.g. to port 11112.");
    return ready();
  }
  let objects;
  let streams;
  try {
    objects = await wb.objects("dicom");
    streams = await connections(objects.filter((o) => !listed.has(o.id)));
  } catch (e) {
    // Another file, or none: the reset that follows starts over
    if (["stale", "no-capture"].includes(e.code)) return;
    message(`Could not list the DICOM objects: ${e.message}`);
    return ready();
  }
  if (g !== generation) return;
  const added = objects.filter((o) => !listed.has(o.id)).sort((a, b) => a.frame - b.frame);
  for (const o of added) {
    listed.add(o.id);
    const stream = streams.get(o.frame) ?? "";
    let a = associations.find((x) => x.stream === stream);
    if (!a) associations.push((a = { stream, stores: [] }));
    const s = { n: a.stores.length + 1, id: o.id, frame: o.frame, size: o.size, association: a };
    a.stores.push(s);
    stores.push(s);
    queue.push(s);
  }
  if (!userPickedAssociation) pickedAssociation = associations.at(-1) ?? null;
  if (!stores.length) {
    message("No DICOM objects in this capture yet: the images of a C-STORE show once its dataset is complete.");
    return ready();
  }
  if (added.length) message(`Reading ${stores.length} DICOM objects…`);
  status();
  pump();
}

function start() {
  generation++;
  clearTimeout(deriveTimer);
  deriveTimer = 0;
  clear();
  queue.length = 0;
  readout.hidden = true;
  if (statusText) wb.status((statusText = ""));
  bar();
  draw();
  return refresh();
}

// A live capture: look again every REFRESH_MS while packets come
let refreshTimer = 0;
wb.on("packets", () => {
  if (refreshTimer) return;
  refreshTimer = setTimeout(() => {
    refreshTimer = 0;
    void refresh();
  }, REFRESH_MS);
});
// A C-STORE's packet selected in WireBuddy: its association and image
wb.on("select", (frame) => {
  const s = stores.find((x) => x.frame === frame);
  if (!s?.image) return;
  if (s.association !== pickedAssociation) showAssociation(s.association);
  const g = series.find((x) => x.uid === s.series);
  if (g) pick(g, s);
  else draw();
});
wb.on("theme", () => {
  derive();
  draw();
});
wb.on("reset", start);
await start();
