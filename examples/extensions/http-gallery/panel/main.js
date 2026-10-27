// Images sent over HTTP as a grid of thumbnails, the other files as a list. A click shows
// one in full with where it came from. Everything from the capture goes into the page as
// text (wb.h, textContent) or as a blob: URL in an <img>.

/** The panel's only query: the files HTTP carried, from Wireshark's Export Objects. */
const listFiles = () => wb.objects("http");

const IMAGE_NAME = /\.(png|jpe?g|gif|webp|avif|bmp|ico|svg)$/i;
const TEXT_TYPE = /^text\/|json|xml|javascript/;
/** Thumbnails loading at once. */
const LOADS = 4;
const REFRESH_MS = 2000;

const note = wb.h("p", { class: "note" });
const grid = wb.h("div", { class: "grid" });
const rows = wb.h("tbody");
const othersTitle = wb.h("h2");
const others = wb.h(
  "section",
  { class: "others", hidden: true },
  othersTitle,
  wb.h("table", null, wb.h("thead", null, wb.h("tr", null, ["File", "Type", "Size", "Host", "Frame"].map((t) => wb.h("th", null, t)))), rows),
);
const viewer = wb.h("div", { class: "viewer", hidden: true });
document.body.append(note, grid, others, viewer);

let seen = new Set();
let images = 0;
let otherCount = 0;
/** Bumped on reset: work started for an older capture drops its results. */
let generation = 0;
/** Each thumbnail's object, <img> and size label. */
const tiles = new Map();
const queue = [];
let loading = 0;

const kind = (o) => (o.type.split(";")[0].split("/")[1] ?? "file").replace(/^x-|\+xml$/g, "").toUpperCase();
const isImage = (o) => o.type.startsWith("image/") || IMAGE_NAME.test(o.filename);

function count() {
  othersTitle.textContent = `Other files (${otherCount})`;
  others.hidden = otherCount === 0;
  wb.status(`${images} image${images === 1 ? "" : "s"} · ${otherCount} other file${otherCount === 1 ? "" : "s"}`);
}

function addImage(o) {
  const img = wb.h("img", { alt: o.filename || "image", draggable: "false" });
  const dims = wb.h("span");
  const tile = wb.h(
    "figure",
    { class: "tile", tabindex: "0", title: `${o.host}/${o.filename}` },
    wb.h("div", { class: "thumb" }, img),
    wb.h("figcaption", null, wb.h("b", null, o.filename || "(no name)"), wb.h("span", null, `${kind(o)} · ${wb.fmt.bytes(o.size)}`, dims)),
  );
  const t = { o, img, dims, generation };
  tile.addEventListener("click", () => showImage(t));
  tile.addEventListener("keydown", (e) => e.key === "Enter" && showImage(t));
  tiles.set(tile, t);
  grid.append(tile);
  observer.observe(tile);
  images++;
}

function addOther(o, why = "") {
  const row = wb.h(
    "tr",
    { tabindex: "0" },
    wb.h("td", null, o.filename || "(no name)"),
    wb.h("td", null, o.type || "?"),
    wb.h("td", { class: "num" }, wb.fmt.bytes(o.size)),
    wb.h("td", null, o.host),
    wb.h("td", { class: "num" }, String(o.frame)),
  );
  row.addEventListener("click", () => showFile(o, why));
  row.addEventListener("keydown", (e) => e.key === "Enter" && showFile(o, why));
  rows.append(row);
  otherCount++;
}

// Thumbnails load when they scroll into view, a few at a time
const observer = new IntersectionObserver((entries) => {
  for (const e of entries) {
    if (!e.isIntersecting) continue;
    observer.unobserve(e.target);
    queue.push(e.target);
  }
  pump();
});

function pump() {
  while (loading < LOADS && queue.length) {
    const tile = queue.shift();
    loading++;
    load(tile).finally(() => {
      loading--;
      pump();
    });
  }
}

async function load(tile) {
  const t = tiles.get(tile);
  if (!t || t.generation !== generation) return;
  try {
    t.img.src = await wb.objectURL(t.o.id);
    await t.img.decode();
    if (t.generation !== generation) return;
    t.dims.textContent = ` · ${t.img.naturalWidth}×${t.img.naturalHeight}`;
    tile.classList.add("loaded");
  } catch (e) {
    if (t.generation !== generation || e?.code === "stale") return;
    // Said to be an image, but the browser can't show it
    tile.remove();
    tiles.delete(tile);
    images--;
    addOther(t.o, "Not an image the browser can show.");
    count();
  }
}

/** The full-size view: `content` on top, the file's details below. */
function display(o, content, extra = []) {
  const meta = [
    ["File", o.filename || "(no name)"],
    ["Type", o.type || "?"],
    ["Size", `${wb.fmt.bytes(o.size)} (${o.size} bytes)`],
    ...extra,
    ["Host", o.host || "?"],
    ["Frame", String(o.frame)],
    ["SHA-1", o.sha1],
  ];
  viewer.replaceChildren(
    wb.h(
      "div",
      { class: "card" },
      wb.h("button", { class: "close", title: "Close (Esc)", onclick: close }, "×"),
      wb.h("div", { class: "content" }, content),
      wb.h("dl", null, meta.flatMap(([k, v]) => [wb.h("dt", null, k), wb.h("dd", null, v)])),
    ),
  );
  viewer.hidden = false;
}

async function showImage(t) {
  const src = t.img.currentSrc || (await wb.objectURL(t.o.id));
  display(t.o, wb.h("img", { src, alt: t.o.filename }), t.img.naturalWidth ? [["Picture", `${t.img.naturalWidth}×${t.img.naturalHeight} pixels`]] : []);
}

async function showFile(o, why) {
  // A look inside: text as text, anything else as hex
  const pre = wb.h("pre", null, "Loading…");
  display(o, why ? [wb.h("p", { class: "note" }, why), pre] : pre);
  try {
    const file = await wb.object(o.id);
    const head = file.bytes.subarray(0, 4096);
    pre.textContent = TEXT_TYPE.test(file.type) ? wb.text(head) + (file.bytes.length > head.length ? "\n…" : "") : wb.hex(file.bytes, 512);
  } catch (e) {
    pre.textContent = `Could not read it: ${e.message}`;
  }
}

function close() {
  viewer.hidden = true;
  viewer.replaceChildren();
}
viewer.addEventListener("click", (e) => e.target === viewer && close());
// Runs before the bridge's Escape handler, which would tell WireBuddy
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !viewer.hidden) {
    e.preventDefault();
    close();
  }
});

async function refresh() {
  const g = generation;
  if (!wb.view.file) {
    note.textContent = "Open a capture with HTTP downloads to see its pictures.";
    count();
    return;
  }
  let files;
  try {
    files = await listFiles();
  } catch (e) {
    // Another file, or none: the reset that follows starts over
    if (["stale", "no-capture"].includes(e.code)) return;
    note.textContent = `Could not list the files: ${e.message}`;
    return;
  }
  if (g !== generation) return;
  for (const o of files) {
    if (seen.has(o.id)) continue;
    seen.add(o.id);
    if (isImage(o)) addImage(o);
    else addOther(o);
  }
  note.textContent = seen.size ? "" : "No files sent over HTTP in this capture yet. HTTPS shows here once WireBuddy has its TLS keys.";
  count();
}

wb.on("reset", () => {
  generation++;
  seen = new Set();
  images = otherCount = 0;
  queue.length = 0;
  tiles.clear();
  grid.replaceChildren();
  rows.replaceChildren();
  close();
  return refresh();
});

// A live capture: look again once it has been quiet for a moment
let timer = 0;
wb.on("packets", () => {
  clearTimeout(timer);
  timer = setTimeout(refresh, REFRESH_MS);
});

await refresh();
wb.ready();
