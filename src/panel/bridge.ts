/**
 * The `wb` global of a WireBuddy panel, loaded before the panel's main.js: its
 * link to WireBuddy (the view, the capture's data, readiness, status, errors
 * to the agent, the page's watchdog) and small helpers. Panels have no network
 * but their own origin.
 */

import type { PanelView } from "../shared/api.ts";

type Child = Node | string | number | null | undefined | false;
type WbEvent = "view" | "select" | "packets" | "reset" | "visible" | "theme";

interface Query {
  filter?: string;
  frames?: "displayed" | "selected" | "marked" | [number, number][];
  fields?: string[];
  bytes?: string;
  after?: number;
  limit?: number;
  maxBytes?: number;
  /** wb.subscribe: from the first packet (default) or only new ones. */
  from?: "start" | "end";
}

interface Page {
  n: number;
  frames: Uint32Array;
  times: Float64Array;
  lens: Uint32Array;
  offsets: Uint32Array;
  data: Uint8Array;
  dirs: Uint8Array | null;
  bytes(i: number): Uint8Array;
  fields: Record<string, string[]>;
  clipped: [number, string][];
  next: number | null;
  done: boolean;
  live: boolean;
  pending: boolean;
  epoch: number;
  total: number | null;
  dropped: number;
  layer: string;
  readonly packets: { frame: number; time: number; len: number; bytes: Uint8Array; dir?: number; fields: Record<string, string> }[];
}

interface PageHead {
  n: number;
  epoch: number;
  total: number | null;
  next: number | null;
  done: boolean;
  live: boolean;
  pending?: boolean;
  layer: string;
  fields?: Record<string, string[]>;
  clipped?: [number, string][];
  dropped?: number;
  dirs: boolean;
  follow?: { protocol: string; filter: string; client: Endpoint; server: Endpoint; truncated: boolean };
}

interface Endpoint {
  host: string;
  port: string;
  bytes: number;
}

const MAGIC = 0x4b504257;
/** A busy WireBuddy is asked again for this long. */
const BUSY_GIVE_UP_MS = 3 * 60_000;
/** wb.all() gives up above this. */
const MAX_ALL = 64 * 1024 * 1024;

(() => {
  const meta = (name: string): string => document.querySelector(`meta[name="${name}"]`)?.getAttribute("content") ?? "";
  const doc = meta("wb-doc");
  // WireBuddy's page: the only one the frame-ancestors policy lets frame a panel
  const parentOrigin = location.ancestorOrigins?.[0] ?? "*";
  const post = (msg: Record<string, unknown>): void => parent.postMessage({ wb: 1, ...msg }, parentOrigin);

  let replaced = false;
  let sent = 0;
  let second = 0;
  const report = (body: Record<string, unknown>): void => {
    if (replaced) return;
    // At most 50 a second: an error in a render loop is one line
    const now = Math.floor(Date.now() / 1000);
    if (now !== second) [second, sent] = [now, 0];
    if (++sent > 50) return;
    fetch("/_wb/report", { method: "POST", headers: { "content-type": "application/json", "x-wb-doc": doc }, body: JSON.stringify(body), keepalive: true })
      .then((r) => {
        if (r.status === 409) shownElsewhere();
      })
      .catch(() => {});
  };

  /** Another WireBuddy tab shows this panel now. */
  const shownElsewhere = (): void => {
    replaced = true;
    document.body.replaceChildren(h("p", { style: "padding:1em;color:var(--wb-muted)" }, "Shown in another WireBuddy tab."));
  };

  const text = (v: unknown): string => {
    if (typeof v === "string") return v;
    if (v instanceof Error) return v.stack ?? v.message;
    try {
      return JSON.stringify(v);
    } catch {
      return String(v);
    }
  };
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    const original = console[level].bind(console);
    console[level] = (...args: unknown[]) => {
      original(...args);
      report({ kind: "log", level, text: args.map(text).join(" ").slice(0, 2000) });
    };
  }
  const reportError = (e: unknown): void => report({ kind: "error", message: e instanceof Error ? e.message : text(e), stack: e instanceof Error ? e.stack : "" });
  addEventListener("error", (e) => report({ kind: "error", message: e.message, stack: e.error instanceof Error ? e.error.stack : `${e.filename}:${e.lineno}:${e.colno}` }));
  addEventListener("unhandledrejection", (e) => {
    const r = e.reason;
    report({ kind: "error", message: r instanceof Error ? r.message : text(r), stack: r instanceof Error ? r.stack : "" });
  });
  document.addEventListener("securitypolicyviolation", (e) => report({ kind: "csp", directive: e.effectiveDirective, blocked: e.blockedURI }));

  // The page checks that the panel responds, and whether it runs in a process of its own
  addEventListener("message", (e) => {
    if (e.source !== parent || (parentOrigin !== "*" && e.origin !== parentOrigin)) return;
    const m = e.data as { wb?: number; t?: string; seq?: number; ms?: number } | null;
    if (m?.wb !== 1) return;
    if (m.t === "ping") post({ t: "pong", seq: m.seq });
    else if (m.t === "probe") {
      const end = performance.now() + Math.min(m.ms ?? 0, 200);
      while (performance.now() < end);
      post({ t: "probed" });
    }
  });
  addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !e.defaultPrevented) post({ t: "key", key: "Escape" });
  });

  function h(tag: string, attrs?: Record<string, unknown> | null, ...children: (Child | Child[])[]): HTMLElement {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs ?? {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v as EventListener);
      else if (k === "class") el.className = String(v);
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c instanceof Node ? c : String(c));
    return el;
  }

  /** A canvas filling its parent (the body by default), sized for the device pixel ratio. */
  function canvas(opts: { context?: "2d" | "webgl2"; parent?: HTMLElement; onResize?: (w: number, h: number, dpr: number) => void } = {}) {
    const el = document.createElement("canvas");
    el.className = "wb-canvas";
    (opts.parent ?? document.body).append(el);
    const kind = opts.context ?? "2d";
    // Kept after drawing, so a snapshot sees WebGL output too
    const ctx = kind === "webgl2" ? el.getContext("webgl2", { preserveDrawingBuffer: true }) : el.getContext("2d");
    if (!ctx) throw new Error(`this browser can't give a ${kind} canvas`);
    const fit = (): void => {
      const dpr = devicePixelRatio || 1;
      const w = Math.max(1, Math.round(el.clientWidth * dpr));
      const ht = Math.max(1, Math.round(el.clientHeight * dpr));
      if (el.width === w && el.height === ht) return;
      el.width = w;
      el.height = ht;
      opts.onResize?.(w, ht, dpr);
    };
    new ResizeObserver(fit).observe(el);
    fit();
    return kind === "webgl2" ? { canvas: el, gl: ctx as WebGL2RenderingContext } : { canvas: el, ctx: ctx as CanvasRenderingContext2D };
  }

  /** What the panel shows, for the agent: its canvases and the start of its text. */
  function digest(): string {
    const parts = [...document.querySelectorAll("canvas")].slice(0, 4).map((c) => `canvas ${c.width}x${c.height}`);
    const t = (document.body.innerText ?? "").replace(/\s+/g, " ").trim().slice(0, 300);
    if (t) parts.push(`text "${t}"`);
    if (document.querySelectorAll("img").length) parts.push(`${document.querySelectorAll("img").length} images`);
    return parts.join("; ") || "nothing yet";
  }

  const hex = (u8: Uint8Array, max = 256): string => {
    const rows: string[] = [];
    for (let i = 0; i < Math.min(u8.length, max); i += 16) {
      const row = [...u8.subarray(i, Math.min(i + 16, u8.length, max))];
      rows.push(`${i.toString(16).padStart(4, "0")}  ${row.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47)}  ${row.map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("")}`);
    }
    if (u8.length > max) rows.push(`… ${u8.length - max} more bytes`);
    return rows.join("\n");
  };

  // --- the view, and events about it

  let view: PanelView = JSON.parse(meta("wb-view") || "null") ?? { file: null, epoch: 0, frames: 0, displayed: 0, filter: "", selected: null, selection: null, marked: 0, live: false, capture: "idle" };
  const listeners = new Map<WbEvent, Set<(v: never) => unknown>>();
  /** Calls `fn` on an event; returns a function that stops it. */
  function on(event: WbEvent, fn: (v: never) => unknown): () => void {
    if (!["view", "select", "packets", "reset", "visible", "theme"].includes(event)) throw new Error(`wb.on: no event "${event}"`);
    const set = listeners.get(event) ?? new Set();
    listeners.set(event, set);
    set.add(fn);
    return () => void set.delete(fn);
  }
  const emit = (event: WbEvent, v: unknown): void => {
    for (const fn of [...(listeners.get(event) ?? [])]) {
      try {
        const r = (fn as (v: unknown) => unknown)(v);
        if (r instanceof Promise) r.catch(reportError);
      } catch (e) {
        reportError(e);
      }
    }
  };
  const objectURLs = new Set<string>();
  const stream = new EventSource(`/_wb/events?doc=${encodeURIComponent(doc)}`);
  const dataOf = (e: Event): unknown => JSON.parse((e as MessageEvent<string>).data);
  /** Takes a new view; one of another epoch (also missed while disconnected) means starting over. */
  const setView = (next: PanelView, why = "changed"): void => {
    const before = view;
    view = next;
    if (next.epoch !== before.epoch) {
      for (const url of objectURLs) URL.revokeObjectURL(url);
      objectURLs.clear();
      emit("reset", { epoch: next.epoch, why });
    }
    if (next.selected !== before.selected) emit("select", next.selected);
    emit("view", next);
  };
  stream.addEventListener("view", (e) => setView(dataOf(e) as PanelView));
  stream.addEventListener("packets", (e) => emit("packets", dataOf(e)));
  stream.addEventListener("reset", (e) => {
    const r = dataOf(e) as { why: string; view: PanelView };
    setView(r.view, r.why);
  });
  stream.addEventListener("bye", (e) => {
    stream.close();
    if ((dataOf(e) as { why: string }).why === "replaced") shownElsewhere();
  });
  document.addEventListener("visibilitychange", () => emit("visible", !document.hidden));
  const dark = matchMedia("(prefers-color-scheme: dark)");
  dark.addEventListener("change", () => emit("theme", dark.matches ? "dark" : "light"));

  // --- the capture's data

  /** A failed wb call; `code` tells why (bad-args, filter, no-capture, stale, gone, too-large, busy, too-slow, internal). */
  class WbError extends Error {
    constructor(
      message: string,
      readonly code: string,
      readonly hint?: string,
      readonly retryMs?: number,
    ) {
      super(message);
      this.name = "WbError";
    }
  }
  const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

  /** POSTs to the panel's data API for the data of `epoch`; a busy server is asked again, as often as it says. */
  async function request(method: string, body: object, epoch = view.epoch): Promise<Response> {
    const giveUp = Date.now() + BUSY_GIVE_UP_MS;
    for (;;) {
      const r = await fetch(`/_wb/api/${method}`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-wb-doc": doc },
        body: JSON.stringify({ ...body, epoch }),
      });
      if (r.ok) return r;
      let e: { error?: string; code?: string; hint?: string; retryMs?: number } = {};
      try {
        e = await r.json();
      } catch {
        // not JSON
      }
      if (e.code === "replaced") shownElsewhere();
      if (e.code === "busy" && Date.now() < giveUp) {
        await sleep(Math.min(Math.max(e.retryMs ?? 200, 50), 60_000));
        continue;
      }
      throw new WbError(e.error ?? `HTTP ${r.status}`, e.code ?? "internal", e.hint, e.retryMs);
    }
  }

  /** A public call: failures reach the agent too, except the ones the panel just waits out. */
  function reported<A extends unknown[], T>(name: string, fn: (...a: A) => Promise<T>): (...a: A) => Promise<T> {
    return async (...a: A) => {
      try {
        return await fn(...a);
      } catch (e) {
        if (e instanceof WbError && !["stale", "replaced", "no-capture"].includes(e.code)) console.warn(`wb.${name} failed: ${e.message}${e.hint ? ` (${e.hint})` : ""}`);
        throw e;
      }
    };
  }

  function makePage(head: PageHead, frames: Uint32Array, times: Float64Array, lens: Uint32Array, offsets: Uint32Array, data: Uint8Array, dirs: Uint8Array | null): Page {
    const fields = head.fields ?? {};
    const bytes = (i: number): Uint8Array => data.subarray(offsets[i], offsets[i + 1]);
    let packets: Page["packets"] | null = null;
    return {
      n: head.n,
      frames,
      times,
      lens,
      offsets,
      data,
      dirs,
      bytes,
      fields,
      clipped: head.clipped ?? [],
      next: head.next,
      done: head.done,
      live: head.live,
      pending: !!head.pending,
      epoch: head.epoch,
      total: head.total,
      dropped: head.dropped ?? 0,
      layer: head.layer,
      get packets() {
        packets ??= Array.from({ length: head.n }, (_, i) => ({
          frame: frames[i],
          time: times[i],
          len: lens[i],
          bytes: bytes(i),
          ...(dirs ? { dir: dirs[i] } : {}),
          fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, v[i]])),
        }));
        return packets;
      },
    };
  }

  let warnedClipped = false;
  function decode(buf: ArrayBuffer): { page: Page; head: PageHead } {
    const dv = new DataView(buf);
    if (buf.byteLength < 8 || dv.getUint32(0, true) !== MAGIC) throw new WbError("not a WireBuddy page", "internal");
    const h = dv.getUint32(4, true);
    const head = JSON.parse(new TextDecoder().decode(new Uint8Array(buf, 8, h))) as PageHead;
    const n = head.n;
    let at = 8 + h;
    const times = new Float64Array(buf, at, n);
    at += 8 * n;
    const frames = new Uint32Array(buf, at, n);
    at += 4 * n;
    const lens = new Uint32Array(buf, at, n);
    at += 4 * n;
    const offsets = new Uint32Array(buf, at, n + 1);
    at += 4 * (n + 1);
    const dirs = head.dirs ? new Uint8Array(buf, at, n) : null;
    if (dirs) at += n;
    const page = makePage(head, frames, times, lens, offsets, new Uint8Array(buf, at, offsets[n]), dirs);
    if (page.clipped.length && !warnedClipped) {
      warnedClipped = true;
      console.warn(`wb.packets: Wireshark cut long values of ${[...new Set(page.clipped.map((c) => c[1]))].join(", ")} (see page.clipped); bytes: "<field>" gives a whole value`);
    }
    return { page, head };
  }

  async function packets(q: Query = {}, epoch = view.epoch): Promise<Page> {
    const { from: _from, ...body } = q;
    return decode(await (await request("packets", body, epoch)).arrayBuffer()).page;
  }

  /** Pages joined into one. */
  function merge(pages: Page[]): Page {
    const last = pages[pages.length - 1];
    const n = pages.reduce((a, p) => a + p.n, 0);
    const size = pages.reduce((a, p) => a + p.data.length, 0);
    const frames = new Uint32Array(n);
    const times = new Float64Array(n);
    const lens = new Uint32Array(n);
    const offsets = new Uint32Array(n + 1);
    const data = new Uint8Array(size);
    const fields: Record<string, string[]> = Object.fromEntries(Object.keys(last.fields).map((k) => [k, []]));
    const clipped: [number, string][] = [];
    let i = 0;
    let at = 0;
    for (const p of pages) {
      frames.set(p.frames, i);
      times.set(p.times, i);
      lens.set(p.lens, i);
      for (let k = 0; k < p.n; k++) offsets[i + k] = at + p.offsets[k];
      data.set(p.data, at);
      for (const [k, v] of Object.entries(p.fields)) fields[k]?.push(...v);
      for (const [row, f] of p.clipped) clipped.push([row + i, f]);
      i += p.n;
      at += p.data.length;
    }
    offsets[n] = at;
    const head: PageHead = { ...last, n, epoch: pages[0].epoch, fields, clipped, dropped: pages.reduce((a, p) => a + p.dropped, 0), dirs: false };
    return makePage(head, frames, times, lens, offsets, data, null);
  }

  async function all(q: Query = {}): Promise<Page> {
    const pages: Page[] = [];
    let after = q.after ?? 0;
    let size = 0;
    // All pages of one capture: another one in between means stale
    const epoch = view.epoch;
    for (;;) {
      const p = await packets({ ...q, after }, epoch);
      pages.push(p);
      size += p.data.length + p.n * 20;
      if (size > MAX_ALL) throw new WbError("over 64 MiB: use wb.subscribe, or ask for less (fewer packets, a layer instead of whole frames)", "too-large");
      if (p.done || p.next === null) return merge(pages);
      after = p.next;
    }
  }

  /** Pages through `q` and, while a capture runs, the packets that come; batch() is awaited before the next page. */
  function subscribe(
    q: Query,
    h: { batch(page: Page, info: { live: boolean }): unknown; reset?(): unknown; error?(e: Error): unknown },
  ): { close(): void } {
    let closed = false;
    let restart = false;
    let wake: (() => void) | null = null;
    // An event while nobody waits is kept for the next wait
    let nudged = false;
    const nudge = (): void => {
      const w = wake;
      wake = null;
      if (w) w();
      else nudged = true;
    };
    const wait = (ms: number): Promise<void> =>
      new Promise((done) => {
        if (nudged || closed) {
          nudged = false;
          return done();
        }
        wake = done;
        if (ms) setTimeout(() => wake === done && nudge(), ms);
      });
    const offs = [
      on("packets", nudge),
      on("reset", () => {
        restart = true;
        nudge();
      }),
    ];
    const start = (): number => (q.from === "end" ? view.frames : (q.after ?? 0));
    void (async () => {
      let after = start();
      let epoch = view.epoch;
      while (!closed) {
        if (restart || view.epoch !== epoch) {
          restart = false;
          await h.reset?.();
          after = start();
          epoch = view.epoch;
        }
        let page: Page;
        try {
          page = await packets({ ...q, after }, epoch);
        } catch (e) {
          if (closed) return;
          // Another file, or none yet: wait for its view
          if (e instanceof WbError && e.code === "stale") {
            await wait(2000);
            continue;
          }
          if (e instanceof WbError && e.code === "no-capture") {
            await wait(0);
            continue;
          }
          if (e instanceof WbError) console.warn(`wb.subscribe failed: ${e.message}${e.hint ? ` (${e.hint})` : ""}`);
          h.error?.(e as Error);
          return;
        }
        if (closed || restart) continue;
        if (page.n) await h.batch(page, { live: page.live });
        if (page.next !== null) after = page.next;
        // The panel engine reads a live file again at most once a second
        if (page.done) await wait(page.pending ? 1000 : 0);
      }
    })().catch(reportError);
    return {
      close() {
        closed = true;
        for (const off of offs) off();
        nudge();
      },
    };
  }

  const fromBase64 = (s: string): Uint8Array => {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  };

  async function frame(n: number, opts: { tree?: boolean; bytes?: boolean } = {}) {
    const r = (await (await request("frame", { frame: n, ...opts })).json()) as { frame: number; tree: unknown; bytes: string; sources: { name: string; bytes: string }[]; followers: [string, string][] };
    return { frame: r.frame, tree: r.tree, bytes: fromBase64(r.bytes), sources: r.sources.map((s) => ({ name: s.name, bytes: fromBase64(s.bytes) })), followers: r.followers };
  }

  async function follow(which: { frame?: number; protocol?: string; stream?: number; filter?: string }, opts: { offset?: number; maxBytes?: number } = {}) {
    const { page, head } = decode(await (await request("follow", { ...which, ...opts })).arrayBuffer());
    const f = head.follow!;
    return { protocol: f.protocol, filter: f.filter, client: f.client, server: f.server, truncated: f.truncated, next: page.next, chunks: page };
  }

  let warnedObjects = false;
  async function objects(kind: string) {
    const r = (await (await request("objects", { kind })).json()) as { objects: { id: string; frame: number; host: string; type: string; filename: string; size: number; sha1: string }[]; truncated: boolean };
    if (r.truncated && !warnedObjects) {
      warnedObjects = true;
      console.warn(`wb.objects: only the first ${r.objects.length} ${kind} objects are listed`);
    }
    return r.objects;
  }

  async function object(id: string) {
    const r = await request("object", { id });
    return { type: decodeURIComponent(r.headers.get("x-wb-type") ?? ""), filename: decodeURIComponent(r.headers.get("x-wb-filename") ?? ""), bytes: new Uint8Array(await r.arrayBuffer()) };
  }

  async function objectURL(id: string): Promise<string> {
    const o = await object(id);
    const url = URL.createObjectURL(new Blob([o.bytes as BlobPart], { type: o.type }));
    objectURLs.add(url);
    return url;
  }

  const tap = async (name: string, opts: { filter?: string } = {}): Promise<unknown> => (await request("tap", { name, ...opts })).json();
  const check = async (filter: string): Promise<{ ok: boolean; error?: string; warning?: string }> => (await request("check", { filter })).json();

  const wb = {
    /** The panel's params from its extension.json. */
    params: JSON.parse(meta("wb-params") || "{}") as Record<string, unknown>,
    /** Its extension's name. */
    name: meta("wb-name"),
    /** What the user's view shows now. */
    get view(): PanelView {
      return view;
    },
    on,
    packets: reported("packets", packets),
    all: reported("all", all),
    subscribe,
    frame: reported("frame", frame),
    follow: reported("follow", follow),
    objects: reported("objects", objects),
    object: reported("object", object),
    objectURL: reported("objectURL", objectURL),
    tap: reported("tap", tap),
    check: reported("check", check),
    /** Call once the first view is drawn: the agent hears that it works, and what it shows. */
    ready(): void {
      report({ kind: "ready", digest: digest() });
    },
    /** A short status line under the window, e.g. "75 frames · 25 fps". */
    status(t: unknown): void {
      report({ kind: "status", text: String(t) });
    },
    title(t: unknown): void {
      report({ kind: "title", text: String(t) });
    },
    h,
    canvas,
    hex,
    text: (u8: Uint8Array): string => new TextDecoder().decode(u8),
    fmt: {
      bytes: (n: number): string => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`),
      duration: (s: number): string => `${Math.floor(s / 60)}:${(s % 60).toFixed(2).padStart(5, "0")}`,
    },
  };
  Object.defineProperty(window, "wb", { value: Object.freeze(wb) });
  post({ t: "hello" });
})();
