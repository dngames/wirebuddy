/**
 * The `wb` global of a WireBuddy panel, loaded before the panel's main.js: its
 * link to WireBuddy (readiness, status, errors to the agent, the page's
 * watchdog) and small helpers. Panels have no network but their own origin.
 */

type Child = Node | string | number | null | undefined | false;

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

  const wb = {
    /** The panel's params from its extension.json. */
    params: JSON.parse(meta("wb-params") || "{}") as Record<string, unknown>,
    /** Its extension's name. */
    name: meta("wb-name"),
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
