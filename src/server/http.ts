import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { WebSocketServer, type WebSocket } from "ws";
import { CAPTURE_FILE, CONV_TYPES, StaleGenerationError, type ConvType, type Viewer } from "./viewer.ts";
import type { CaptureRequest, CustomColumn, DirEntry, DirListing, ExportRequest, IoGraphSpec, RecentFiles, ServerEvent } from "../shared/api.ts";

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json",
  ".svg": "image/svg+xml",
};

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

type Handler = (q: URLSearchParams, body: any) => unknown | Promise<unknown>;

export interface HttpServer {
  url: string;
  close(): void;
}

export async function startHttp(viewer: Viewer, opts: { port: number; token: string; webRoot: string }): Promise<HttpServer> {
  const { token, webRoot } = opts;

  const num = (q: URLSearchParams, name: string): number => {
    const v = Number(q.get(name));
    if (!q.has(name) || !Number.isFinite(v)) throw new HttpError(400, `missing or invalid "${name}"`);
    return v;
  };
  const convType = (q: URLSearchParams): ConvType => {
    const t = q.get("type") as ConvType;
    if (!CONV_TYPES.includes(t)) throw new HttpError(400, `type must be one of ${CONV_TYPES.join(", ")}`);
    return t;
  };

  const get: Record<string, Handler> = {
    "/api/state": () => viewer.state,
    "/api/rows": (q) => viewer.rows(num(q, "gen"), num(q, "start"), num(q, "count")),
    "/api/frame": (q) => viewer.frame(num(q, "num")),
    "/api/filter/check": (q) => viewer.checkFilter(q.get("filter") ?? ""),
    "/api/filter/complete": async (q) => ({ fields: await viewer.complete(q.get("field") ?? "") }),
    "/api/files": (q) => listDir(q.get("dir") || defaultDir(viewer), q.get("kind") === "any"),
    "/api/recent": () => recentFiles(viewer.recent),
    "/api/stats/phs": (q) => viewer.phs(q.get("filter") ?? ""),
    "/api/stats/conv": (q) => viewer.conversations(convType(q), q.get("filter") ?? ""),
    "/api/stats/endpt": (q) => viewer.endpoints(convType(q), q.get("filter") ?? ""),
    "/api/stats/expert": (q) => viewer.expert(q.get("filter") ?? ""),
    "/api/stats/iograph": (q) => viewer.ioGraph(graphs(q.get("graphs")), num(q, "interval")),
    "/api/frame-at": async (q) => ({ frame: await viewer.frameAt(num(q, "t")) }),
    "/api/follow": (q) => viewer.follow(q.get("proto") || "TCP", q.get("filter") ?? ""),
    "/api/capture/interfaces": () => viewer.capture.interfaces(),
    "/api/capture/check": (q) => viewer.capture.checkFilter(q.get("iface") ?? "", q.get("filter") ?? ""),
    "/api/capture/activity": () => viewer.capture.activity(),
  };

  const ok = { ok: true };
  const post: Record<string, Handler> = {
    "/api/filter": (_q, b) => viewer.setFilter(String(b.filter ?? ""), "user"),
    "/api/select": (_q, b) => (viewer.select(b.frame ?? null, "user"), ok),
    "/api/open": async (_q, b) => (await viewer.open(String(b.path ?? "")), ok),
    "/api/close": async () => (await viewer.close(), ok),
    "/api/marks": (_q, b) => (viewer.mark(numbers(b.frames), String(b.note ?? ""), "user"), ok),
    "/api/marks/clear": (_q, b) => (viewer.clearMarks(b.frames ? numbers(b.frames) : undefined), ok),
    "/api/wireshark": (_q, b) => (viewer.openInWireshark(b.frame ?? null), ok),
    "/api/columns": (_q, b) => viewer.setColumns(columnList(b.columns), "user"),
    "/api/tls": async (_q, b) => (await viewer.setTlsKeylog(b.keylog ? String(b.keylog) : null), ok),
    "/api/export": (_q, b) => viewer.exportPackets(exportRequest(b), "user"),
    "/api/capture/start": async (_q, b) => (await viewer.capture.start(b as CaptureRequest), ok),
    "/api/capture/stop": () => (viewer.capture.stop(), ok),
  };

  let port = opts.port;
  const localHosts = () => new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  // Rejects DNS-rebinding hosts and cross-site requests
  const trusted = (req: IncomingMessage): boolean => {
    const hosts = localHosts();
    if (!req.headers.host || !hosts.has(req.headers.host)) return false;
    const origin = req.headers.origin;
    if (origin && origin !== "null") {
      try {
        if (!hosts.has(new URL(origin).host)) return false;
      } catch {
        return false;
      }
    }
    return true;
  };
  const hasToken = (req: IncomingMessage, q: URLSearchParams): boolean =>
    req.headers["x-wirebuddy-token"] === token || q.get("token") === token;

  const send = (res: ServerResponse, status: number, body: unknown) => {
    const json = JSON.stringify(body);
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(json);
  };

  const server = createServer(async (req, res) => {
    try {
      if (!trusted(req)) return send(res, 403, { error: "forbidden" });
      const url = parseUrl(req.url);
      if (!url) return send(res, 400, { error: "bad request" });

      if (!url.pathname.startsWith("/api/")) return serveStatic(res, webRoot, url.pathname);
      if (!hasToken(req, url.searchParams)) return send(res, 401, { error: "missing or wrong token" });

      const handler = req.method === "GET" ? get[url.pathname] : req.method === "POST" ? post[url.pathname] : undefined;
      if (!handler) return send(res, 404, { error: `no route ${req.method} ${url.pathname}` });
      const body = req.method === "POST" ? await readJson(req) : undefined;
      send(res, 200, await handler(url.searchParams, body));
    } catch (err) {
      if (res.headersSent) return res.destroy();
      if (err instanceof StaleGenerationError) return send(res, 409, { error: err.message });
      const status = err instanceof HttpError ? err.status : 400;
      send(res, status, { error: (err as Error).message });
    }
  });

  const wss = new WebSocketServer({ noServer: true });
  server.on("upgrade", (req, socket, head) => {
    const url = parseUrl(req.url);
    if (!url || url.pathname !== "/ws" || !trusted(req) || !hasToken(req, url.searchParams)) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.send(JSON.stringify({ type: "state", state: viewer.state } satisfies ServerEvent));
    });
  });

  const broadcast = (event: ServerEvent) => {
    let data: string;
    try {
      data = JSON.stringify(event);
    } catch {
      return;
    }
    for (const ws of wss.clients as Set<WebSocket>) if (ws.readyState === ws.OPEN) ws.send(data);
  };
  // Live captures change state many times a second; coalesce to ~10 updates/s
  let stateTimer: NodeJS.Timeout | null = null;
  viewer.on("state", () => {
    if (stateTimer) return;
    stateTimer = setTimeout(() => {
      stateTimer = null;
      broadcast({ type: "state", state: viewer.state });
    }, 100);
  });
  viewer.on("toast", (level: "info" | "error", text: string) => broadcast({ type: "toast", level, text }));

  await new Promise<void>((resolveListen, reject) => {
    const tryListen = (p: number, fallback: boolean) => {
      server.once("error", (err: NodeJS.ErrnoException) => {
        if (fallback && err.code === "EADDRINUSE") tryListen(0, false);
        else reject(err);
      });
      server.listen(p, "127.0.0.1", () => resolveListen());
    };
    tryListen(port, port !== 0);
  });
  const address = server.address();
  port = typeof address === "object" && address ? address.port : port;

  return {
    url: `http://127.0.0.1:${port}/?token=${token}`,
    close: () => {
      wss.close();
      server.close();
    },
  };
}

function numbers(value: unknown): number[] {
  if (!Array.isArray(value)) throw new HttpError(400, "frames must be an array of frame numbers");
  if (value.length > 10000) throw new HttpError(400, "too many frames");
  return value.map(Number).filter(Number.isInteger);
}

function graphs(raw: string | null): IoGraphSpec[] {
  let list: unknown;
  try {
    list = JSON.parse(raw ?? "");
  } catch {
    throw new HttpError(400, "graphs must be a JSON array");
  }
  if (!Array.isArray(list)) throw new HttpError(400, "graphs must be a JSON array");
  return list.map((g) => ({ metric: String(g?.metric ?? "packets") as IoGraphSpec["metric"], filter: String(g?.filter ?? "") }));
}

function columnList(value: unknown): CustomColumn[] {
  if (!Array.isArray(value)) throw new HttpError(400, "columns must be an array");
  return value.map((c) => ({ field: String(c?.field ?? ""), title: String(c?.title ?? "") }));
}

function exportRequest(b: any): ExportRequest {
  return { path: String(b.path ?? ""), which: b.which, range: b.range === undefined ? undefined : String(b.range), overwrite: !!b.overwrite };
}

/** Request URLs are client input: malformed ones must not throw out of a handler. */
function parseUrl(raw: string | undefined): URL | null {
  try {
    const url = new URL(raw ?? "/", "http://localhost");
    decodeURIComponent(url.pathname);
    return url;
  } catch {
    return null;
  }
}

function readJson(req: IncomingMessage): Promise<any> {
  return new Promise((resolveBody, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 1024 * 1024) {
        reject(new HttpError(413, "request body too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      try {
        resolveBody(text ? JSON.parse(text) : {});
      } catch {
        reject(new HttpError(400, "invalid JSON body"));
      }
    });
    req.on("error", reject);
  });
}

function serveStatic(res: ServerResponse, root: string, pathname: string): void {
  const rel = pathname === "/" ? "index.html" : decodeURIComponent(pathname).replace(/^\/+/, "");
  const file = resolve(root, rel);
  if (!file.startsWith(resolve(root) + "/") || !existsSync(file) || !statSync(file).isFile()) {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("not found");
    return;
  }
  res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream", "cache-control": "no-cache" });
  res.end(readFileSync(file));
}

function defaultDir(viewer: Viewer): string {
  if (viewer.state.file) return dirname(viewer.state.file);
  if (existsSync(viewer.capture.state.dir)) return viewer.capture.state.dir;
  return homedir();
}

function listDir(dir: string, anyFile = false): DirListing {
  const abs = resolve(dir);
  const st = statSync(abs, { throwIfNoEntry: false });
  if (!st?.isDirectory()) throw new HttpError(400, `not a directory: ${abs}`);
  const entries: DirEntry[] = [];
  for (const d of readdirSync(abs, { withFileTypes: true })) {
    if (d.name.startsWith(".")) continue;
    const path = join(abs, d.name);
    const s = statSync(path, { throwIfNoEntry: false });
    if (!s) continue;
    if (s.isDirectory()) entries.push({ name: d.name, path, isDir: true, size: 0, mtime: s.mtimeMs });
    else if (s.isFile() && (anyFile || CAPTURE_FILE.test(d.name))) entries.push({ name: d.name, path, isDir: false, size: s.size, mtime: s.mtimeMs });
  }
  entries.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1));
  const parent = dirname(abs);
  return { dir: abs, parent: parent === abs ? null : parent, entries };
}

/** Our own history first, then Wireshark's recent files. */
function recentFiles(own: string[]): RecentFiles {
  const paths = [...own];
  try {
    const text = readFileSync(join(homedir(), ".config/wireshark/recent_common"), "utf8");
    for (const m of text.matchAll(/^recent\.capture_file:\s*(.+)$/gm)) paths.push(m[1].trim());
  } catch {
    // no Wireshark history
  }
  const files: RecentFiles["files"] = [];
  for (const path of new Set(paths)) {
    const s = statSync(path, { throwIfNoEntry: false });
    if (s?.isFile()) files.push({ path, size: s.size, mtime: s.mtimeMs });
    if (files.length >= 15) break;
  }
  return { files };
}
