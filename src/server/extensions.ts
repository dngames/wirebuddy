/**
 * Extensions: Lua dissectors the agent writes for protocols Wireshark doesn't
 * know. One folder per extension with an `extension.json` and its `*.lua`
 * files, in WireBuddy's own data folder; the user's Wireshark folders stay
 * untouched. sharkd (and Open in Wireshark) get a plugin folder of their own:
 * links to the real global plugins, a prelude that keeps plugins from breaking
 * sharkd, and a loader that loads the enabled extensions and reports on each.
 */

import { execFileSync, spawn } from "node:child_process";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statfsSync,
  statSync,
  symlinkSync,
  writeFileSync,
  type Stats,
} from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { basename, delimiter, dirname, extname, join, resolve, sep } from "node:path";
import type { ExtensionInfo, ExtensionList } from "../shared/api.ts";
import type { LuaReport } from "./sharkd.ts";
import { printable } from "./text.ts";

/** Extension folder names: also what the agent and the UI call them. */
const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const MANIFEST = "extension.json";
const MAX_MANIFEST = 64 * 1024;
/** A panel's folder in its extension, and what may be in it. */
const PANEL_DIR = "panel";
const PANEL_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PANEL_MAX_DEPTH = 4;
const PANEL_MAX_FILES = 200;
const PANEL_MAX_FILE = 8 * 1024 * 1024;
const PANEL_MAX_TOTAL = 16 * 1024 * 1024;
/** Files a panel's frame is served, by type; others are left out. */
export const PANEL_TYPES: Record<string, string> = {
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".wasm": "application/wasm",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".avif": "image/avif",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".otf": "font/otf",
  ".txt": "text/plain",
  ".csv": "text/csv",
  ".bin": "application/octet-stream",
  ".glsl": "text/plain",
};
const OVERLAY_PREFIX = "wirebuddy-plugins-";

/** Runs before every Wireshark plugin while WireBuddy's plugin folder is used. */
const PRELUDE = `-- WireBuddy's prelude: runs before every Wireshark plugin in WireBuddy's sharkd and Wireshark.
-- print() from a plugin would corrupt sharkd's JSON answers: it goes to stderr
print = function(...)
  local parts = {}
  for i = 1, select("#", ...) do parts[#parts + 1] = tostring((select(i, ...))) end
  io.stderr:write(table.concat(parts, "\\t"), "\\n")
end
-- Without a GUI these crash sharkd: make them ordinary Lua errors
if not gui_enabled() then
  for _, name in ipairs({ "reload_lua_plugins", "reload_packets", "reload", "retap_packets", "apply_filter", "set_filter",
      "get_filter", "copy_to_clipboard", "open_capture_file", "browser_open_url", "browser_open_data_file", "set_color_filter_slot",
      "get_color_filter_slot", "redissect_packets" }) do
    _G[name] = function() error(name .. "() needs the Wireshark GUI", 2) end
  end
  for _, name in ipairs({ "TextWindow", "ProgDlg" }) do
    local fail = function() error(name .. " needs the Wireshark GUI", 2) end
    _G[name] = setmetatable({}, { __index = fail, __call = fail })
  end
end
-- io.write() and io.stdout would corrupt sharkd's JSON answers too
io.output(io.stderr)
io.stdout = io.stderr
-- Extension code running more than 1 s without returning (an endless loop) fails like any Lua error.
-- A packet it failed on that way fails at once from then on, and so does every packet once 3 did.
local running
local self = debug.getinfo(1, "S").source
local function hook()
  local r = running
  if not r or os.clock() - r.at <= 1 then return end
  -- Not inside these wrappers: the error has to come from the extension's code, at its next instruction
  if debug.getinfo(2, "S").source == self then return debug.sethook(hook, "", 1) end
  r.tripped = true
  error("ran for more than 1 s without returning (an endless loop?)", 2)
end
-- Catching that error would leave the loop running unguarded: it goes on up
local realpcall, realxpcall, coresume, cocreate, cowrap = pcall, xpcall, coroutine.resume, coroutine.create, coroutine.wrap
local function rethrow(res)
  if not res[1] and running.tripped then error(res[2], 0) end
  return table.unpack(res, 1, res.n)
end
pcall = function(...)
  if not running then return realpcall(...) end
  return rethrow(table.pack(realpcall(...)))
end
xpcall = function(...)
  if not running then return realxpcall(...) end
  return rethrow(table.pack(realxpcall(...)))
end
coroutine.resume = function(...)
  if not running then return coresume(...) end
  return rethrow(table.pack(coresume(...)))
end
-- Threads started in extension code get the hook too
coroutine.create = function(f)
  local co = cocreate(f)
  if running then debug.sethook(co, hook, "", 10000) end
  return co
end
coroutine.wrap = function(f)
  if not running or type(f) ~= "function" then return cowrap(f) end
  local co = coroutine.create(f)
  return function(...)
    local res = table.pack(coroutine.resume(co, ...))
    if not res[1] then
      coroutine.close(co)
      error(res[2], 0)
    end
    return table.unpack(res, 2, res.n)
  end
end
-- Per reading of a file (this protocol's init runs before each): the packets whose errors were
-- reported. Per capture (told apart by the first packet extension code sees, so kept over live
-- reloads): per function its slow packets and strikes.
local capture, slow, strikes, reported, reports, fresh = nil, {}, {}, {}, 0, true
local reset = Proto("wirebuddy", "WireBuddy")
function reset.init()
  reported, reports, fresh = {}, 0, true
end
local function packet_of(a, b)
  for _, x in ipairs({ a, b }) do
    if typeof(x) == "Pinfo" then return x end
  end
end
-- First-pass errors go to WireBuddy, which tells the agent
local function report_error(pinfo, err)
  if not pinfo or pinfo.visited or reported[pinfo.number] then return end
  reported[pinfo.number] = true
  reports = reports + 1
  if reports <= 1000 then
    io.stderr:write("\\nWIREBUDDY-LUA-ERROR\\t", pinfo.number, "\\t", (tostring(err):gsub("%c+", " ")), "\\n")
  elseif reports == 1001 then
    io.stderr:write("\\nWIREBUDDY-LUA-ERROR\\t0\\tand more\\n")
  end
end
function WIREBUDDY_GUARD(fn)
  local info = debug.getinfo(fn, "S")
  local where = info.short_src .. ":" .. info.linedefined
  return function(...)
    if running then return fn(...) end
    local pinfo = packet_of(...)
    if pinfo and fresh and not pinfo.visited then
      fresh = false
      local key = pinfo.number .. ":" .. tostring(pinfo.abs_ts)
      if key ~= capture then capture, slow, strikes = key, {}, {} end
    end
    local err
    if (strikes[fn] or 0) >= 3 then
      err = where .. ": skipped: it ran too long on 3 packets (an endless loop?)"
    elseif pinfo and slow[fn] and slow[fn][pinfo.number] then
      err = where .. ": skipped: it ran too long on this packet before (an endless loop?)"
    end
    if err then
      report_error(pinfo, err)
      error(err, 0)
    end
    local r = { at = os.clock() }
    local oldHook, oldMask, oldCount = debug.gethook()
    running = r
    debug.sethook(hook, "", 10000)
    local res = table.pack(realxpcall(fn, function(e) return e end, ...))
    running = nil
    if type(oldHook) == "function" then debug.sethook(oldHook, oldMask, oldCount) else debug.sethook() end
    if r.tripped then
      strikes[fn] = (strikes[fn] or 0) + 1
      if pinfo then
        slow[fn] = slow[fn] or {}
        slow[fn][pinfo.number] = true
      end
    end
    if not res[1] then
      report_error(pinfo, res[2])
      error(res[2], 0)
    end
    return table.unpack(res, 2, res.n)
  end
end
`;

/**
 * Loads the extensions WIREBUDDY_EXTENSIONS_LOAD lists, one per line as
 * name, folder and files separated by tabs, reporting on stderr.
 */
const LOADER = `-- WireBuddy's extension loader: WIREBUDDY_EXTENSIONS_LOAD lists one extension per line, as name, folder and files separated by tabs
local function report(kind, name, ...)
  -- The newline first: a plugin may have left half a line on stderr
  local line = "\\nWIREBUDDY-EXT-" .. kind .. "\\t" .. name
  for _, text in ipairs({ ... }) do line = line .. "\\t" .. (tostring(text):gsub("[%c]+", " ")) end
  io.stderr:write(line, "\\n")
end
local guard = WIREBUDDY_GUARD
-- Errors from WireBuddy's wrappers point at the extension's line, not at the loader
local function caller()
  for level = 3, 12 do
    local info = debug.getinfo(level, "Sl")
    if not info then break end
    if info.currentline > 0 and not info.short_src:find("wirebuddy%-loader%.lua") then return info.short_src .. ":" .. info.currentline .. ": " end
  end
  return ""
end
local function relocated(f, ...)
  local res = table.pack(pcall(f, ...))
  if not res[1] then error(caller() .. tostring(res[2]):gsub("^[^\\n]-wirebuddy%-loader%.lua:%d+: ", ""), 0) end
  return table.unpack(res, 2, res.n)
end
local function load_files(name, folder, files)
  for _, file in ipairs(files) do
    local fh, ferr = io.open(folder .. "/" .. file, "rb")
    if not fh then error(ferr, 0) end
    local code = fh:read("a")
    fh:close()
    local chunk, cerr = load(code, "@" .. name .. "/" .. file)
    if not chunk then error(cerr, 0) end
    guard(chunk)()
  end
end
local realProto = Proto
local reg = debug.getregistry()
local protoMeta, listenerMeta = reg.Proto, reg.Listener
local realNewindex, realIndex, realListenerNewindex = protoMeta.__newindex, protoMeta.__index, listenerMeta.__newindex
local realHeuristic = realProto.register_heuristic
local function guardedHeuristic(p, list, fn) return relocated(realHeuristic, p, list, guard(fn)) end
for line in (os.getenv("WIREBUDDY_EXTENSIONS_LOAD") or ""):gmatch("[^\\n]+") do
  local parts = {}
  for part in line:gmatch("[^\\t]+") do parts[#parts + 1] = part end
  local name, folder = parts[1], parts[2]
  report("LOADING", name)
  -- The protocols it registers, as filter names, so their packets can be found; its functions run guarded
  local protos = {}
  local function record(p, pname)
    protos[#protos + 1] = tostring(pname):lower()
    return p
  end
  Proto = setmetatable({}, {
    __index = function(_, k)
      if k == "new" then return function(pname, ...) return record(relocated(realProto.new, pname, ...), pname) end end
      if k == "register_heuristic" then return guardedHeuristic end
      return realProto[k]
    end,
    __call = function(_, pname, ...) return record(relocated(realProto, pname, ...), pname) end,
  })
  protoMeta.__newindex = function(self, k, v)
    if type(v) == "function" then v = guard(v) end
    return relocated(realNewindex, self, k, v)
  end
  protoMeta.__index = function(self, k)
    if k == "register_heuristic" then return guardedHeuristic end
    return relocated(realIndex, self, k)
  end
  listenerMeta.__newindex = function(self, k, v)
    if type(v) == "function" then v = guard(v) end
    return relocated(realListenerNewindex, self, k, v)
  end
  local ok, err = pcall(load_files, name, folder, { table.unpack(parts, 3) })
  Proto = realProto
  protoMeta.__newindex, protoMeta.__index, listenerMeta.__newindex = realNewindex, realIndex, realListenerNewindex
  -- What it registered before an error stays registered
  if ok then report("OK", name, table.concat(protos, " ")) else report("ERROR", name, err, table.concat(protos, " ")) end
end
report("DONE", "")
`;

/** Dissector templates for the guide, each checked against sharkd 4.6. */
export const TEMPLATES = {
  port: `-- A protocol on a fixed UDP port (use "tcp.port" for TCP)
local acme = Proto("acme", "ACME Telemetry")
local f = {
  magic = ProtoField.uint16("acme.magic", "Magic", base.HEX),
  seq = ProtoField.uint32("acme.seq", "Sequence"),
  kind = ProtoField.uint8("acme.kind", "Kind", base.DEC, { [1] = "Status", [2] = "Points" }),
  payload = ProtoField.bytes("acme.payload", "Payload"),
}
acme.fields = f
local short = ProtoExpert.new("acme.short", "Too short for an ACME header", expert.group.MALFORMED, expert.severity.ERROR)
acme.experts = { short }

function acme.dissector(tvb, pinfo, tree)
  pinfo.cols.protocol = "ACME"
  local t = tree:add(acme, tvb())
  if tvb:len() < 7 then
    t:add_proto_expert_info(short)
    return
  end
  t:add(f.magic, tvb(0, 2))
  t:add(f.seq, tvb(2, 4))
  t:add(f.kind, tvb(6, 1))
  if tvb:len() > 7 then t:add(f.payload, tvb(7)) end
  pinfo.cols.info = string.format("seq=%d kind=%d", tvb(2, 4):uint(), tvb(6, 1):uint())
  return tvb:len()
end

DissectorTable.get("udp.port"):add(50000, acme)
`,
  heuristic: `-- A protocol recognized by its content, on any UDP port
local acme = Proto("acme", "ACME Telemetry")
local f_seq = ProtoField.uint32("acme.seq", "Sequence")
acme.fields = { f_seq }

function acme.dissector(tvb, pinfo, tree)
  -- Later packets of the conversation come here without the heuristic: check again
  if tvb:len() < 7 then return 0 end
  pinfo.cols.protocol = "ACME"
  tree:add(acme, tvb()):add(f_seq, tvb(2, 4))
  return tvb:len()
end

local function heuristic(tvb, pinfo, tree)
  if tvb:len() < 7 or tvb(0, 2):uint() ~= 0xACE1 then return false end
  acme.dissector(tvb, pinfo, tree)
  pinfo.conversation = acme
  return true
end
acme:register_heuristic("udp", heuristic)
`,
  postdissector: `-- Adds a computed field to packets other dissectors decoded
local gap = Proto("acme_gap", "ACME gap")
local f_gap = ProtoField.double("acme_gap.ms", "Since previous ACME packet (ms)")
gap.fields = { f_gap }

-- sharkd reads the file once in order, then dissects single packets in any order: key state by frame
local gaps, last = {}, nil
function gap.init()
  gaps, last = {}, nil
end

function gap.dissector(tvb, pinfo, tree)
  -- 3: UDP
  if pinfo.port_type ~= 3 or pinfo.dst_port ~= 50000 then return end
  if not pinfo.visited then
    if last then gaps[pinfo.number] = (pinfo.abs_ts - last) * 1000 end
    last = pinfo.abs_ts
  end
  if gaps[pinfo.number] then tree:add(gap, tvb(0, 0)):add(f_gap, gaps[pinfo.number]) end
end
register_postdissector(gap)
`,
  decodeAs: `-- A protocol Wireshark knows, on a port it doesn't expect (like Decode As)
DissectorTable.get("udp.port"):add(50000, Dissector.get("rtp"))
`,
};

interface State {
  /** Switched off, with why; no prototype, so any folder name is just a key. */
  off: Record<string, string>;
}

/**
 * Whether others could change what is in a folder. `dev`: its filesystem;
 * `privateDev`: set below a folder of the user's that others can't enter,
 * for entries on that folder's filesystem.
 */
interface RootTrust {
  problem: string | null;
  real: string;
  dev: number;
  privateDev: number | null;
}

interface Last {
  status: "loaded" | "error";
  error?: string;
  protocols: string[];
}

interface Saved {
  loaded: Map<string, string>;
  last: Map<string, Last>;
  previous: { loaded: Map<string, string>; last: Map<string, Last> } | null;
}

/** An extension as found on disk, with what its files are checked against again when copied. */
interface Entry {
  info: ExtensionInfo;
  folder: string;
  trust: RootTrust;
  panel: PanelManifest | null;
}

/** A panel as its extension.json describes it. */
export interface PanelManifest {
  title: string;
  size: [number, number];
  params: Record<string, unknown>;
  offer: { filter: string; text: string } | null;
  /** "control": it may set the user's display filter (after a click in it). */
  permissions: string[];
  wasm: boolean;
}

/** A panel's files as read, and checked, when it opens: all its frame is ever served. */
export interface PanelFiles {
  folder: string;
  manifest: PanelManifest;
  files: Map<string, { bytes: Buffer; type: string }>;
  /** body.html, put into the generated page. */
  body: string;
  /** Changes when a file of it changes on disk. */
  fingerprint: string;
}

export class Extensions {
  /** The user's extension folder; the agent writes here. */
  readonly dir: string;
  private readonly shared: string[];
  private readonly stateFile: string;
  /** What panels keep with wb.storage, a file per extension. */
  private readonly storageDir: string;
  private storageWrites = 0;
  private readonly runDir: string;
  private state: State;
  /** What the last sharkd start said about each extension it loaded. */
  private last = new Map<string, Last>();
  /** WireBuddy's private folder: plugins/ for WIRESHARK_PLUGIN_DIR, copies/ for the loaded extensions. */
  private home: string | null = null;
  private overlay: string | null = null;
  /** The loader's line per extension, for its copy: every sharkd start loads exactly this code. */
  private loaded = new Map<string, string>();
  /** The set (and what was said about it) before the last change, to go back to when it crashed sharkd. */
  private previous: { loaded: Map<string, string>; last: Map<string, Last> } | null = null;
  private copies = 0;
  /** Grows with every change of the loaded set: sharkd started before runs other code. */
  generation = 0;
  private readonly otherSeen = new Set<string>();
  /** Why extensions can't load, or null when they can. */
  unavailable: string | null = "not set up yet";

  /** `examples`: the folder of the example extensions that ship with WireBuddy, for the panel guide. */
  constructor(private readonly examples = "") {
    const data = process.env.XDG_DATA_HOME || join(homedir(), ".local/share");
    this.dir = join(data, "wirebuddy/extensions");
    this.stateFile = join(data, "wirebuddy/extensions-state.json");
    this.storageDir = join(data, "wirebuddy/panel-storage");
    this.runDir = join(data, "wirebuddy/run");
    this.shared = (process.env.WIREBUDDY_EXTENSIONS ?? "").split(delimiter).filter(Boolean).map((d) => resolve(d));
    this.state = readState(this.stateFile);
  }

  /** Finds the real global plugin folder and builds WireBuddy's plugin folder next to it. */
  async init(sharkd: string): Promise<void> {
    // The checks that keep others' Lua out rely on Linux owners, modes, ACLs and filesystem types
    if (process.platform !== "linux") {
      this.unavailable = "only supported on Linux";
      return;
    }
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      const probe = await probeSharkd(sharkd);
      const home = mkdtempSync(join(this.overlayBase(), `${OVERLAY_PREFIX}${process.pid}-`));
      this.home = home;
      // Wireshark loads every .lua below its plugin folder: the copies live next to it
      const overlay = join(home, "plugins");
      mkdirSync(overlay);
      mkdirSync(join(home, "copies"));
      mkdirSync(join(home, "tests"));
      // Everything Wireshark ships (C plugins in <version>/…, global Lua) stays as it is
      for (const entry of existsSync(probe.globalDir) ? readdirSync(probe.globalDir) : []) {
        if (entry === "init.lua") continue;
        symlinkSync(join(probe.globalDir, entry), join(overlay, entry));
      }
      const globalInit = join(probe.globalDir, "init.lua");
      writeFileSync(join(overlay, "init.lua"), PRELUDE + (existsSync(globalInit) ? `\nlocal f = io.open(${JSON.stringify(globalInit)}, "rb")\nif f then load(f:read("a"), "@init.lua")() f:close() end\n` : ""));
      writeFileSync(join(overlay, "wirebuddy-loader.lua"), LOADER);
      this.overlay = overlay;
      this.unavailable = null;
      this.refresh();
    } catch (err) {
      this.unavailable = (err as Error).message;
    }
  }

  /**
   * A folder only the user can write, so the plugin folder's name can't be
   * taken over once it is gone (a Wireshark opened from here may still use it).
   */
  private overlayBase(): string {
    const uid = process.getuid!();
    const runtime = process.env.XDG_RUNTIME_DIR || (existsSync(`/run/user/${uid}`) ? `/run/user/${uid}` : null);
    const base = runtime && !rootTrust(runtime).problem ? runtime : this.runDir;
    if (base === this.runDir) mkdirSync(base, { recursive: true, mode: 0o700 });
    const trust = rootTrust(base);
    if (trust.problem) throw new Error(`no private folder for sharkd's plugins: ${base} ${trust.problem}`);
    // Plugin folders of WireBuddys that are gone
    for (const entry of readdirSync(trust.real)) {
      const pid = Number(new RegExp(`^${OVERLAY_PREFIX}(\\d+)-`).exec(entry)?.[1]);
      if (pid && pid !== process.pid && !alive(pid)) rmSync(join(trust.real, entry), { recursive: true, force: true });
    }
    return trust.real;
  }

  close(): void {
    if (this.home) rmSync(this.home, { recursive: true, force: true });
  }

  /**
   * Takes the enabled extensions as they are on disk now. Until the next
   * change every sharkd start and Wireshark loads exactly this code, however
   * the files change meanwhile (the agent edits and tests before reloading).
   */
  refresh(): void {
    const next = new Map<string, string>();
    const failed = new Map<string, Last>();
    for (const e of this.entries()) if (e.info.enabled && loadable(e.info) && e.info.lua) this.take(e, next, failed);
    this.change(next);
    for (const name of this.last.keys()) if (!next.has(name)) this.last.delete(name);
    for (const [name, last] of failed) this.last.set(name, last);
  }

  /** Switches one extension on or off in the loaded set; the others stay as they are. */
  include(name: string, on: boolean): void {
    const next = new Map(this.loaded);
    const failed = new Map<string, Last>();
    next.delete(name);
    const e = on ? this.entries().find((x) => x.info.name === name) : undefined;
    if (e && loadable(e.info) && e.info.lua) this.take(e, next, failed);
    this.change(next);
    this.last.delete(name);
    for (const [n, last] of failed) this.last.set(n, last);
  }

  private change(next: Map<string, string>): void {
    this.generation++;
    this.previous = { loaded: this.loaded, last: new Map(this.last) };
    this.loaded = next;
    this.prune();
  }

  /** Back to the set before the last change, which crashed sharkd, but never to one switched off since; false if there is none. */
  revert(): boolean {
    if (!this.previous) return false;
    this.generation++;
    ({ loaded: this.loaded, last: this.last } = this.previous);
    for (const name of Object.keys(this.state.off)) {
      this.loaded.delete(name);
      this.last.delete(name);
    }
    this.previous = null;
    return true;
  }

  /** No extensions until the next reload: sharkd crashed with the set and there is none to go back to. */
  suspend(): void {
    this.generation++;
    this.previous = null;
    this.loaded = new Map();
    this.last = new Map();
  }

  /** The loaded set as it is now, for restore(). */
  saved(): Saved {
    return { loaded: this.loaded, last: this.last, previous: this.previous };
  }

  /** Puts back a saved set: sharkd crashed without the extensions too, so they weren't the cause. */
  restore(s: Saved): void {
    this.generation++;
    ({ loaded: this.loaded, last: this.last, previous: this.previous } = s);
  }

  /** Removes copies neither the loaded set nor the one to go back to uses. */
  private prune(): void {
    if (!this.home) return;
    const used = new Set([...this.loaded.values(), ...(this.previous?.loaded.values() ?? [])].map((line) => basename(dirname(line.split("\t")[1]))));
    for (const n of readdirSync(join(this.home, "copies"))) if (!used.has(n)) rmSync(join(this.home, "copies", n), { recursive: true, force: true });
  }

  private take(e: Entry, into: Map<string, string>, failed: Map<string, Last>): void {
    try {
      into.set(e.info.name, this.copy(e));
    } catch (err) {
      failed.set(e.info.name, { status: "error", error: printable((err as Error).message), protocols: [] });
    }
  }

  /** Copies an extension's Lua files, checked again as they are read; the loader's line for the copy. */
  private copy(e: Entry, folder: "copies" | "tests" = "copies"): string {
    if (!this.home) throw new Error(`extensions are unavailable: ${this.unavailable}`);
    const dir = join(this.home, folder, String(++this.copies), e.info.name);
    mkdirSync(dir, { recursive: true });
    const files = luaFiles(e.folder);
    for (const f of files) writeFileSync(join(dir, f), readChecked(join(e.folder, f), e.trust));
    return [e.info.name, dir, ...files].join("\t");
  }

  /** Environment for sharkd and Wireshark: WireBuddy's plugin folder and the extensions to load. */
  env(): NodeJS.ProcessEnv {
    if (!this.overlay) return process.env;
    const lines = [...this.loaded.keys()].sort().map((name) => this.loaded.get(name)!);
    return { ...process.env, WIRESHARK_PLUGIN_DIR: this.overlay, WIREBUDDY_EXTENSIONS_LOAD: lines.join("\n") };
  }

  /** The environment for testing one extension as it is on disk now, enabled or not; `done` removes its copy. */
  testEnv(name: string): { env: NodeJS.ProcessEnv; done: () => void } {
    const e = this.entries().find((x) => x.info.name === name);
    if (!e) throw new Error(this.missing(name));
    if (!loadable(e.info)) throw new Error(`extension "${name}" can't load: ${e.info.error}`);
    if (!this.overlay) throw new Error(`extensions are unavailable: ${this.unavailable}`);
    // Not with the loaded copies, which a reload meanwhile may prune
    const line = this.copy(e, "tests");
    const dir = dirname(line.split("\t")[1]);
    return { env: { ...process.env, WIRESHARK_PLUGIN_DIR: this.overlay, WIREBUDDY_EXTENSIONS_LOAD: line }, done: () => rmSync(dir, { recursive: true, force: true }) };
  }

  /** Extensions found in the user's folder, then the shared ones; a name's first folder wins. */
  list(): ExtensionInfo[] {
    return this.entries().map((e) => e.info);
  }

  /** The list for the UI and the agent, with the shared folders that were ignored. */
  listing(): ExtensionList {
    const ignored: string[] = [];
    const extensions = this.entries(ignored).map((e) => e.info);
    return { dir: this.dir, unavailable: this.unavailable, extensions, ignored };
  }

  private entries(ignored: string[] = []): Entry[] {
    const seen = new Set<string>();
    const out: Entry[] = [];
    for (const root of [this.dir, ...this.shared]) {
      if (!existsSync(root)) continue;
      // Lua runs as the user: a folder others can change is not even listed
      const trust = rootTrust(root);
      let names: string[];
      try {
        if (trust.problem) throw new Error(trust.problem);
        names = readdirSync(trust.real).sort();
      } catch (err) {
        ignored.push(`${printable(root)}: ${trust.problem ?? "it can't be read"}`);
        continue;
      }
      for (const name of names) {
        if (name.startsWith(".") || seen.has(name)) continue;
        const folder = join(trust.real, name);
        let st: Stats | undefined;
        try {
          st = lstatSync(folder, { throwIfNoEntry: false });
        } catch {
          // a folder that can be listed but not entered
          ignored.push(`${printable(root)}: it can't be entered`);
          break;
        }
        if (!st || (!st.isDirectory() && !st.isSymbolicLink())) continue;
        seen.add(name);
        let found: { info: ExtensionInfo; panel: PanelManifest | null };
        try {
          found = this.describe(name, folder, trust);
        } catch {
          const info: ExtensionInfo = { name: printable(name), folder: printable(folder), label: printable(name), version: "", description: "", enabled: false, status: "untrusted", error: `${printable(folder)} can't be read`, protocols: [], lua: false, panel: null };
          found = { info, panel: null };
        }
        out.push({ ...found, folder, trust });
      }
    }
    return out;
  }

  private describe(name: string, folder: string, trust: RootTrust): { info: ExtensionInfo; panel: PanelManifest | null } {
    const shown = printable(name);
    const info: ExtensionInfo = {
      name: shown,
      folder: printable(folder),
      label: shown,
      version: "",
      description: "",
      enabled: !Object.hasOwn(this.state.off, name),
      status: "new",
      protocols: [],
      lua: false,
      panel: null,
    };
    const done = (patch: Partial<ExtensionInfo>, panel: PanelManifest | null = null) => ({ info: { ...info, ...patch }, panel });
    if (!NAME.test(name)) return done({ status: "invalid", error: "folder names may only use letters, digits, '.', '_' and '-'" });
    // Checked before anything is read: what others could change stays unread
    let lua: string[] = [];
    let problem = entryProblem(folder, "folder", trust);
    try {
      if (!problem) lua = luaFiles(folder);
    } catch {
      problem = `${printable(folder)} can't be read`;
    }
    problem ??= entryProblem(join(folder, MANIFEST), "file", trust, true) ?? lua.map((f) => entryProblem(join(folder, f), "file", trust)).find(Boolean) ?? null;
    const tree = problem ? null : panelTree(folder, trust);
    problem ??= tree?.problem ?? null;
    if (problem) return done({ status: "untrusted", error: `${problem}; WireBuddy doesn't load it` });
    let m: Record<string, unknown>;
    try {
      m = JSON.parse(readChecked(join(folder, MANIFEST), trust, MAX_MANIFEST).toString("utf8")) as Record<string, unknown>;
      info.label = typeof m.label === "string" && m.label ? printable(m.label).slice(0, 60) : shown;
      info.version = typeof m.version === "string" ? printable(m.version).slice(0, 20) : "";
      info.description = typeof m.description === "string" ? printable(m.description).slice(0, 300) : "";
    } catch (err) {
      return done({ status: "invalid", error: `${MANIFEST}: ${printable((err as Error).message)}` });
    }
    info.lua = lua.length > 0;
    let panel: PanelManifest | null = null;
    if (m.panel !== undefined && m.panel !== false) {
      try {
        panel = panelManifest(m.panel, info.label);
      } catch (err) {
        return done({ status: "invalid", error: `${MANIFEST}: panel: ${printable((err as Error).message)}` });
      }
      if (tree?.invalid) return done({ status: "invalid", error: tree.invalid });
      info.panel = { title: panel.title, open: false, stale: false, offer: panel.offer?.text ?? null };
    }
    if (!info.lua && !panel) return done({ status: "invalid", error: "neither a .lua file nor a panel" });
    if (!info.enabled) return done({ status: "off", error: this.state.off[name] || undefined }, panel);
    // A panel alone never goes to sharkd
    if (!info.lua) return done({ status: "loaded" }, panel);
    const last = this.last.get(name);
    return done(last ? { status: last.status, error: last.error, protocols: last.protocols } : {}, panel);
  }

  /** A panel's files, read and checked again now: what its frame will be served. */
  panelFiles(name: string): PanelFiles {
    const e = this.panelEntry(name);
    const tree = panelTree(e.folder, e.trust);
    if (tree.problem || tree.invalid) throw new Error(`${tree.problem ?? tree.invalid}`);
    const files = new Map<string, { bytes: Buffer; type: string }>();
    let body = "";
    for (const f of tree.files) {
      const bytes = readChecked(f.path, e.trust, PANEL_MAX_FILE);
      if (f.rel === "body.html") body = bytes.toString("utf8");
      else files.set(f.rel, { bytes, type: PANEL_TYPES[extname(f.rel).toLowerCase()] });
    }
    return { folder: e.folder, manifest: e.panel!, files, body, fingerprint: fingerprint(e.folder, tree) };
  }

  /** The offers of enabled panels that could open: theirs to check against the capture. */
  offers(): { name: string; label: string; filter: string; text: string }[] {
    return this.entries()
      .filter((e) => e.panel?.offer && e.info.enabled && loadable(e.info))
      .map((e) => ({ name: e.info.name, label: e.info.label, filter: e.panel!.offer!.filter, text: e.panel!.offer!.text }));
  }

  /** What an extension's panel kept with wb.storage.set, as JSON, or null. */
  panelStorage(name: string): string | null {
    if (!NAME.test(name)) throw new Error(`no extension "${name}"`);
    try {
      return readFileSync(join(this.storageDir, `${name}.json`), "utf8");
    } catch {
      return null;
    }
  }

  /** Keeps `json` for an extension's panel, replacing the file whole; null removes it. */
  setPanelStorage(name: string, json: string | null): void {
    if (!NAME.test(name)) throw new Error(`no extension "${name}"`);
    const file = join(this.storageDir, `${name}.json`);
    if (json === null) return rmSync(file, { force: true });
    mkdirSync(this.storageDir, { recursive: true, mode: 0o700 });
    // A new file renamed over the old one: never half written, never through a link
    const tmp = join(this.storageDir, `.${name}.${process.pid}.${++this.storageWrites}.tmp`);
    try {
      writeFileSync(tmp, json, { mode: 0o600, flag: "wx" });
      renameSync(tmp, file);
    } finally {
      rmSync(tmp, { force: true });
    }
  }

  /** Changes when the panel's files or extension.json change; null without a panel. */
  panelFingerprint(name: string): string | null {
    const e = this.entries().find((x) => x.info.name === name);
    return e?.panel ? fingerprint(e.folder, panelTree(e.folder, e.trust)) : null;
  }

  private panelEntry(name: string): Entry {
    const e = this.entries().find((x) => x.info.name === name);
    if (!e) throw new Error(this.missing(name));
    if (!loadable(e.info)) throw new Error(`extension "${name}" can't load: ${e.info.error}`);
    if (!e.panel) throw new Error(`extension "${name}" has no panel ("panel" in its extension.json, and panel/main.js)`);
    if (!e.info.enabled) throw new Error(`extension "${name}" is switched off`);
    return e;
  }


  /** Records a sharkd load report, which covers every extension it loaded; returns what changed, for the agent. */
  report(r: LuaReport): { level: "INFO" | "WARNING" | "ERROR"; text: string }[] {
    const out: { level: "INFO" | "WARNING" | "ERROR"; text: string }[] = [];
    const before = this.last;
    this.last = new Map();
    for (const { name, protocols } of r.loaded) {
      const was = before.get(name);
      this.last.set(name, { status: "loaded", protocols });
      if (was?.status !== "loaded" || was.protocols.join() !== protocols.join()) {
        out.push({ level: "INFO", text: `Extension "${name}" loaded${protocols.length ? ` (protocols: ${protocols.join(", ")})` : " without a protocol of its own"}` });
      }
    }
    for (const { name, error, protocols } of r.failed) {
      const text = printable(error);
      // What ran before the error stays registered in sharkd
      const partly = protocols.length ? ` It registered ${protocols.join(", ")} before the error, which stays active until it loads again without.` : "";
      this.last.set(name, { status: "error", error: text + partly, protocols });
      if (before.get(name)?.error !== text + partly) {
        out.push({ level: "WARNING", text: `Extension "${name}" did not load: ${text}.${partly} Fix its Lua, check it with extensions(action "test"), then reload` });
      }
    }
    if (r.crashedIn && !Object.hasOwn(this.state.off, r.crashedIn)) {
      this.generation++;
      this.loaded.delete(r.crashedIn);
      out.push({ level: "ERROR", text: `Extension "${r.crashedIn}" crashed sharkd while loading and was switched off — fix it, test it, then enable it again` });
      try {
        this.setEnabled(r.crashedIn, false, "sharkd crashed while loading it");
      } catch (err) {
        out.push({ level: "WARNING", text: `Could not remember that "${r.crashedIn}" is off: ${printable((err as Error).message)}` });
      }
    }
    for (const text of r.other.map(printable)) {
      if (this.otherSeen.has(text)) continue;
      this.otherSeen.add(text);
      out.push({ level: "WARNING", text: `A Lua plugin did not load: ${text}` });
    }
    return out;
  }

  /** Switches an extension on or off for later loads; throws when that can't be saved. */
  setEnabled(name: string, on: boolean, why = ""): void {
    if (!NAME.test(name)) throw new Error(`no extension "${name}"`);
    if (on) delete this.state.off[name];
    else this.state.off[name] = why;
    this.last.delete(name);
    writeFileSync(this.stateFile, JSON.stringify(this.state, null, 2), { mode: 0o600 });
  }

  guide(topic: "lua" | "panel" = "lua"): string {
    if (topic === "panel") return this.panelGuide();
    const shared = this.shared.length ? `\nShared extensions (read-only for you unless the user says otherwise): ${this.shared.join(", ")}` : "";
    const own = existsSync(this.dir) ? rootTrust(this.dir).problem : null;
    const why = this.unavailable ? `\n\nExtensions are unavailable right now: ${this.unavailable}` : own ? `\n\nWireBuddy can't use ${this.dir} right now: ${own}. Tell the user.` : "";
    return `# WireBuddy extensions

An extension is a Wireshark Lua dissector that WireBuddy's sharkd, and the Wireshark it opens, load
from its own folder. Write one when the capture has traffic Wireshark doesn't decode (its packets
show "Data" / "UDP" / "TCP" with a raw payload; the filter "data" finds them), decodes wrongly, or
when a computed field would help the user. Fields you register can be filtered on, shown as
columns, and read with inspect_frame and query_packets fields.

Folder: ${this.dir}/<name>/   (name: letters, digits, ".", "_", "-")
  extension.json   {"label": "ACME telemetry", "version": "1", "description": "What it decodes, from what source"}
  *.lua            loaded in name order; one file is usually enough${shared}

Workflow:
1. Look at the undecoded packets: query_packets with filter "data" (or "udp.port == N"),
   inspect_frame with hex, follow_stream. Work out the format; ask the user for a spec if there is one.
2. Write the folder with your file tools.
3. extensions action "test": loads only this extension into a separate sharkd with the open capture and
   reports load errors, how many packets each protocol matched, a sample tree and Lua errors.
   Fix and repeat until it is clean. The user's view does not change.
4. extensions action "reload": the user's view decodes with it. Tell the user what you added and
   which filter shows it (e.g. "acme"), maybe add a column with set_columns.
5. If it misbehaves later, fix it and reload, or action "disable".

Rules and pitfalls:
- Lua runs as the user with full file and process access. Write a dissector only: no file writes,
  no os.execute, no network, nothing beyond decoding packets.
- An extension listed as untrusted, or a folder WireBuddy ignored, could have been changed by others.
  Never copy it into your folder or change its permissions to make it load: tell the user.
- Protocol names must be unique, lowercase, and are the filter name; field names start with it ("acme.seq").
- Return quietly on packets that don't fit; never assume a length: tvb(offset, len) past the end
  raises "Range is out of bounds". Lua errors show as an expert item and as WireBuddy events.
- Little-endian values: t:add_le(field, range) and range:le_uint().
- Heuristic dissectors: after pinfo.conversation = proto, later packets of that conversation skip the
  heuristic, so the dissector must check lengths too.
- Field.new() extractors are empty during sharkd's first pass over the file; use pinfo and tvb for
  state across packets, keyed by pinfo.number, and reset it in proto.init.
- Code that runs more than 1 s on one packet is stopped as an endless loop (a Lua error on that
  packet); after 3 such packets the function is skipped for the whole capture.
- GUI functions (TextWindow, reload_packets, set_filter, ...) raise errors here; print() and io.write()
  go to stderr.
- Wireshark's Lua API: https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html

Template, protocol on a fixed port:
${TEMPLATES.port}
Template, heuristic (recognized by content):
${TEMPLATES.heuristic}
Template, post-dissector (computed field on packets decoded by others):
${TEMPLATES.postdissector}
Template, a known protocol on another port:
${TEMPLATES.decodeAs}
Panels (a window of your own in the user's view: images, video, point clouds, charts): topic "panel".${why}`;
  }

  /** How to write a panel: for the agent. */
  private panelGuide(): string {
    return `# WireBuddy panels

A panel is a small web page you write; WireBuddy shows it in a window of its UI and feeds it the
open capture, also while a live capture runs. Write one when a picture says more than packet rows:
images or files in the traffic, video, point clouds, maps, a field over time. It lives in an
extension folder, with or without a Lua dissector (topic "lua"), and runs sandboxed on an origin
of its own: no network, no access to WireBuddy's page or API, only \`wb\`.

Folder: ${this.dir}/<name>/
  extension.json   {"label": "...", "version": "1", "description": "...",
                    "panel": {"title": "...", "size": [800, 560], "params": {...}}}   ("panel": true for defaults)
                    "panel" may also have "offer": {"filter": "wbpc", "text": "Show the point cloud"}: a chip in the
                    status bar offers the panel when the open capture has matching packets (text: 40 characters)
                    and "permissions": ["control"], only needed for wb.setFilter
  panel/main.js    required: an ES module; \`wb\` is a global; top-level await works
  panel/body.html  optional HTML put into <body> (no scripts, no on*= attributes)
  panel/style.css  optional; panel/... more modules (import "./x.js"), workers, images, fonts, data
  At most 4 folders deep, 200 files, 8 MiB a file, 16 MiB in all.
${this.examples && existsSync(this.examples) ? `Examples to copy with your file tools: ${this.examples}/{http-gallery,rtp-video,lidar-wbpc}\n  (pictures from HTTP; H.264 over RTP with WebCodecs; a point cloud from a Lua dissector in WebGL2)\n` : ""}
Loop:
1. Write the files with your file tools.
2. extensions action "test": manifest, file trust, JavaScript syntax (file:line) and lints.
3. panel action "open": starts it in the user's view and reports whether it got ready, its errors
   (file:line) and what it shows; panel action "snapshot" returns an image of it.
4. Fix, then panel action "reload"; repeat. panel action "status" shows errors and console lines since
   your last look. If it needs your Lua protocol, extensions action "reload" first.
5. Tell the user what the panel shows and that View › Panels opens it again.

Rules:
- No network: only the panel's own files and wb. Copy libraries into panel/.
- Packet data is attacker-controlled: put it into the page with textContent or wb.h, never innerHTML.
  Show captured images only through wb.objectURL (or a blob: URL) in <img>, never as SVG markup.
- No inline scripts, on*= attributes, eval or new Function (the page's policy blocks them).
- Don't navigate or open windows: a panel that navigates is closed. One that stops responding
  for 20 s is stopped.
- Call wb.ready() once the first view is drawn. On "reset" (another file, re-read extensions or
  TLS keys) throw away what you read and read again.
- Fetch data in main.js and transfer it to workers; workers can't call wb.

API (global wb):
  wb.view          what the user's view shows: {file, epoch, frames, displayed, filter, selected,
                   selection (frame ranges or null), marked, live (a capture runs), capture}
  wb.on(event, fn) "view", "select" (frame or null), "packets" (the file grew), "reset",
                   "visible" (true/false), "theme" ("light"/"dark"); returns a function that stops it
  wb.packets(q)    one page of packets, q:
     filter        a display filter
     match         packets by their headers, read from the file without dissecting (pcap and pcapng only):
                   {proto: "udp" | "tcp" | ..., port, srcport, dstport, addr, src, dst (also "10.0.0.0/8"),
                   ethertype, vlan}; each a value or a list of them; every key given must hold. Per packet:
                   IP fragments after the first have no ports
     frames        "displayed" | "selected" | "marked" | [[first, last], ...]   (with filter or match: all hold)
     fields        up to 16 field names: display strings, all occurrences joined by ","
     bytes         "frame" | "ip" | "payload" (of UDP or TCP) | a field or protocol ("http.file_data", "rtp")
     after         continue after this frame number (page.next)
     limit         packets a page: 1000; at most 50000 without fields, 5000 with fields, 2000 with a
                   field's bytes (or any bytes of a compressed file)
     maxBytes      bytes a page: 4 MiB, at most 16 MiB (a page has at least one packet)
     epoch         when paging by hand: the first page's page.epoch, so a page of another capture rejects "stale"
   page: {n, frames, times (epoch seconds), lens, bytes(i), fields: {name: [values]}, clipped, next, done,
          live, total, dropped (packets without that layer), packets: [{frame, time, len, bytes, fields}]}
  wb.all(q)        every page joined (at most 64 MiB)
  wb.subscribe(q, {batch(page, {live}), reset(), error(e)})   pages through q, then the packets a live
                   capture adds; batch is awaited before the next page; q.from "end": new packets only;
                   waits for a capture if none is open; returns {close()}
  wb.frame(n, {tree, bytes})   {frame, tree, bytes, sources: [{name, bytes}] (reassembled data), followers}
  wb.follow({frame} | {protocol: "TCP", stream: 0} | {protocol, filter}, {offset, maxBytes, epoch})
                   {protocol, filter, client, server, truncated, next, epoch, chunks: a page with dirs (1: from the server)}
  wb.objects(kind) files in the traffic, kind "http" | "imf" | "smb" | "tftp" | "dicom" | "ftp-data":
                   [{id, frame, host, type, filename, size, sha1}]
  wb.object(id)    {type, filename, bytes};  wb.objectURL(id): a blob: URL for <img> or <video>
  wb.tap(name, {filter})   "phs", "expert", "rtp-streams", "conv:eth|ipv4|ipv6|tcp|udp", "endpt:..."
  wb.check(filter) {ok, error?, warning?}
  wb.select(frame) selects a packet in the user's view; only right after the user clicked or typed in the panel
  wb.setFilter(filter)   applies a display filter in the user's view; needs "permissions": ["control"] and a click too
  wb.storage.get() / wb.storage.set(value)   JSON of at most 256 KiB kept for this extension, also across restarts
  wb.onSnapshot(fn)   what panel action "snapshot" shows: fn returns a canvas, OffscreenCanvas or Blob
                   (default: the largest canvas; make WebGL canvases with wb.canvas so their pixels are kept)
  Failed calls reject with an Error whose .code is bad-args, filter, no-capture, stale, gone,
  too-large, busy, too-slow, denied (no click, no permission) or internal (some with .hint);
  they are reported to you as well.
  wb.params        the panel's "params" from extension.json
  wb.ready()       it works: the agent hears it, with what it shows
  wb.status(text)  a short status line under the window;  wb.title(text): the window's title
  wb.h(tag, attrs, ...children)   an element; attrs: class, style (object), on<event> functions, others as attributes
  wb.canvas({context: "2d" | "webgl2", onResize(w, h, dpr)})   a canvas filling the panel: {canvas, ctx} or {canvas, gl}
  wb.hex(bytes, max)  wb.text(bytes)  wb.fmt.bytes(n)  wb.fmt.duration(s)
  console.* lines and uncaught errors are reported to you.

Pitfalls:
- Field values are display strings ("0x0012", "True"); Wireshark cuts values over about 2 KB
  (page.clipped): ask for bytes: "<field>" to get a whole value.
- page.bytes(i) are views into one buffer: slice() what you keep.
- Over ~1000 packets/s use match + bytes "payload": read straight from the file, also ahead of the view
  while it grows. Filters, fields and a field's bytes cost a dissection per packet (a few thousand a second).
- WebCodecs: check VideoDecoder.isConfigSupported; codec "avc1." + hex of SPS bytes 1-3; Annex B
  needs no description; close every VideoFrame.

Minimal panel/main.js (the selected packet's payload, and UDP packets counted live):
  const hex = document.body.appendChild(wb.h("pre"));
  const count = document.body.appendChild(wb.h("div"));
  async function show(frame) {
    if (frame == null) return void (hex.textContent = "Select a packet");
    const page = await wb.packets({ frames: [[frame, frame]], bytes: "payload" });
    hex.textContent = page.n && page.bytes(0).length ? wb.hex(page.bytes(0), 512) : "No UDP or TCP payload";
  }
  wb.on("select", show);
  let n = 0;
  wb.subscribe({ filter: "udp" }, {
    batch(page) { n += page.n; count.textContent = \`\${n} UDP packets\`; wb.status(\`\${n} UDP packets\`); },
    reset() { n = 0; },
  });
  await show(wb.view.selected);
  wb.ready();
with extension.json {"label": "Payload", "version": "1", "description": "Payload of the selected packet", "panel": true}`;
  }

  /** Throws unless `name` is an extension that exists (and with `loadable`, could load). */
  check(name: string, loadableToo = true): void {
    const e = this.list().find((x) => x.name === name);
    if (!e) throw new Error(this.missing(name));
    if (loadableToo && !loadable(e)) throw new Error(`extension "${name}" can't load: ${e.error}`);
  }

  private missing(name: string): string {
    const why = existsSync(this.dir) ? rootTrust(this.dir).problem : null;
    return why ? `WireBuddy can't use ${this.dir}: ${why}` : `no extension "${name}" in ${this.dir}`;
  }

  /** Whether any extension decodes now (also one that loaded only partly). */
  active(): number {
    return this.list().filter((e) => e.lua && (e.status === "loaded" || (e.status === "error" && e.protocols.length))).length;
  }

  failing(): number {
    return this.list().filter((e) => e.status === "error" || (e.enabled && (e.status === "invalid" || e.status === "untrusted"))).length;
  }

  /** Whether sharkd starts with any extension. */
  any(): boolean {
    return this.loaded.size > 0;
  }
}

function loadable(e: ExtensionInfo): boolean {
  return e.status !== "untrusted" && e.status !== "invalid";
}

/** An extension's Lua files in load order; names with tabs or newlines can't be passed on. */
function luaFiles(folder: string): string[] {
  return readdirSync(folder)
    .filter((f) => f.endsWith(".lua") && !/[\t\n]/.test(f))
    .sort();
}

interface PanelTree {
  files: { rel: string; path: string; size: number; mtimeMs: number }[];
  /** Others could have changed something in it. */
  problem: string | null;
  invalid: string | null;
}

/** The files of an extension's panel folder, checked like its Lua; none when there is no panel folder. */
function panelTree(folder: string, trust: RootTrust): PanelTree {
  const root = join(folder, PANEL_DIR);
  const out: PanelTree = { files: [], problem: null, invalid: null };
  if (!lstatSync(root, { throwIfNoEntry: false })) return out;
  let total = 0;
  const walk = (dir: string, rel: string, depth: number): void => {
    out.problem ??= entryProblem(dir, "folder", trust);
    for (const name of out.problem ? [] : readdirSync(dir).sort()) {
      if (out.problem || out.invalid) return;
      const path = join(dir, name);
      const r = rel ? `${rel}/${name}` : name;
      const shown = `${PANEL_DIR}/${printable(r)}`;
      if (!PANEL_SEGMENT.test(name) || (!rel && name === "_wb")) {
        out.invalid = `${shown}: names may only use letters, digits, '.', '_' and '-' and start with a letter or digit ("_wb" is WireBuddy's)`;
        return;
      }
      const st = lstatSync(path);
      if (st.isDirectory()) {
        if (depth >= PANEL_MAX_DEPTH) out.invalid = `${shown}: more than ${PANEL_MAX_DEPTH} folders deep`;
        else walk(path, r, depth + 1);
        continue;
      }
      out.problem ??= entryProblem(path, "file", trust);
      // Only what a frame can use is served
      if (out.problem || (r !== "body.html" && !PANEL_TYPES[extname(name).toLowerCase()])) continue;
      total += st.size;
      if (st.size > PANEL_MAX_FILE) out.invalid = `${shown} is larger than ${PANEL_MAX_FILE / 1024 / 1024} MiB`;
      else if (total > PANEL_MAX_TOTAL) out.invalid = `${PANEL_DIR}/ holds more than ${PANEL_MAX_TOTAL / 1024 / 1024} MiB`;
      else if (out.files.length >= PANEL_MAX_FILES) out.invalid = `${PANEL_DIR}/ holds more than ${PANEL_MAX_FILES} files`;
      else out.files.push({ rel: r, path, size: st.size, mtimeMs: st.mtimeMs });
    }
  };
  try {
    walk(root, "", 1);
  } catch {
    out.problem ??= `${printable(root)} can't be read`;
  }
  if (!out.problem && !out.invalid && !out.files.some((f) => f.rel === "main.js")) out.invalid = `${PANEL_DIR}/main.js is missing`;
  return out;
}

function fingerprint(folder: string, tree: PanelTree): string {
  const manifest = lstatSync(join(folder, MANIFEST), { throwIfNoEntry: false });
  return [`${manifest?.size}:${manifest?.mtimeMs}`, ...tree.files.map((f) => `${f.rel}:${f.size}:${f.mtimeMs}`)].join("|");
}

/** The "panel" of an extension.json: true for all defaults, or an object. */
function panelManifest(value: unknown, label: string): PanelManifest {
  const o = value === true ? {} : value;
  if (!o || typeof o !== "object" || Array.isArray(o)) throw new Error("must be true or an object");
  const p = o as Record<string, unknown>;
  const num = (v: unknown, lo: number, hi: number, fallback: number): number => (typeof v === "number" && Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.round(v))) : fallback);
  const size = Array.isArray(p.size) ? p.size : [];
  const params = p.params ?? {};
  if (typeof params !== "object" || Array.isArray(params) || params === null) throw new Error("params must be an object");
  if (JSON.stringify(params).length > 8192) throw new Error("params are larger than 8 KiB");
  let offer: PanelManifest["offer"] = null;
  if (p.offer !== undefined) {
    const of = p.offer as Record<string, unknown>;
    if (!of || typeof of.filter !== "string" || !of.filter.trim() || of.filter.length > 1024) throw new Error("offer.filter must be a display filter of at most 1 KiB");
    offer = { filter: of.filter.trim(), text: typeof of.text === "string" && of.text.trim() ? printable(of.text).slice(0, 40) : "Open" };
  }
  const permissions = p.permissions ?? [];
  if (!Array.isArray(permissions) || !permissions.every((x) => x === "control")) throw new Error('permissions may only list "control"');
  if (p.wasm !== undefined && typeof p.wasm !== "boolean") throw new Error("wasm must be true or false");
  return {
    title: typeof p.title === "string" && p.title.trim() ? printable(p.title).slice(0, 60) : label,
    size: [num(size[0], 320, 1600, 800), num(size[1], 200, 1200, 560)],
    params: params as Record<string, unknown>,
    offer,
    permissions: [...new Set(permissions as string[])],
    wasm: p.wasm === true,
  };
}

function readState(file: string): State {
  const off: Record<string, string> = Object.create(null);
  try {
    const s = JSON.parse(readFileSync(file, "utf8")) as Partial<State>;
    for (const [name, why] of Object.entries(s.off ?? {})) if (NAME.test(name)) off[name] = typeof why === "string" ? why : "";
  } catch {
    // none yet
  }
  return { off };
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

let ownGroup: number | null | undefined;

/** The user's own group when nobody else is in it (Debian's user private groups), else null. */
function privateGid(): number | null {
  if (ownGroup !== undefined) return ownGroup;
  ownGroup = null;
  const gid = process.getgid?.();
  try {
    const [name, , , members] = execFileSync("getent", ["group", String(gid)], { encoding: "utf8", timeout: 5000 }).trim().split(":");
    if (gid !== undefined && name === userInfo().username && !members) ownGroup = gid;
  } catch {
    // no getent: a group-writable file counts as writable by others
  }
  return ownGroup;
}

const aclCache = new Map<string, boolean>();

/** Whether a POSIX ACL lets named users or groups write (the group bits then show the ACL mask). */
function aclLetsOthersWrite(path: string, st: Stats): boolean {
  const key = `${st.dev}:${st.ino}:${st.ctimeMs}`;
  let result = aclCache.get(key);
  if (result !== undefined) return result;
  result = false;
  try {
    const acl = execFileSync("getfacl", ["--absolute-names", "--omit-header", "--", path], { encoding: "utf8", timeout: 5000 });
    for (const line of acl.split("\n")) {
      const [type, who, perms = ""] = line.split(":");
      if ((type === "user" || type === "group") && who && perms.slice(0, 3).includes("w")) result = true;
    }
  } catch {
    // no getfacl: no ACLs set with it either
  }
  aclCache.set(key, result);
  return result;
}

/** Writable by someone besides the user (and root). */
function othersCanWrite(st: Stats, path: string): boolean {
  if (st.mode & 0o002) return true;
  if (!(st.mode & 0o020)) return false;
  return st.gid !== privateGid() || aclLetsOthersWrite(path, st);
}

/** Network and FUSE filesystems: the owners and modes they show don't say who can write. */
const UNCHECKABLE_FS = new Set([
  0x6969, 0x517b, 0xff534d42, 0xfe534d42, 0x65735546, 0x01021997, 0x00c36400, 0x5346414f, 0x73757245, 0x564c, 0x6b414653, 0x0bd00bd0, 0x47504653, 0x786f4256, 0x20030528,
  0x19830326,
]);

/**
 * Whether others could change what is in `root`: every folder from / down to
 * it must belong to root or the user and be closed to other writers, except
 * sticky ones (like /tmp), below which only the user's own entries count. A
 * folder of the user's that others can't enter makes everything below it on
 * the same filesystem private.
 */
function rootTrust(root: string): RootTrust {
  const fail = (problem: string): RootTrust => ({ problem, real: root, dev: -1, privateDev: null });
  let real: string;
  try {
    real = realpathSync(root);
  } catch {
    return fail("it can't be read");
  }
  const uid = process.getuid!();
  let path: string = sep;
  let sticky = false;
  let privateDev: number | null = null;
  let dev = -1;
  try {
    const parts = ["", ...real.split(sep).filter(Boolean)];
    for (const [i, part] of parts.entries()) {
      path = join(path, part);
      const st = statSync(path);
      dev = st.dev;
      // The folder itself counts even below a private one: it may be a bind mount of a shared folder
      if (i === parts.length - 1) {
        if (st.uid !== uid && st.uid !== 0) return fail("another user owns it");
        if (othersCanWrite(st, path)) return fail("others can write to it");
      }
      if (privateDev !== null && st.dev === privateDev) continue;
      // Another filesystem mounted below the private folder: check it from here
      privateDev = null;
      if (st.uid !== uid && (st.uid !== 0 || sticky)) return fail("another user owns it or a folder above it");
      if (st.uid === uid && st.isDirectory() && (st.mode & 0o011) === 0) {
        privateDev = st.dev;
        sticky = false;
        continue;
      }
      sticky = othersCanWrite(st, path) && (st.mode & 0o1000) !== 0;
      if (othersCanWrite(st, path) && !sticky) return fail("others can write to it or a folder above it");
    }
    if (UNCHECKABLE_FS.has(Number(statfsSync(real).type))) return fail("it is on a network or FUSE filesystem, where WireBuddy can't check who can write");
  } catch {
    return fail("it can't be read");
  }
  if (sticky) return fail("others can write to it");
  return { problem: null, real, dev, privateDev };
}

/** Why something with these stats in a trusted root could have been changed by others, or null. */
function statProblem(st: Stats, path: string, kind: "folder" | "file", trust: RootTrust): string | null {
  if (st.isSymbolicLink()) return "is a symbolic link";
  if (kind === "folder" ? !st.isDirectory() : !st.isFile()) return kind === "file" ? "is not a regular file" : "is not a folder";
  if (st.dev !== trust.dev) return "is on another filesystem";
  // Root could change anything anyway
  if (st.uid !== process.getuid!() && st.uid !== 0) return "belongs to another user";
  // Another link to the file could be in a folder others can reach
  if (kind === "file" && st.nlink > 1) return "has other hard links";
  if (othersCanWrite(st, path)) return "can be written by others";
  return null;
}

/** Why an extension's folder or file could have been changed by others, or null. */
function entryProblem(path: string, kind: "folder" | "file", trust: RootTrust, optional = false): string | null {
  const st = lstatSync(path, { throwIfNoEntry: false });
  if (!st) return optional ? null : `${printable(path)} is missing`;
  const problem = statProblem(st, path, kind, trust);
  return problem && `${printable(path)} ${problem}`;
}

/** Reads a file through a descriptor checked like entryProblem, so what was checked is what is read. */
function readChecked(path: string, trust: RootTrust, max = Infinity): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd);
    const problem = statProblem(st, path, "file", trust);
    if (problem) throw new Error(`${printable(path)} ${problem}`);
    if (st.size > max) throw new Error("too large");
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}

/** Asks sharkd, through a throwaway plugin, where its global plugins live. */
function probeSharkd(sharkd: string): Promise<{ globalDir: string }> {
  const config = mkdtempSync(join(tmpdir(), "wirebuddy-probe-"));
  mkdirSync(join(config, "plugins"));
  writeFileSync(join(config, "plugins/probe.lua"), `io.stderr:write("WIREBUDDY-PROBE\\t" .. Dir.global_plugins_path() .. "\\n")\n`);
  return new Promise((done, fail) => {
    const p = spawn(sharkd, ["-"], { env: { ...process.env, WIRESHARK_CONFIG_DIR: config }, stdio: ["pipe", "ignore", "pipe"] });
    let err = "";
    let settled = false;
    const finish = (result: { globalDir: string } | Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      p.kill();
      rmSync(config, { recursive: true, force: true });
      if (result instanceof Error) fail(result);
      else done(result);
    };
    const timer = setTimeout(() => finish(new Error("sharkd did not start in time")), 15000);
    p.stderr.setEncoding("utf8");
    p.stderr.on("data", (d: string) => {
      err += d;
      const m = /WIREBUDDY-PROBE\t([^\n]+)\n/.exec(err);
      if (m) finish({ globalDir: m[1] });
      else if (/Hello in child/.test(err)) finish(new Error("this sharkd has no Lua support"));
    });
    p.on("error", (e) => finish(e));
    p.on("close", () => finish(new Error("sharkd exited while starting")));
  });
}
