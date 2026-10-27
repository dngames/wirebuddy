/**
 * Follow TCP/UDP/... Stream, like Wireshark's window: the packet list shows
 * the stream while it is open, Back restores the previous display filter.
 */

import type { ConvRow, FollowResult, FrameDetail } from "../../shared/api.ts";
import { errorText, get } from "../api.ts";
import * as act from "../actions.ts";
import { app, hooks } from "../app.ts";
import { Dialog } from "../dialog.ts";
import type { MenuItem } from "../menu.ts";
import { b64ToBytes, copyText, fmtInt, h, hex2, keyLabel, load, save } from "../util.ts";

type Mode = "ascii" | "carrays" | "hex" | "utf8" | "raw";
type Dir = "both" | "client" | "server";

/** Analyze > Follow in Wireshark's order; other streams sharkd offers come after these. */
export const FOLLOW: { proto: string; label: string; key?: string }[] = [
  { proto: "TCP", label: "TCP Stream", key: "Ctrl+Alt+Shift+T" },
  { proto: "UDP", label: "UDP Stream", key: "Ctrl+Alt+Shift+U" },
  { proto: "DCCP", label: "DCCP Stream" },
  { proto: "TLS", label: "TLS Stream", key: "Ctrl+Alt+Shift+S" },
  { proto: "HTTP", label: "HTTP Stream", key: "Ctrl+Alt+Shift+H" },
  { proto: "HTTP2", label: "HTTP/2 Stream" },
  { proto: "QUIC", label: "QUIC Stream" },
  { proto: "SIP", label: "SIP Call" },
  { proto: "WebSocket", label: "WebSocket Stream" },
];

const MODES: [Mode, string][] = [
  ["ascii", "ASCII"],
  ["carrays", "C Arrays"],
  ["hex", "Hex Dump"],
  ["utf8", "UTF-8"],
  ["raw", "Raw"],
];

/** Conversation table behind a stream index, for the number of streams. */
const CONV_TYPE: Record<string, string> = { "tcp.stream": "tcp", "udp.stream": "udp" };

/** Follow submenu for a packet: every kind, the ones it has enabled. */
export function followItems(fd: FrameDetail | null): MenuItem[] {
  const followers = fd?.followers ?? [];
  const known = FOLLOW.map((f): MenuItem => {
    const hit = followers.find(([p]) => p === f.proto);
    return { label: f.label, shortcut: f.key && keyLabel(f.key), disabled: !hit, action: () => hit && openFollowDialog(f.proto, hit[1]) };
  });
  const other = followers
    .filter(([p]) => !FOLLOW.some((f) => f.proto === p))
    .map(([p, filter]): MenuItem => ({ label: `${p} Stream`, action: () => openFollowDialog(p, filter) }));
  return [...known, ...other];
}

function asciiOf(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) {
    const c = b[i];
    if (c === 0x0a || c === 0x09) s += String.fromCharCode(c);
    else if (c === 0x0d) {
      if (b[i + 1] !== 0x0a) s += "\n";
    } else if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c);
    else s += ".";
  }
  return s;
}

function hexOf(b: Uint8Array, base: number, indent: string): string {
  const lines: string[] = [];
  for (let off = 0; off < b.length; off += 16) {
    let hx = "";
    let asc = "";
    for (let k = 0; k < 16; k++) {
      const i = off + k;
      if (i < b.length) {
        hx += hex2(b[i]) + " ";
        asc += b[i] >= 0x20 && b[i] < 0x7f ? String.fromCharCode(b[i]) : ".";
      } else {
        hx += "   ";
      }
      if (k === 7) hx += " ";
    }
    lines.push(`${indent}${(base + off).toString(16).padStart(8, "0")}  ${hx} ${asc}`);
  }
  return lines.join("\n") + "\n";
}

/** Wireshark's C Arrays: one array per packet and peer, eight bytes a line. */
function cArrayOf(b: Uint8Array, name: string, frame: number): string {
  const lines: string[] = [];
  for (let off = 0; off < b.length; off += 8) {
    lines.push(Array.from(b.subarray(off, off + 8), (x) => `0x${hex2(x)}`).join(", "));
  }
  return `char ${name}[] = { /* Packet ${frame} */\n${lines.join(", \n")} };\n`;
}

/** Selects `length` characters at `start` of the text in `root` and scrolls them into view. */
function selectText(root: HTMLElement, start: number, length: number): void {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const range = document.createRange();
  let pos = 0;
  let started = false;
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const len = node.textContent?.length ?? 0;
    if (!started && start < pos + len) {
      range.setStart(node, start - pos);
      started = true;
    }
    if (started && start + length <= pos + len) {
      range.setEnd(node, start + length - pos);
      break;
    }
    pos += len;
  }
  const sel = window.getSelection();
  sel?.removeAllRanges();
  sel?.addRange(range);
  const r = range.getBoundingClientRect();
  const c = root.getBoundingClientRect();
  if (r.top < c.top || r.bottom > c.bottom) root.scrollTop += r.top - c.top - root.clientHeight / 3;
}

function download(name: string, data: BlobPart, type: string): void {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = h("a", { href: url, attrs: { download: name } });
  document.body.append(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function openFollowDialog(proto: string, filter: string): void {
  const kind = FOLLOW.find((f) => f.proto === proto)?.label ?? `${proto} Stream`;
  // The packet list shows the stream while the window is open, as in Wireshark
  const previous = app.state?.filter ?? "";
  const indexed = /^([a-z][a-z0-9_.]*) eq (\d+)$/i.exec(filter.trim());
  const field = indexed?.[1] ?? null;
  let current = filter;

  const d = new Dialog(`Follow ${kind} (${filter})`, { width: 900, height: 620, cls: "dlg-follow", modal: false });
  const text = h("div", { class: "fl-text", tabIndex: 0 }, h("div", { class: "stat-msg" }, "Loading stream…"));
  const info = h("div", { class: "fl-summary" });
  const dirSel = h("select", { class: "fl-dir", attrs: { "aria-label": "Direction" } });
  const modeSel = h("select", { class: "fl-mode", attrs: { "aria-label": "Show data as" } }, ...MODES.map(([v, l]) => h("option", { value: v }, l)));
  modeSel.value = MODES.some(([v]) => v === load<string>("followmode", "ascii")) ? load<string>("followmode", "ascii") : "ascii";
  const streamIn = h("input", { type: "number", class: "fl-stream", min: "0", step: "1", attrs: { "aria-label": "Stream" } });
  const findIn = h("input", { type: "text", class: "fl-find", spellcheck: false, placeholder: "Find in the stream", attrs: { "aria-label": "Find in the stream" } });
  const findBtn = h("button", { class: "btn" }, "Find Next");
  const findMsg = h("span", { class: "fl-find-msg" });
  if (indexed) streamIn.value = indexed[2];

  d.body.append(
    text,
    info,
    h(
      "div",
      { class: "fl-controls" },
      dirSel,
      h("label", { class: "fl-lbl" }, "Show data as", modeSel),
      h("span", { class: "fl-spacer" }),
      indexed ? h("label", { class: "fl-lbl" }, "Stream", streamIn) : null,
    ),
    h("div", { class: "fl-controls" }, h("label", { class: "fl-lbl fl-findrow" }, "Find:", findIn), findBtn, findMsg),
  );

  let res: FollowResult | null = null;
  let decoded: { frame: number; server: boolean; bytes: Uint8Array }[] = [];
  /** The shown text, piece by piece, for Copy, Save and the packet under the pointer. */
  let pieces: { frame: number; server: boolean; text: string }[] = [];
  let found = -1;
  let seq = 0;

  const filterOut = d.button(
    "Filter Out This Stream",
    () => {
      hooks.setFilter(previous ? `(${previous}) && !(${current})` : `!(${current})`, true);
      d.close();
    },
    { disabled: true, title: "Hide this stream in the packet list and close" },
  );
  const saveBtn = d.button("Save as…", () => saveShown(), { disabled: true, title: "Download what is shown (Raw: the bytes)" });
  const copyBtn = d.button("Copy", () => void copyText(pieces.map((p) => p.text).join("")), { disabled: true, title: "Copy what is shown" });
  d.button(
    "Back",
    () => {
      hooks.setFilter(previous, true);
      d.close();
    },
    { title: "Restore the previous display filter and close" },
  );
  d.button("Close", () => d.close(), { primary: true });

  const shown = (p: { server: boolean }): boolean => dirSel.value === "both" || (dirSel.value === "server") === p.server;

  const counts = (): string => {
    let client = 0;
    let server = 0;
    let turns = 0;
    let last: boolean | null = null;
    for (const p of decoded) {
      if (p.server) server++;
      else client++;
      if (p.server !== last) turns++;
      last = p.server;
    }
    return `${fmtInt(client)} client pkt${client === 1 ? "" : "s"}, ${fmtInt(server)} server pkt${server === 1 ? "" : "s"}, ${fmtInt(turns)} turn${turns === 1 ? "" : "s"}.`;
  };

  const setInfo = (frame: number | null): void => {
    if (!res) return;
    info.textContent = `${frame ? `Packet ${frame}. ` : ""}${counts()} Click to select.`;
  };

  const render = (): void => {
    if (!res) return;
    const mode = modeSel.value as Mode;
    text.classList.toggle("hex", mode === "hex" || mode === "carrays" || mode === "raw");
    const utf8 = { client: new TextDecoder(), server: new TextDecoder() };
    let cOff = 0;
    let sOff = 0;
    let cN = 0;
    let sN = 0;
    pieces = [];
    for (const p of decoded) {
      let t: string;
      if (mode === "hex") t = hexOf(p.bytes, p.server ? sOff : cOff, p.server ? "    " : "");
      else if (mode === "carrays") t = cArrayOf(p.bytes, p.server ? `peer1_${sN}` : `peer0_${cN}`, p.frame);
      else if (mode === "raw") t = `${Array.from(p.bytes, hex2).join("")}\n`;
      else if (mode === "utf8") t = (p.server ? utf8.server : utf8.client).decode(p.bytes, { stream: true }).replace(/\r\n/g, "\n");
      else t = asciiOf(p.bytes);
      if (p.server) {
        sOff += p.bytes.length;
        sN++;
      } else {
        cOff += p.bytes.length;
        cN++;
      }
      if (shown(p)) pieces.push({ frame: p.frame, server: p.server, text: t });
    }
    const frag = document.createDocumentFragment();
    for (const p of pieces) frag.append(h("span", { class: p.server ? "fl-s" : "fl-c", data: { frame: p.frame } }, p.text));
    if (res.truncated) {
      const omitted = res.omittedBytes ?? 0;
      frag.append(h("div", { class: "fl-trunc" }, omitted > 0 ? `… ${fmtInt(omitted)} more bytes not shown` : "… truncated: the stream is longer than shown here"));
    }
    if (!decoded.length) frag.append(h("div", { class: "stat-msg" }, "No payload data in this stream"));
    text.replaceChildren(frag);
    found = -1;
    findMsg.textContent = "";
    setInfo(null);
  };

  const saveShown = (): void => {
    const name = `${proto.toLowerCase()}-stream${streamIn.value ? `-${streamIn.value}` : ""}`;
    const mode = modeSel.value as Mode;
    if (mode === "raw") {
      const parts = decoded.filter(shown).map((p) => p.bytes);
      const all = new Uint8Array(parts.reduce((n, b) => n + b.length, 0));
      let at = 0;
      for (const b of parts) {
        all.set(b, at);
        at += b.length;
      }
      download(`${name}.bin`, all, "application/octet-stream");
    } else {
      download(`${name}.${mode === "carrays" ? "c" : "txt"}`, pieces.map((p) => p.text).join(""), "text/plain");
    }
  };

  const findNext = (): void => {
    const q = findIn.value.toLowerCase();
    if (!q) return;
    const all = pieces.map((p) => p.text).join("").toLowerCase();
    let i = all.indexOf(q, found + 1);
    const wrapped = i < 0 && found >= 0;
    if (i < 0) i = all.indexOf(q);
    if (i < 0) {
      findMsg.textContent = "Not found";
      return;
    }
    found = i;
    findMsg.textContent = wrapped ? "Search wrapped around" : "";
    selectText(text, i, q.length);
  };

  const loadStream = (f: string): void => {
    const my = ++seq;
    current = f;
    d.setTitle(`Follow ${kind} (${f})`);
    hooks.setFilter(f, true);
    for (const b of [filterOut, saveBtn, copyBtn]) b.disabled = true;
    get<FollowResult>("api/follow", { proto, filter: f })
      .then((r) => {
        if (my !== seq) return;
        res = r;
        decoded = (r.payloads ?? []).map((p) => ({ frame: p.frame, server: p.server, bytes: b64ToBytes(p.data) }));
        const c = r.client;
        const s = r.server;
        const cName = `${c.host}${c.port ? `:${c.port}` : ""}`;
        const sName = `${s.host}${s.port ? `:${s.port}` : ""}`;
        const dir = dirSel.value || "both";
        dirSel.replaceChildren(
          h("option", { value: "both" }, `Entire conversation (${fmtInt(c.bytes + s.bytes)} bytes)`),
          h("option", { value: "client" }, `${cName} → ${sName} (${fmtInt(c.bytes)} bytes)`),
          h("option", { value: "server" }, `${sName} → ${cName} (${fmtInt(s.bytes)} bytes)`),
        );
        dirSel.value = dir;
        for (const b of [filterOut, saveBtn, copyBtn]) b.disabled = false;
        render();
      })
      .catch((e: unknown) => {
        if (my !== seq) return;
        res = null;
        decoded = [];
        pieces = [];
        info.textContent = "";
        text.replaceChildren(h("div", { class: "stat-msg error" }, `Failed: ${errorText(e)}`));
      });
  };

  modeSel.addEventListener("change", () => {
    save("followmode", modeSel.value);
    render();
  });
  dirSel.addEventListener("change", render);
  streamIn.addEventListener("change", () => {
    const n = Number(streamIn.value);
    if (field && Number.isInteger(n) && n >= 0) loadStream(`${field} eq ${n}`);
  });
  findIn.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      findNext();
    }
  });
  findIn.addEventListener("input", () => {
    found = -1;
    findMsg.textContent = "";
  });
  findBtn.addEventListener("click", findNext);
  text.addEventListener("mousemove", (e) => {
    const sp = (e.target as HTMLElement).closest<HTMLElement>("[data-frame]");
    setInfo(sp ? Number(sp.dataset.frame) : null);
  });
  text.addEventListener("mouseleave", () => setInfo(null));
  text.addEventListener("click", (e) => {
    if (window.getSelection()?.toString()) return;
    const sp = (e.target as HTMLElement).closest<HTMLElement>("[data-frame]");
    if (sp) act.jumpToFrame(Number(sp.dataset.frame));
  });

  d.show(text);
  loadStream(filter);

  // The spinner stops at the last stream
  const conv = field && CONV_TYPE[field];
  if (conv) {
    get<ConvRow[]>("api/stats/conv", { type: conv })
      .then((rows) => {
        if (Array.isArray(rows) && rows.length) streamIn.max = String(rows.length - 1);
      })
      .catch(() => {
        // the spinner works without a maximum
      });
  }
}
