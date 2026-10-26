/** Follow TCP/UDP/... Stream. */

import type { FollowResult } from "../../shared/api.ts";
import { errorText, get } from "../api.ts";
import * as act from "../actions.ts";
import { hooks } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { b64ToBytes, copyText, fmtInt, h, hex2 } from "../util.ts";

type Mode = "ascii" | "hex";
type Dir = "both" | "client" | "server";

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

export function openFollowDialog(proto: string, filter: string): void {
  const shortFilter = filter.length > 80 ? `${filter.slice(0, 80)}…` : filter;
  const d = new Dialog(`Follow ${proto} Stream (${shortFilter})`, { width: 860, height: 580, cls: "dlg-follow" });
  const text = h("div", { class: "fl-text", tabIndex: 0 }, h("div", { class: "stat-msg" }, "Loading stream…"));
  const summary = h("div", { class: "fl-summary" });
  const dirSel = h("select", { class: "fl-dir", attrs: { "aria-label": "Direction" } });
  const modeSel = h(
    "select",
    { class: "fl-mode", attrs: { "aria-label": "Show data as" } },
    h("option", { value: "ascii" }, "ASCII"),
    h("option", { value: "hex" }, "Hex Dump"),
  );
  d.body.append(
    text,
    h("div", { class: "fl-controls" }, summary, h("span", { class: "fl-spacer" }), dirSel, h("label", { class: "fl-lbl" }, "Show data as", modeSel)),
  );
  d.footerLeft.textContent = "Click text to go to its packet";

  let res: FollowResult | null = null;
  let decoded: { frame: number; server: boolean; bytes: Uint8Array }[] = [];

  const filterBtn = d.button("Filter on this stream", () => {
    hooks.setFilter(res?.filter || filter, true);
    d.close();
  }, { disabled: true });
  const copyBtn = d.button("Copy", () => {
    const parts = decoded.filter((p) => dirSel.value === "both" || (dirSel.value === "server") === p.server);
    void copyText(parts.map((p) => asciiOf(p.bytes)).join(""));
  }, { disabled: true, title: "Copy the shown direction as text" });
  d.button("Close", () => d.close(), { primary: true });

  const render = (): void => {
    if (!res) return;
    const mode = modeSel.value as Mode;
    const dir = dirSel.value as Dir;
    text.classList.toggle("hex", mode === "hex");
    const frag = document.createDocumentFragment();
    let cOff = 0;
    let sOff = 0;
    for (const p of decoded) {
      const show = dir === "both" || (dir === "server") === p.server;
      let t: string;
      if (mode === "hex") {
        t = hexOf(p.bytes, p.server ? sOff : cOff, p.server ? "    " : "");
      } else {
        t = asciiOf(p.bytes);
      }
      if (p.server) sOff += p.bytes.length;
      else cOff += p.bytes.length;
      if (!show) continue;
      frag.appendChild(h("span", { class: p.server ? "fl-s" : "fl-c", title: `Packet ${p.frame}`, data: { frame: p.frame } }, t));
    }
    if (res.truncated) {
      // `omittedBytes` is optional: older servers only send `truncated`.
      const omitted = (res as FollowResult & { omittedBytes?: number }).omittedBytes;
      const more = typeof omitted === "number" && omitted > 0 ? ` … ${fmtInt(omitted)} more bytes not shown` : " … truncated: the stream is longer than shown here";
      frag.appendChild(h("div", { class: "fl-trunc" }, more.trim()));
    }
    if (!decoded.length) frag.appendChild(h("div", { class: "stat-msg" }, "No payload data in this stream"));
    text.replaceChildren(frag);
  };

  modeSel.addEventListener("change", render);
  dirSel.addEventListener("change", render);
  text.addEventListener("click", (e) => {
    if (window.getSelection()?.toString()) return;
    const sp = (e.target as HTMLElement).closest<HTMLElement>("[data-frame]");
    if (sp) act.jumpToFrame(Number(sp.dataset.frame));
  });

  d.show(text);

  get<FollowResult>("api/follow", { proto, filter })
    .then((r) => {
      res = r;
      decoded = (r.payloads ?? []).map((p) => ({ frame: p.frame, server: p.server, bytes: b64ToBytes(p.data) }));
      const c = r.client;
      const s = r.server;
      const cName = `${c.host}${c.port ? `:${c.port}` : ""}`;
      const sName = `${s.host}${s.port ? `:${s.port}` : ""}`;
      dirSel.replaceChildren(
        h("option", { value: "both" }, `Entire conversation (${fmtInt(c.bytes + s.bytes)} bytes)`),
        h("option", { value: "client" }, `${cName} → ${sName} (${fmtInt(c.bytes)} bytes)`),
        h("option", { value: "server" }, `${sName} → ${cName} (${fmtInt(s.bytes)} bytes)`),
      );
      summary.replaceChildren(
        h("span", { class: "fl-key fl-c" }, `Client → Server ${fmtInt(c.bytes)} bytes`),
        ", ",
        h("span", { class: "fl-key fl-s" }, `Server → Client ${fmtInt(s.bytes)} bytes`),
      );
      if (r.truncated) summary.append(h("span", { class: "fl-trunc-tag", title: "The server cut the payloads to keep the response small" }, "truncated"));
      filterBtn.disabled = false;
      copyBtn.disabled = false;
      render();
    })
    .catch((e: unknown) => {
      text.replaceChildren(h("div", { class: "stat-msg error" }, `Failed: ${errorText(e)}`));
    });
}
