/** Decode As: a port of the packet as a protocol Wireshark knows (packet list menu), and removing entries (status bar). */

import type { CompleteResponse, DecodeAsEntry, FrameDetail } from "../../shared/api.ts";
import { entryText } from "../../shared/decodeas.ts";
import * as act from "../actions.ts";
import { get } from "../api.ts";
import { app } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { decodeAsPorts } from "../frame.ts";
import { SEP, type MenuItem } from "../menu.ts";
import { toast } from "../toast.ts";
import { debounce, fmtInt, h } from "../util.ts";

let current: Dialog | null = null;

/** The packet menu's Decode As: a port of the packet to decode, or an entry on its ports to remove. */
export function decodeAsItem(fd: FrameDetail | null): MenuItem {
  const s = app.state;
  const p = fd && decodeAsPorts(fd);
  if (s?.decodeAs.unavailable) return { label: "Decode As", disabled: true, title: `Decode As is unavailable: ${s.decodeAs.unavailable}` };
  if (!p) return { label: "Decode As", disabled: true, title: "This packet has no TCP or UDP port" };
  const ports = [...new Set([p.src, p.dst])].sort((a, b) => a - b);
  const entries = (s?.decodeAs.entries ?? []).filter((e) => e.table === `${p.transport}.port` && ports.includes(e.value));
  const sub: MenuItem[] = ports.map((port) => ({ label: `${p.transport.toUpperCase()} Port ${port}…`, action: () => openDecodeAsDialog({ ...p, port }) }));
  if (entries.length) sub.push(SEP, ...entries.map((e) => ({ label: `Remove ${entryText(e)}`, action: () => void removeDecodeAs(e) })));
  return { label: "Decode As", sub };
}

/** The status bar's menu: remove one entry or all. */
export function decodeAsMenu(): MenuItem[] {
  const entries = app.state?.decodeAs.entries ?? [];
  return [...entries.map((e) => ({ label: `Remove ${entryText(e)}`, action: () => void removeDecodeAs(e) })), SEP, { label: "Remove All", action: () => void removeDecodeAs() }];
}

/** Removes an entry, or without one all of them. */
async function removeDecodeAs(e?: DecodeAsEntry): Promise<void> {
  const r = await act.changeDecodeAs(e ? { action: "clear", table: e.table, value: e.value } : { action: "clear" });
  if (typeof r === "string") toast("error", `Removing Decode As failed: ${r}`);
}

/** Decode <transport> Port <port> As: every packet on that port, as one protocol. */
function openDecodeAsDialog(p: { transport: "tcp" | "udp"; port: number; src: number; dst: number; now: string | null; payload: boolean }): void {
  if (current?.isOpen) return;
  const name = p.transport.toUpperCase();
  const table = p.transport === "tcp" ? "tcp.port" : "udp.port";
  const d = new Dialog(`Decode ${name} Port ${p.port} As`, { width: 460, cls: "dlg-decodeas", resizable: false });
  current = d;
  const existing = app.state?.decodeAs.entries.find((e) => e.table === table && e.value === p.port);
  const options = h("datalist", { id: "da-protocols" });
  const input = h("input", { type: "text", class: "da-in", spellcheck: false, value: existing?.protocol ?? "", placeholder: "e.g. rtp, mqtt, dns", attrs: { list: "da-protocols", "aria-label": "Protocol" } });
  const err = h("div", { class: "of-err", hidden: true });
  const showErr = (text: string): void => {
    err.textContent = text;
    err.hidden = false;
  };
  d.body.append(
    h("div", { class: "da-packet" }, `This packet: ${name} ${p.src} → ${p.dst}${p.now !== null ? `, decoded as ${p.now} now` : p.payload ? "" : ", has no payload of its own"}.`),
    h("div", { class: "dlg-field" }, h("label", null, "Protocol:", input), options),
    h("div", { class: "goto-hint" }, `Every packet on ${name} port ${p.port}, in this capture and the next ones, is dissected as this protocol until WireBuddy exits; "data" shows the raw bytes.`),
    err,
  );
  // Protocols only: their names have no dot
  let asked = 0;
  const suggest = debounce(async () => {
    const seq = ++asked;
    const text = input.value.trim();
    const r = text ? await get<CompleteResponse>("api/filter/complete", { field: text }).catch(() => null) : null;
    if (seq !== asked) return;
    options.replaceChildren(...(r?.fields ?? []).filter((x) => !x.f.includes(".")).map((x) => h("option", { value: x.f, label: x.n ?? "" })));
  }, 150);
  input.addEventListener("input", () => suggest());

  const apply = async (): Promise<void> => {
    const protocol = input.value.trim();
    if (!protocol) return showErr("Enter a protocol, e.g. rtp");
    if (applyBtn.disabled) return;
    applyBtn.disabled = true;
    const r = await act.changeDecodeAs({ action: "set", table, value: p.port, protocol });
    applyBtn.disabled = false;
    if (typeof r === "string") return showErr(r);
    d.close();
    if (!r.set) return;
    const { now, frames } = r.set;
    toast("info", `${name} port ${p.port} now decodes as ${now}${frames === null ? "" : ` (${fmtInt(frames)} packet${frames === 1 ? "" : "s"})`}`);
  };
  const applyBtn = d.button("Apply", () => void apply(), { primary: true });
  d.button("Cancel", () => d.close());
  d.defaultAction = () => void apply();
  d.onClose = () => {
    suggest.cancel();
    current = null;
  };
  d.show(input);
  input.select();
}
