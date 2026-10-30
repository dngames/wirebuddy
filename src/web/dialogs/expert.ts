/** Expert Information dialog: expert items grouped by severity and message. */

import type { ExpertItem, ExpertSeverity } from "../../shared/api.ts";
import { errorText, get } from "../api.ts";
import * as act from "../actions.ts";
import { app, bus } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { sevClass, sevRank } from "../frame.ts";
import { icon } from "../icons.ts";
import { showMenu } from "../menu.ts";
import { copyText, debounce, fmtInt, h, IS_MAC } from "../util.ts";
import { VList } from "../vlist.ts";

const RH = 22;
const SEVERITIES = ["Error", "Warning", "Note", "Chat", "Comment"] as const;
type Sev = (typeof SEVERITIES)[number];

interface Msg {
  key: string;
  severity: Sev;
  group: string;
  protocol: string;
  message: string;
  frames: number[];
}

type Row =
  | { kind: "sev"; key: string; severity: Sev; count: number; msgs: Msg[] }
  | { kind: "msg"; key: string; msg: Msg }
  | { kind: "frame"; key: string; msg: Msg; frame: number };

function normSev(s: string): Sev {
  return s === "Warn" ? "Warning" : (SEVERITIES as readonly string[]).includes(s) ? (s as Sev) : "Note";
}

/** Groups items into severity -> message -> frames, highest severity first. */
function group(items: ExpertItem[]): Map<Sev, Msg[]> {
  const byKey = new Map<string, Msg>();
  for (const it of items) {
    const severity = normSev(it.severity);
    const key = `${severity}\u0001${it.group}\u0001${it.protocol}\u0001${it.message}`;
    let m = byKey.get(key);
    if (!m) {
      m = { key, severity, group: it.group, protocol: it.protocol, message: it.message, frames: [] };
      byKey.set(key, m);
    }
    m.frames.push(it.frame);
  }
  const out = new Map<Sev, Msg[]>();
  for (const m of byKey.values()) {
    m.frames.sort((a, b) => a - b);
    const list = out.get(m.severity) ?? [];
    list.push(m);
    out.set(m.severity, list);
  }
  for (const list of out.values()) list.sort((a, b) => b.frames.length - a.frames.length || a.message.localeCompare(b.message));
  return out;
}

let current: Dialog | null = null;

export function openExpertDialog(): void {
  if (current?.isOpen) {
    current.raise();
    return;
  }
  const s = app.state;
  if (!s?.file) return;
  const d = new Dialog("Expert Information", { width: 900, height: 540, cls: "dlg-stats dlg-expert", modal: false });
  current = d;

  const search = h("input", { type: "text", class: "ex-search", placeholder: "Search messages, groups, protocols…", spellcheck: false, attrs: { "aria-label": "Search" } });
  const limit = h("input", { type: "checkbox" });
  const limitLbl = h("label", { class: "cb-check", title: "Only expert items of the displayed packets" }, limit, "Limit to display filter");
  const refreshBtn = h("button", { class: "tb-mini", title: "Refresh", attrs: { "aria-label": "Refresh" } }, icon("refresh"));
  const head = h(
    "div",
    { class: "ex-head" },
    h("span", { class: "ex-c-sum" }, "Severity / Summary"),
    h("span", { class: "ex-c-grp" }, "Group"),
    h("span", { class: "ex-c-proto" }, "Protocol"),
    h("span", { class: "ex-c-count" }, "Count"),
  );
  const msg = h("div", { class: "stat-msg ex-msg" }, "Loading…");

  let data: Map<Sev, Msg[]> = new Map();
  let total = 0;
  let rows: Row[] = [];
  const openSev = new Set<string>(SEVERITIES.map((v) => `s:${v}`));
  const openMsg = new Set<string>();
  let selKey: string | null = null;
  let loadSeq = 0;
  /** Filter of the latest request, and of the results on screen ("" for all packets). */
  let requested = "";
  let sentFilter = "";

  const renderRow = (i: number): HTMLElement => {
    const r = rows[i];
    const depth = r.kind === "sev" ? 0 : r.kind === "msg" ? 1 : 2;
    const expandable = r.kind !== "frame";
    const isOpen = r.kind === "sev" ? openSev.has(r.key) : r.kind === "msg" ? openMsg.has(r.key) : false;
    let sum: HTMLElement;
    let grp = "";
    let proto = "";
    let count = "";
    if (r.kind === "sev") {
      sum = h("span", { class: `ex-sev sev ${sevClass(r.severity)}` }, r.severity);
      count = fmtInt(r.count);
    } else if (r.kind === "msg") {
      sum = h("span", { class: "ex-text", title: r.msg.message }, r.msg.message);
      grp = r.msg.group;
      proto = r.msg.protocol;
      count = fmtInt(r.msg.frames.length);
    } else {
      sum = h("span", { class: "ex-text ex-frame", title: "Double-click to go to this packet" }, `Packet ${r.frame}`);
    }
    return h(
      "div",
      { class: `ex-row${r.key === selKey ? " sel" : ""}${r.kind === "frame" ? " frame" : ""}` },
      h(
        "span",
        { class: "ex-c-sum" },
        h("span", { class: "dt-indent", style: `width:${depth * 16}px` }),
        h("span", { class: `dt-tog${expandable ? (isOpen ? " open" : " closed") : ""}` }),
        sum,
      ),
      h("span", { class: "ex-c-grp" }, grp),
      h("span", { class: "ex-c-proto" }, proto),
      h("span", { class: "ex-c-count" }, count),
    );
  };
  const vl = new VList(RH, renderRow, "ex-list");

  const rebuild = (): void => {
    const q = search.value.trim().toLowerCase();
    rows = [];
    let shown = 0;
    for (const sev of SEVERITIES) {
      const all = data.get(sev) ?? [];
      const msgs = q ? all.filter((m) => `${m.message}\u0001${m.group}\u0001${m.protocol}`.toLowerCase().includes(q)) : all;
      if (!msgs.length) continue;
      const count = msgs.reduce((a, m) => a + m.frames.length, 0);
      shown += count;
      rows.push({ kind: "sev", key: `s:${sev}`, severity: sev, count, msgs });
      if (!openSev.has(`s:${sev}`)) continue;
      for (const m of msgs) {
        rows.push({ kind: "msg", key: `m:${m.key}`, msg: m });
        if (!openMsg.has(`m:${m.key}`)) continue;
        for (const f of m.frames) rows.push({ kind: "frame", key: `f:${m.key}\u0001${f}`, msg: m, frame: f });
      }
    }
    vl.setCount(rows.length);
    msg.hidden = rows.length > 0;
    if (!rows.length && !msg.classList.contains("error")) msg.textContent = total ? "No expert items match the search" : "No expert information in these packets";
    const scope = sentFilter ? `Display filter: ${sentFilter.length > 80 ? `${sentFilter.slice(0, 80)}…` : sentFilter}` : "All packets";
    d.footerLeft.textContent = `${fmtInt(q ? shown : total)} item${(q ? shown : total) === 1 ? "" : "s"} · ${scope}`;
  };

  const selIndex = (): number => (selKey === null ? -1 : rows.findIndex((r) => r.key === selKey));

  const select = (i: number): void => {
    const r = rows[i];
    if (!r) return;
    selKey = r.key;
    vl.forEachRow((el, k) => el.classList.toggle("sel", rows[k]?.key === selKey));
    vl.scrollTo(i);
  };

  const toggle = (r: Row, open?: boolean): void => {
    if (r.kind === "frame") return;
    const set = r.kind === "sev" ? openSev : openMsg;
    const now = open ?? !set.has(r.key);
    if (now) set.add(r.key);
    else set.delete(r.key);
    rebuild();
  };

  const activate = (r: Row): void => {
    if (r.kind === "frame") act.jumpToFrame(r.frame);
    else toggle(r);
  };

  const load = async (): Promise<void> => {
    const seq = ++loadSeq;
    msg.classList.remove("error");
    msg.hidden = false;
    msg.textContent = "Loading…";
    const filter = limit.checked ? app.state?.filter || undefined : undefined;
    requested = filter ?? "";
    try {
      const items = await get<ExpertItem[]>("api/stats/expert", { filter });
      if (seq !== loadSeq) return;
      sentFilter = requested;
      const list = Array.isArray(items) ? items : [];
      total = list.length;
      data = group(list);
      rebuild();
    } catch (e) {
      if (seq !== loadSeq) return;
      sentFilter = requested;
      data = new Map();
      total = 0;
      msg.classList.add("error");
      msg.textContent = `Failed: ${errorText(e)}`;
      rebuild();
    }
  };

  const rowFromEvent = (e: Event): Row | null => {
    const el = (e.target as HTMLElement).closest<HTMLElement>(".ex-row");
    return el?.dataset.i !== undefined ? rows[Number(el.dataset.i)] ?? null : null;
  };

  vl.el.addEventListener("mousedown", (e) => {
    // Control+click is the context click on macOS
    if (e.button !== 0 || (IS_MAC && e.ctrlKey)) return;
    const r = rowFromEvent(e);
    if (!r) return;
    select(rows.indexOf(r));
    if ((e.target as HTMLElement).closest(".dt-tog")) toggle(r);
  });
  vl.el.addEventListener("dblclick", (e) => {
    const r = rowFromEvent(e);
    if (r && !(e.target as HTMLElement).closest(".dt-tog")) activate(r);
  });
  vl.el.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    const r = rowFromEvent(e);
    if (!r) return;
    select(rows.indexOf(r));
    const m = r.kind === "sev" ? null : r.msg;
    showMenu(
      [
        { label: "Go to Packet", disabled: r.kind !== "frame", action: () => activate(r) },
        { label: r.kind !== "frame" && (r.kind === "sev" ? openSev : openMsg).has(r.key) ? "Collapse" : "Expand", disabled: r.kind === "frame", action: () => toggle(r) },
        { label: "Copy Summary", disabled: !m, action: () => m && void copyText(m.message) },
      ],
      e.clientX,
      e.clientY,
    );
  });
  vl.el.addEventListener("keydown", (e) => {
    const i = selIndex();
    const r = rows[i];
    switch (e.key) {
      case "ArrowDown":
        select(Math.min(rows.length - 1, i + 1));
        break;
      case "ArrowUp":
        select(Math.max(0, i - 1));
        break;
      case "Home":
        select(0);
        break;
      case "End":
        select(rows.length - 1);
        break;
      case "ArrowRight":
        if (r) toggle(r, true);
        break;
      case "ArrowLeft":
        if (r && r.kind !== "frame" && (r.kind === "sev" ? openSev : openMsg).has(r.key)) toggle(r, false);
        else if (r && r.kind !== "sev") {
          const parentKey = r.kind === "frame" ? `m:${r.msg.key}` : `s:${r.msg.severity}`;
          select(rows.findIndex((x) => x.key === parentKey));
        }
        break;
      case "Enter":
        if (r) activate(r);
        break;
      default:
        return;
    }
    e.preventDefault();
  });

  search.addEventListener("input", debounce(rebuild, 150));
  search.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      vl.el.focus();
      if (selIndex() < 0) select(0);
    }
  });
  limit.addEventListener("change", () => void load());
  refreshBtn.addEventListener("click", () => void load());
  const syncLimit = (): void => {
    const f = app.state?.filter ?? "";
    limit.disabled = !f;
    limitLbl.title = f ? `Only expert items of packets matching: ${f.length > 120 ? `${f.slice(0, 120)}…` : f}` : "No display filter is applied";
    if (!f && limit.checked) {
      limit.checked = false;
      void load();
    }
  };
  syncLimit();
  // Live reloads arrive every second: reload once they settle.
  const reloadSoon = debounce(() => void load(), 1500);
  const offState = bus.on("state", (st, prev) => {
    const wasChecked = limit.checked;
    syncLimit();
    if (!prev || (wasChecked && !limit.checked)) return;
    const newFile = st.file !== prev.file;
    // Same file dissected again (TLS keys, Decode As, live reload) changes the items too.
    const redissected = st.tlsKeylog !== prev.tlsKeylog || st.epoch !== prev.epoch || st.totalFrames !== prev.totalFrames || st.fileSize !== prev.fileSize;
    const filterChanged = limit.checked && st.filter !== requested;
    if (newFile || filterChanged) void load();
    else if (redissected) reloadSoon();
  });

  d.body.append(h("div", { class: "ex-bar" }, search, limitLbl, refreshBtn), h("div", { class: "ex-table" }, head, vl.el, msg));
  d.button("Close", () => d.close(), { primary: true });
  d.onClose = () => {
    reloadSoon.cancel();
    offState();
    current = null;
  };
  d.show(search);
  void load();
}

/** Highest severity among items, or null. */
export function maxItemSeverity(items: ExpertItem[]): ExpertSeverity | null {
  let best: ExpertSeverity | null = null;
  for (const it of items) if (sevRank(it.severity) > sevRank(best)) best = it.severity;
  return best;
}
