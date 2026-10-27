/** Statistics > Conversations and Statistics > Endpoints. */

import type { ConvRow, EndpointRow } from "../../shared/api.ts";
import { errorText, get } from "../api.ts";
import { app, hooks } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { showMenu } from "../menu.ts";
import { copyText, csvField, fmtInt, h } from "../util.ts";
import { scopeControl } from "./scope.ts";

type Kind = "conv" | "endpt";
type Row = ConvRow | EndpointRow;

const TYPES: [string, string][] = [
  ["eth", "Ethernet"],
  ["ipv4", "IPv4"],
  ["ipv6", "IPv6"],
  ["tcp", "TCP"],
  ["udp", "UDP"],
];

const MAX_ROWS = 5000;

interface Col {
  title: string;
  get: (r: Row) => string | number;
  num?: boolean;
  fmt?: (v: number) => string;
}

function convCols(withPorts: boolean): Col[] {
  const c = (r: Row): ConvRow => r as ConvRow;
  const cols: Col[] = [{ title: "Address A", get: (r) => c(r).addrA }];
  if (withPorts) cols.push({ title: "Port A", get: (r) => c(r).portA ?? "", num: true });
  cols.push({ title: "Address B", get: (r) => c(r).addrB });
  if (withPorts) cols.push({ title: "Port B", get: (r) => c(r).portB ?? "", num: true });
  cols.push(
    { title: "Packets", get: (r) => c(r).framesAB + c(r).framesBA, num: true, fmt: fmtInt },
    { title: "Bytes", get: (r) => c(r).bytesAB + c(r).bytesBA, num: true, fmt: fmtInt },
    { title: "Packets A → B", get: (r) => c(r).framesAB, num: true, fmt: fmtInt },
    { title: "Bytes A → B", get: (r) => c(r).bytesAB, num: true, fmt: fmtInt },
    { title: "Packets B → A", get: (r) => c(r).framesBA, num: true, fmt: fmtInt },
    { title: "Bytes B → A", get: (r) => c(r).bytesBA, num: true, fmt: fmtInt },
    { title: "Rel Start", get: (r) => c(r).start, num: true, fmt: (v) => v.toFixed(6) },
    { title: "Duration", get: (r) => c(r).duration, num: true, fmt: (v) => v.toFixed(4) },
  );
  return cols;
}

function endptCols(withPorts: boolean): Col[] {
  const e = (r: Row): EndpointRow => r as EndpointRow;
  const cols: Col[] = [{ title: "Address", get: (r) => e(r).addr }];
  if (withPorts) cols.push({ title: "Port", get: (r) => e(r).port ?? "", num: true });
  cols.push(
    { title: "Packets", get: (r) => e(r).framesTx + e(r).framesRx, num: true, fmt: fmtInt },
    { title: "Bytes", get: (r) => e(r).bytesTx + e(r).bytesRx, num: true, fmt: fmtInt },
    { title: "Tx Packets", get: (r) => e(r).framesTx, num: true, fmt: fmtInt },
    { title: "Tx Bytes", get: (r) => e(r).bytesTx, num: true, fmt: fmtInt },
    { title: "Rx Packets", get: (r) => e(r).framesRx, num: true, fmt: fmtInt },
    { title: "Rx Bytes", get: (r) => e(r).bytesRx, num: true, fmt: fmtInt },
  );
  return cols;
}

function cmp(a: string | number, b: string | number): number {
  if (typeof a === "number" && typeof b === "number") return a - b;
  const na = Number(a);
  const nb = Number(b);
  if (a !== "" && b !== "" && Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

export function openConvDialog(kind: Kind, initial = "ipv4"): void {
  const s = app.state;
  if (!s?.file) return;
  const title = kind === "conv" ? "Conversations" : "Endpoints";
  const d = new Dialog(title, { width: 940, height: 540, cls: "dlg-stats" });
  const tabs = h("div", { class: "tabs", role: "tablist" });
  const wrap = h("div", { class: "stat-wrap" });
  d.body.append(tabs, wrap);
  const scope = scopeControl(() => {
    scopeSeq++;
    data.clear();
    setSelected(null);
    d.footerLeft.textContent = scope.text();
    renderTabs();
    void load();
  });
  let scopeSeq = 0;
  d.body.prepend(h("div", { class: "stat-bar" }, scope.el));
  d.footerLeft.textContent = scope.text();

  const data = new Map<string, Row[] | string>();
  const sortBy = new Map<string, { col: number; desc: boolean }>();
  let type = TYPES.some(([t]) => t === initial) ? initial : "ipv4";
  let selected: Row | null = null;

  const applyBtn = d.button("Apply as Filter", () => selected && hooks.setFilter(selected.filter, true), { disabled: true });
  const prepBtn = d.button("Prepare as Filter", () => selected && hooks.setFilter(selected.filter, false), { disabled: true });
  d.button("Copy as CSV", () => void copyText(csv()));
  d.button("Close", () => d.close(), { primary: true });

  const colsFor = (t: string): Col[] => {
    const ports = t === "tcp" || t === "udp";
    return kind === "conv" ? convCols(ports) : endptCols(ports);
  };
  const cols = (): Col[] => colsFor(type);

  const sorted = (rows: Row[]): Row[] => {
    const so = sortBy.get(type);
    if (!so) return rows;
    const c = cols()[so.col];
    if (!c) return rows;
    const out = [...rows].sort((a, b) => cmp(c.get(a), c.get(b)));
    if (so.desc) out.reverse();
    return out;
  };

  const csv = (): string => {
    const rows = data.get(type);
    if (!Array.isArray(rows)) return "";
    const cs = cols();
    return [cs.map((c) => csvField(c.title)).join(","), ...sorted(rows).map((r) => cs.map((c) => csvField(String(c.get(r)))).join(","))].join("\n");
  };

  const setSelected = (r: Row | null): void => {
    selected = r;
    applyBtn.disabled = prepBtn.disabled = !r?.filter;
  };

  const renderTabs = (): void => {
    tabs.replaceChildren(
      ...TYPES.map(([t, label]) => {
        const rows = data.get(t);
        const count = Array.isArray(rows) ? ` · ${rows.length}` : "";
        return h(
          "button",
          {
            class: `tab${t === type ? " active" : ""}`,
            role: "tab",
            attrs: { "aria-selected": t === type ? "true" : "false" },
            onclick: () => {
              type = t;
              setSelected(null);
              renderTabs();
              void load();
            },
          },
          label + count,
        );
      }),
    );
  };

  const renderTable = (): void => {
    const rows = data.get(type);
    if (rows === undefined) {
      wrap.replaceChildren(h("div", { class: "stat-msg" }, "Computing…"));
      return;
    }
    if (typeof rows === "string") {
      wrap.replaceChildren(h("div", { class: "stat-msg error" }, `Failed: ${rows}`));
      return;
    }
    if (!rows.length) {
      wrap.replaceChildren(h("div", { class: "stat-msg" }, `No ${TYPES.find(([t]) => t === type)?.[1] ?? ""} ${kind === "conv" ? "conversations" : "endpoints"}`));
      return;
    }
    const cs = cols();
    const so = sortBy.get(type);
    const head = h(
      "tr",
      null,
      ...cs.map((c, j) => {
        const th = h("th", { class: `${c.num ? "" : "left"} sortable${so?.col === j ? (so.desc ? " desc" : " asc") : ""}`, title: "Click to sort" }, c.title);
        th.addEventListener("click", () => {
          const cur = sortBy.get(type);
          sortBy.set(type, { col: j, desc: cur?.col === j ? !cur.desc : !!c.num });
          renderTable();
        });
        return th;
      }),
    );
    const tbody = h("tbody");
    const shown = sorted(rows).slice(0, MAX_ROWS);
    for (const r of shown) {
      const tr = h(
        "tr",
        { class: r === selected ? "sel" : "" },
        ...cs.map((c) => {
          const v = c.get(r);
          return h("td", { class: c.num ? "num" : "left" }, typeof v === "number" && c.fmt ? c.fmt(v) : String(v));
        }),
      );
      const pick = (): void => {
        tbody.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel"));
        tr.classList.add("sel");
        setSelected(r);
      };
      tr.addEventListener("mousedown", pick);
      tr.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        pick();
        showMenu(
          [
            { label: "Apply as Filter", disabled: !r.filter, action: () => hooks.setFilter(r.filter, true) },
            { label: "Prepare as Filter", disabled: !r.filter, action: () => hooks.setFilter(r.filter, false) },
            { label: "Copy Filter", disabled: !r.filter, action: () => void copyText(r.filter) },
            { label: "Copy Row", action: () => void copyText(cs.map((c) => String(c.get(r))).join("\t")) },
          ],
          e.clientX,
          e.clientY,
        );
      });
      tbody.appendChild(tr);
    }
    const children: HTMLElement[] = [h("table", { class: "stat-table" }, h("thead", null, head), tbody)];
    if (rows.length > MAX_ROWS) children.push(h("div", { class: "stat-msg" }, `Showing ${fmtInt(MAX_ROWS)} of ${fmtInt(rows.length)} rows`));
    wrap.replaceChildren(...children);
  };

  const load = async (): Promise<void> => {
    const t = type;
    const sc = scopeSeq;
    renderTable();
    if (data.has(t) && typeof data.get(t) !== "string") return;
    data.delete(t);
    renderTable();
    try {
      const rows = await get<Row[]>(kind === "conv" ? "api/stats/conv" : "api/stats/endpt", { type: t, filter: scope.filter() });
      if (sc !== scopeSeq) return;
      data.set(t, Array.isArray(rows) ? rows : []);
      if (!sortBy.has(t)) sortBy.set(t, { col: colsFor(t).findIndex((c) => c.title === "Packets"), desc: true });
    } catch (e) {
      if (sc !== scopeSeq) return;
      data.set(t, errorText(e));
    }
    renderTabs();
    if (t === type) renderTable();
  };

  renderTabs();
  d.show();
  void load();
}
