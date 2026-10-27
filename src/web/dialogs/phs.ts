/** Statistics > Protocol Hierarchy. */

import type { PhsNode } from "../../shared/api.ts";
import { errorText, get } from "../api.ts";
import { app, hooks } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { showMenu } from "../menu.ts";
import { copyText, fmtInt, h } from "../util.ts";
import { scopeControl } from "./scope.ts";

function pctCell(part: number, whole: number): HTMLTableCellElement {
  const pct = whole ? (100 * part) / whole : 0;
  return h(
    "td",
    { class: "num pct" },
    h("div", { class: "pct-bar", style: `width:${Math.min(100, pct).toFixed(2)}%` }),
    h("span", { class: "pct-text" }, `${pct.toFixed(1)}%`),
  );
}

export function openPhsDialog(): void {
  const s = app.state;
  if (!s?.file) return;
  const d = new Dialog("Protocol Hierarchy Statistics", { width: 820, height: 520, cls: "dlg-stats" });
  const tbody = h("tbody");
  const table = h(
    "table",
    { class: "stat-table phs" },
    h(
      "thead",
      null,
      h("tr", null, h("th", { class: "left" }, "Protocol"), h("th", null, "Percent Packets"), h("th", null, "Packets"), h("th", null, "Percent Bytes"), h("th", null, "Bytes")),
    ),
    tbody,
  );
  const msg = h("div", { class: "stat-msg" }, "Computing…");
  const scope = scopeControl(() => void load());
  d.body.append(h("div", { class: "stat-bar" }, scope.el), h("div", { class: "stat-wrap" }, table, msg));

  let roots: PhsNode[] = [];
  const collapsed = new Set<PhsNode>();
  let selected: PhsNode | null = null;
  let totalFrames = 0;
  let totalBytes = 0;

  const render = (): void => {
    const rows: HTMLTableRowElement[] = [];
    const add = (nodes: PhsNode[], depth: number): void => {
      for (const n of nodes) {
        const kids = n.children?.length > 0;
        const open = !collapsed.has(n);
        const tog = h("span", { class: `dt-tog${kids ? (open ? " open" : " closed") : ""}` });
        const tr = h(
          "tr",
          { class: n === selected ? "sel" : "" },
          h("td", { class: "left proto" }, h("span", { class: "dt-indent", style: `width:${depth * 16}px` }), tog, n.proto),
          pctCell(n.frames, totalFrames),
          h("td", { class: "num" }, fmtInt(n.frames)),
          pctCell(n.bytes, totalBytes),
          h("td", { class: "num" }, fmtInt(n.bytes)),
        );
        tog.addEventListener("click", (e) => {
          e.stopPropagation();
          if (open) collapsed.add(n);
          else collapsed.delete(n);
          render();
        });
        tr.addEventListener("mousedown", () => {
          selected = n;
          tbody.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel"));
          tr.classList.add("sel");
        });
        tr.addEventListener("dblclick", () => {
          if (!kids) return;
          if (open) collapsed.add(n);
          else collapsed.delete(n);
          render();
        });
        tr.addEventListener("contextmenu", (e) => {
          e.preventDefault();
          selected = n;
          tbody.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel"));
          tr.classList.add("sel");
          showMenu(
            [
              { label: "Apply as Filter", action: () => hooks.setFilter(n.proto, true) },
              { label: "Prepare as Filter", action: () => hooks.setFilter(n.proto, false) },
              { label: "Copy Protocol Name", action: () => void copyText(n.proto) },
            ],
            e.clientX,
            e.clientY,
          );
        });
        rows.push(tr);
        if (kids && open) add(n.children, depth + 1);
      }
    };
    add(roots, 0);
    tbody.replaceChildren(...rows);
  };

  const asText = (): string => {
    const lines = ["Protocol\tPercent Packets\tPackets\tPercent Bytes\tBytes"];
    const add = (nodes: PhsNode[], depth: number): void => {
      for (const n of nodes) {
        const pp = totalFrames ? ((100 * n.frames) / totalFrames).toFixed(1) : "0.0";
        const pb = totalBytes ? ((100 * n.bytes) / totalBytes).toFixed(1) : "0.0";
        lines.push(`${"  ".repeat(depth)}${n.proto}\t${pp}\t${n.frames}\t${pb}\t${n.bytes}`);
        add(n.children ?? [], depth + 1);
      }
    };
    add(roots, 0);
    return lines.join("\n");
  };

  d.button("Copy", () => void copyText(asText()), { title: "Copy as tab-separated text" });
  d.button("Close", () => d.close(), { primary: true });
  d.show();

  let loadSeq = 0;
  async function load(): Promise<void> {
    const seq = ++loadSeq;
    d.footerLeft.textContent = scope.text();
    msg.hidden = false;
    msg.classList.remove("error");
    msg.textContent = "Computing…";
    try {
      const r = await get<PhsNode[]>("api/stats/phs", { filter: scope.filter() });
      if (seq !== loadSeq) return;
      roots = Array.isArray(r) ? r : [];
      totalFrames = roots.reduce((a, n) => a + n.frames, 0);
      totalBytes = roots.reduce((a, n) => a + n.bytes, 0);
      msg.hidden = roots.length > 0;
      msg.textContent = "No protocols";
    } catch (e) {
      if (seq !== loadSeq) return;
      roots = [];
      msg.textContent = `Failed: ${errorText(e)}`;
      msg.classList.add("error");
    }
    render();
  }
  void load();
}
