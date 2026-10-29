/** File > Export Objects: the files carried in the traffic, to go to their packets and save them. */

import type { ObjectKind, ObjectList, ObjectRow, ObjectSaveResult } from "../../shared/api.ts";
import { errorText, get, HttpError, post } from "../api.ts";
import * as act from "../actions.ts";
import { app, bus, captureActive } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { icon } from "../icons.ts";
import type { MenuItem } from "../menu.ts";
import { baseName, debounce, fmtInt, fmtSize, h } from "../util.ts";
import { cmp } from "./conv.ts";

/** In Wireshark's order. */
const KINDS: ObjectKind[] = ["dicom", "ftp-data", "http", "imf", "smb", "tftp"];
const MAX_ROWS = 5000;
/** The most objects a save names; one without names saves all. */
const MAX_KEYS = 10000;

const COLS: { title: string; get: (o: ObjectRow) => string | number; num?: boolean }[] = [
  { title: "Packet", get: (o) => o.frame, num: true },
  { title: "Hostname", get: (o) => o.host },
  { title: "Content Type", get: (o) => o.type },
  { title: "Size", get: (o) => o.size, num: true },
  { title: "Filename", get: (o) => o.filename },
];

let current: { d: Dialog; kind: ObjectKind } | null = null;

export function objectItems(): MenuItem[] {
  return KINDS.map((kind) => ({ label: `${kind.toUpperCase()}…`, action: () => openObjectsDialog(kind) }));
}

export function openObjectsDialog(kind: ObjectKind): void {
  if (current?.kind === kind) {
    current.d.raise();
    return;
  }
  if (!app.state?.file) return;
  current?.d.close();
  const what = kind.toUpperCase();
  const d = new Dialog(`Export Objects · ${what}`, { width: 860, height: 500, cls: "dlg-stats dlg-objects", modal: false });
  current = { d, kind };

  const search = h("input", { type: "text", class: "ex-search", placeholder: "Filter by packet, host, type or name…", spellcheck: false, attrs: { "aria-label": "Filter" } });
  const refreshBtn = h("button", { class: "tb-mini", title: "List again", attrs: { "aria-label": "List again" }, onclick: () => void load() }, icon("refresh"));
  const wrap = h("div", { class: "stat-wrap" });
  const pathIn = h("input", { type: "text", class: "ex-path", spellcheck: false, title: `Each save goes into a new ${kind}-objects folder here, under names of its own`, attrs: { "aria-label": "Folder" } });
  const err = h("div", { class: "of-err", hidden: true });
  d.body.append(h("div", { class: "ex-bar" }, search, refreshBtn), wrap, h("div", { class: "dlg-field ex-pathrow" }, h("label", null, "Save to:", pathIn)), err);

  /** The listed objects; null while listing, the error when that failed, undefined once a running capture outdated them. */
  let objects: ObjectRow[] | string | null | undefined = null;
  let matched: ObjectRow[] = [];
  let sortBy: { col: number; desc: boolean } | null = null;
  let selected: ObjectRow | null = null;
  let listedFile: string | null = null;
  let pathEdited = false;
  let saving = false;
  /** What the last save did and where, shown until the list, the filter or the folder changes. */
  let note: { text: string; folder: string } | null = null;
  let loadSeq = 0;

  const saveBtn = d.button("Save", () => selected && void save([selected]), { disabled: true });
  const saveAllBtn = d.button("Save All", () => {
    const rows = search.value.trim() ? matching() : null;
    if (rows && rows.length > MAX_KEYS) showErr(`Save All saves at most ${fmtInt(MAX_KEYS)} filtered objects; clear the filter to save all`);
    else void save(rows);
  }, { disabled: true });
  d.button("Close", () => d.close(), { primary: true });

  const showErr = (m: string | null): void => {
    err.textContent = m ?? "";
    err.hidden = !m;
  };

  const matching = (): ObjectRow[] => {
    if (!Array.isArray(objects)) return [];
    const q = search.value.trim().toLowerCase();
    return q ? objects.filter((o) => `${o.frame}\u0001${o.host}\u0001${o.type}\u0001${o.filename}`.toLowerCase().includes(q)) : objects;
  };

  const sync = (): void => {
    saveBtn.disabled = saving || !selected;
    saveAllBtn.disabled = saving || !matched.length;
    const all = Array.isArray(objects) ? objects.length : 0;
    const count = Array.isArray(objects) ? `${search.value.trim() ? `${fmtInt(matched.length)} of ` : ""}${fmtInt(all)} ${what} object${all === 1 ? "" : "s"}` : "";
    const live = captureActive() ? "capturing: Refresh lists newer packets" : "";
    d.footerLeft.textContent = saving ? "Saving…" : (note?.text ?? [count, live].filter(Boolean).join(" · "));
    d.footerLeft.title = saving ? "" : (note?.folder ?? "");
  };

  const render = (): void => {
    matched = matching();
    if (selected && !matched.includes(selected)) selected = null;
    sync();
    const msg = (text: string, error = false): void => wrap.replaceChildren(h("div", { class: `stat-msg${error ? " error" : ""}` }, text));
    if (objects === null) return msg(`Listing ${what} objects…`);
    if (objects === undefined) return msg(`Capturing: Refresh lists the ${what} objects`);
    if (typeof objects === "string") return msg(`Failed: ${objects}`, true);
    if (!objects.length) return msg(`No ${what} objects in this capture`);
    if (!matched.length) return msg("No object matches the filter");
    const sort = (j: number): void => {
      sortBy = { col: j, desc: sortBy?.col === j ? !sortBy.desc : !!COLS[j].num };
      render();
    };
    const head = h("tr", null, ...COLS.map((c, j) => h("th", { class: `${c.num ? "" : "left"} sortable${sortBy?.col === j ? (sortBy.desc ? " desc" : " asc") : ""}`, title: "Click to sort", onclick: () => sort(j) }, c.title)));
    const rows = [...matched];
    if (sortBy) {
      const c = COLS[sortBy.col];
      rows.sort((a, b) => cmp(c.get(a), c.get(b)));
      if (sortBy.desc) rows.reverse();
    }
    const clip = (text: string): HTMLElement => h("td", { class: "left" }, h("span", { class: "eo-clip", title: text }, text));
    const tbody = h("tbody");
    for (const o of rows.slice(0, MAX_ROWS)) {
      const tr = h("tr", { class: o === selected ? "sel" : "" }, h("td", null, String(o.frame)), clip(o.host), clip(o.type), h("td", { title: `${fmtInt(o.size)} bytes` }, fmtSize(o.size)), clip(o.filename));
      tr.addEventListener("mousedown", (e) => {
        // Keyboard focus stays where it was
        e.preventDefault();
        tbody.querySelectorAll("tr.sel").forEach((x) => x.classList.remove("sel"));
        tr.classList.add("sel");
        selected = o;
        sync();
        act.jumpToFrame(o.frame);
      });
      tbody.appendChild(tr);
    }
    const children: HTMLElement[] = [h("table", { class: "stat-table" }, h("thead", null, head), tbody)];
    if (rows.length > MAX_ROWS) children.push(h("div", { class: "stat-msg" }, `Showing ${fmtInt(MAX_ROWS)} of ${fmtInt(rows.length)} objects; the filter finds the rest`));
    wrap.replaceChildren(...children);
  };

  const load = async (): Promise<void> => {
    const seq = ++loadSeq;
    listedFile = app.state?.file ?? null;
    objects = null;
    note = null;
    render();
    try {
      const r = await get<ObjectList>("api/objects", { kind });
      if (seq !== loadSeq) return;
      objects = r.objects;
      if (!pathEdited) {
        pathIn.value = r.dir;
        pathIn.scrollLeft = pathIn.scrollWidth;
      }
    } catch (e) {
      if (seq !== loadSeq) return;
      objects = errorText(e);
    }
    render();
  };

  /** Saves `rows`, or with null every object listed at save time. */
  const save = async (rows: ObjectRow[] | null): Promise<void> => {
    showErr(null);
    note = null;
    saving = true;
    sync();
    try {
      const keys = rows?.map((o) => `${o.frame}:${o.sha1}`);
      const r = await post<ObjectSaveResult>("api/objects/save", { kind, dir: pathIn.value.trim(), file: listedFile, keys });
      const [first] = r.skipped;
      const skipped = first ? `${fmtInt(r.skipped.length)} skipped (frame ${first.frame}: ${first.reason}${r.skipped.length > 1 ? ", …" : ""})` : "";
      // The folder is new in the one the field names
      if (r.folder) note = { text: `Saved ${fmtInt(r.saved)} ${what} object${r.saved === 1 ? "" : "s"} to ${baseName(r.folder)}${skipped ? `; ${skipped}` : ""}`, folder: r.folder };
      else showErr(`Nothing saved: ${skipped}`);
    } catch (e) {
      // The state that changed the capture lists again or closes this
      showErr(e instanceof HttpError && e.status === 409 ? "The capture changed meanwhile; nothing was saved" : errorText(e));
    } finally {
      saving = false;
      sync();
    }
  };

  const renderSoon = debounce(render, 150);
  search.addEventListener("input", () => {
    note = null;
    renderSoon();
  });
  pathIn.addEventListener("input", () => {
    pathEdited = true;
    note = null;
    showErr(null);
    sync();
  });
  // Live reloads arrive every second: list once they settle
  const reloadSoon = debounce(() => void load(), 1500);
  const offState = bus.on("state", (st, prev) => {
    // Listing without a capture would tell the agent of an error
    if (!st.file) {
      d.close();
      return;
    }
    if (!prev) return;
    // While capturing only Refresh lists: each listing holds up the packet list
    const capturing = captureActive(st);
    if (st.epoch !== prev.epoch && capturing) {
      ++loadSeq;
      reloadSoon.cancel();
      objects = undefined;
      render();
    } else if (st.epoch !== prev.epoch) void load();
    else if (!capturing && (st.totalFrames !== prev.totalFrames || st.capture.status !== prev.capture.status)) reloadSoon();
    if (capturing !== captureActive(prev)) sync();
  });
  d.onClose = () => {
    reloadSoon.cancel();
    offState();
    current = null;
  };
  d.show(search);
  void load();
}
