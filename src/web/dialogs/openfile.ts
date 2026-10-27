/** Server-side file picker: "Open Capture File" and other path choosers. */

import type { DirEntry, DirListing, RecentFiles } from "../../shared/api.ts";
import { errorText, get } from "../api.ts";
import * as act from "../actions.ts";
import { Dialog } from "../dialog.ts";
import { icon } from "../icons.ts";
import { baseName, dirName, fmtDateTime, fmtSize, h, load, save } from "../util.ts";

export interface PickerOptions {
  title: string;
  /** Label of the accept button, e.g. "Open", "Choose", "Save". */
  accept: string;
  /** "capture" lists capture files only, "any" every file. */
  kind: "capture" | "any";
  /** Storage key for the last visited directory. */
  storeKey: string;
  /** Pre-filled path; its directory is opened first. */
  initialPath?: string;
  /** Show the recent captures column. */
  showRecent?: boolean;
  /** Receives the chosen path; returns an error to keep the dialog open. */
  onPick: (path: string) => Promise<string | null> | string | null;
}

const openPickers = new Set<string>();

export function openFilePicker(opts: PickerOptions): void {
  if (openPickers.has(opts.title)) return;
  openPickers.add(opts.title);
  const d = new Dialog(opts.title, { width: 780, height: 520, cls: "dlg-open" });

  const dirIn = h("input", { class: "of-dir", type: "text", spellcheck: false, autocomplete: "off", attrs: { "aria-label": "Look in" } });
  const upBtn = h("button", { class: "tb-mini", title: "Parent directory (Backspace)", attrs: { "aria-label": "Parent directory" } }, icon("up"));
  const reloadBtn = h("button", { class: "tb-mini", title: "Reload", attrs: { "aria-label": "Reload" } }, icon("refresh"));
  const list = h("div", { class: "of-list", tabIndex: 0, role: "listbox" });
  const recent = h("div", { class: "of-recent" }, h("div", { class: "of-side-title" }, "Recent"));
  const nameIn = h("input", { class: "of-name", type: "text", spellcheck: false, autocomplete: "off", value: opts.initialPath ?? "", attrs: { "aria-label": "File name" } });
  const err = h("div", { class: "of-err", hidden: true });

  d.body.append(
    h("div", { class: "of-top" }, h("label", { class: "of-lbl" }, "Look in:"), dirIn, upBtn, reloadBtn),
    h(
      "div",
      { class: "of-main" },
      opts.showRecent ? recent : null,
      h("div", { class: "of-files" }, h("div", { class: "of-head" }, h("span", { class: "of-c-name" }, "Name"), h("span", { class: "of-c-size" }, "Size"), h("span", { class: "of-c-date" }, "Modified")), list),
    ),
    h("div", { class: "of-bottom" }, h("label", { class: "of-lbl" }, "File name:"), nameIn),
    err,
  );
  const acceptBtn = d.button(opts.accept, () => void doAccept(), { primary: true });
  d.button("Cancel", () => d.close());

  let listing: DirListing | null = null;
  let rows: { el: HTMLElement; entry: DirEntry }[] = [];
  let selIdx = -1;

  const showErr = (m: string | null): void => {
    err.textContent = m ?? "";
    err.hidden = !m;
  };

  const select = (k: number): void => {
    if (k < 0 || k >= rows.length) return;
    rows[selIdx]?.el.classList.remove("sel");
    selIdx = k;
    const r = rows[k];
    r.el.classList.add("sel");
    r.el.scrollIntoView({ block: "nearest" });
    if (!r.entry.isDir) nameIn.value = r.entry.path;
  };

  const activate = (k: number): void => {
    const r = rows[k];
    if (!r) return;
    if (r.entry.isDir) void nav(r.entry.path);
    else void doAccept(r.entry.path);
  };

  const render = (): void => {
    rows = [];
    selIdx = -1;
    list.replaceChildren();
    if (!listing) return;
    const entries: DirEntry[] = [];
    if (listing.parent) entries.push({ name: "..", path: listing.parent, isDir: true, size: 0, mtime: 0 });
    entries.push(...listing.entries);
    entries.forEach((entry, k) => {
      const el = h(
        "div",
        { class: `of-row${entry.isDir ? " dir" : ""}`, role: "option", title: entry.path },
        h("span", { class: "of-c-name" }, icon(entry.isDir ? "folder" : "file"), h("span", { class: "of-fname" }, entry.name)),
        h("span", { class: "of-c-size" }, entry.isDir ? "" : fmtSize(entry.size)),
        h("span", { class: "of-c-date" }, entry.mtime ? fmtDateTime(entry.mtime) : ""),
      );
      el.addEventListener("mousedown", () => select(k));
      el.addEventListener("dblclick", () => activate(k));
      rows.push({ el, entry });
      list.appendChild(el);
    });
    if (!listing.entries.length) list.appendChild(h("div", { class: "of-empty" }, opts.kind === "any" ? "This directory is empty" : "No capture files in this directory"));
  };

  const nav = async (dir?: string, fallback = false): Promise<void> => {
    showErr(null);
    list.classList.add("loading");
    try {
      const l = await get<DirListing>("api/files", { dir, kind: opts.kind });
      listing = l;
      dirIn.value = l.dir;
      save(opts.storeKey, l.dir);
      render();
    } catch (e) {
      if (fallback) {
        await nav(undefined);
        return;
      }
      showErr(errorText(e));
    } finally {
      list.classList.remove("loading");
    }
  };

  const doAccept = async (path?: string): Promise<void> => {
    let p = (path ?? nameIn.value).trim();
    if (!p) {
      if (selIdx >= 0) activate(selIdx);
      return;
    }
    if (listing && !/^([\\/]|[A-Za-z]:|~)/.test(p)) p = `${listing.dir.replace(/[\\/]$/, "")}/${p}`;
    const dirEntry = listing?.entries.find((e) => e.isDir && (e.path === p || e.name === p));
    if (dirEntry || p.endsWith("/")) {
      nameIn.value = "";
      await nav(dirEntry ? dirEntry.path : p);
      return;
    }
    acceptBtn.disabled = true;
    showErr(null);
    let e: string | null;
    try {
      e = await opts.onPick(p);
    } catch (x) {
      e = errorText(x);
    }
    acceptBtn.disabled = false;
    if (e) showErr(e);
    else d.close();
  };

  list.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") select(Math.min(rows.length - 1, selIdx + 1));
    else if (e.key === "ArrowUp") select(Math.max(0, selIdx - 1));
    else if (e.key === "Home") select(0);
    else if (e.key === "End") select(rows.length - 1);
    else if (e.key === "Enter") activate(selIdx);
    else if (e.key === "Backspace" && listing?.parent) void nav(listing.parent);
    else return;
    e.preventDefault();
  });
  dirIn.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      e.stopPropagation();
      void nav(dirIn.value.trim() || undefined);
    }
  });
  upBtn.addEventListener("click", () => {
    if (listing?.parent) void nav(listing.parent);
  });
  reloadBtn.addEventListener("click", () => void nav(listing?.dir));
  d.defaultAction = () => {
    if (document.activeElement === dirIn) return;
    void doAccept();
  };
  d.onClose = () => {
    openPickers.delete(opts.title);
  };

  d.show(nameIn);
  const startDir = opts.initialPath ? dirName(opts.initialPath) : load<string | null>(opts.storeKey, null);
  void nav(startDir || undefined, !!startDir);

  if (!opts.showRecent) return;
  void get<RecentFiles>("api/recent")
    .then((r) => {
      const files = r.files ?? [];
      if (!files.length) recent.append(h("div", { class: "of-empty" }, "None"));
      for (const f of files.slice(0, 20)) {
        const el = h(
          "div",
          { class: "of-recent-item", title: `${f.path}\n${fmtSize(f.size)} · ${fmtDateTime(f.mtime)}` },
          h("span", { class: "of-fname" }, baseName(f.path)),
          h("span", { class: "of-rdir" }, dirName(f.path)),
        );
        el.addEventListener("click", () => {
          nameIn.value = f.path;
          recent.querySelectorAll(".sel").forEach((x) => x.classList.remove("sel"));
          el.classList.add("sel");
        });
        el.addEventListener("dblclick", () => void doAccept(f.path));
        recent.appendChild(el);
      }
    })
    .catch(() => recent.append(h("div", { class: "of-empty" }, "Unavailable")));
}

export function openFileDialog(): void {
  openFilePicker({
    title: "Open Capture File",
    accept: "Open",
    kind: "capture",
    storeKey: "opendir",
    showRecent: true,
    onPick: async (p) => {
      const e = await act.openFile(p);
      return e ? `Can't open ${baseName(p)}: ${e}` : null;
    },
  });
}
