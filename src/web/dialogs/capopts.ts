/** Capture › Options…: Wireshark's Capture Options dialog, with what dumpcap does for WireBuddy. */

import * as act from "../actions.ts";
import { activityBus, paintSpark, pollActivity, watchActivity } from "../activity.ts";
import { app, bus, captureActive, hooks } from "../app.ts";
import { cap, capBus, canStart, capOpts, loadInterfaces, optionsError, paintFilterInput, setOpts, startCaptureClicked, type CaptureOpts, type SizeUnit, type TimeUnit } from "../capture.ts";
import { Dialog } from "../dialog.ts";
import { icon } from "../icons.ts";
import { h, posInt } from "../util.ts";

export type OptionsTab = "input" | "output" | "options";

const TABS: [OptionsTab, string][] = [
  ["input", "Input"],
  ["output", "Output"],
  ["options", "Options"],
];
const SIZE_UNITS: [SizeUnit, string][] = [
  ["kB", "kilobytes"],
  ["MB", "megabytes"],
  ["GB", "gigabytes"],
];
const TIME_UNITS: [TimeUnit, string][] = [
  ["s", "seconds"],
  ["min", "minutes"],
  ["h", "hours"],
];
const HELP = "https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureOptions.html";

type NumKey = "newPkts" | "newSize" | "newTime" | "newEvery" | "ringFiles" | "stopPkts" | "stopFiles" | "stopSize" | "stopTime";
type UnitKey = "newSizeUnit" | "newTimeUnit" | "newEveryUnit" | "stopSizeUnit" | "stopTimeUnit";

let current: { d: Dialog; show: (tab: OptionsTab) => void } | null = null;

export function captureOptionsOpen(): boolean {
  return !!current?.d.isOpen;
}

export function openCaptureOptions(tab: OptionsTab = "input"): void {
  if (current?.d.isOpen) {
    current.show(tab);
    current.d.raise();
    return;
  }
  const d = new Dialog("Capture Options", { width: 860, height: 540, cls: "dlg-capopts" });
  const offs: (() => void)[] = [];
  const sync: (() => void)[] = [];

  // A number that is on while it has a value, like Wireshark's "after [n]" rows; unchecked it is ""
  const numberRow = (key: NumKey, fallback: string, label: string, unit: HTMLElement | string, title: string): { row: HTMLElement; parts: HTMLInputElement[] } => {
    const box = h("input", { type: "checkbox", attrs: { "aria-label": `${label} ${title}` } });
    const num = h("input", { class: "co-num", type: "text", inputMode: "numeric", title });
    box.addEventListener("change", () => setOpts({ [key]: box.checked ? capOpts[key] || fallback : "" } as Partial<CaptureOpts>, `dlg:${key}`));
    num.addEventListener("input", () => {
      num.classList.toggle("invalid", !!num.value.trim() && !posInt(num.value));
      setOpts({ [key]: num.value } as Partial<CaptureOpts>, `dlg:${key}`);
    });
    sync.push(() => {
      box.checked = !!capOpts[key].trim();
      if (document.activeElement !== num) num.value = capOpts[key];
    });
    return { row: h("label", { class: "co-line" }, box, h("span", null, label), num, typeof unit === "string" ? h("span", null, unit) : unit), parts: [box, num] };
  };
  const unitSelect = (key: UnitKey, units: [string, string][]): HTMLSelectElement => {
    const sel = h("select", { class: "co-unit" }, ...units.map(([v, label]) => h("option", { value: v }, label)));
    sel.addEventListener("change", () => setOpts({ [key]: sel.value } as Partial<CaptureOpts>, `dlg:${key}`));
    sync.push(() => (sel.value = capOpts[key]));
    return sel;
  };
  const checkbox = (key: "promisc" | "newFile" | "ring", label: string): HTMLInputElement => {
    const box = h("input", { type: "checkbox" });
    box.addEventListener("change", () => setOpts({ [key]: box.checked } as Partial<CaptureOpts>, `dlg:${key}`));
    sync.push(() => (box.checked = capOpts[key]));
    box.setAttribute("aria-label", label);
    return box;
  };

  // ---------------------------------------------------------------- Input
  const tbody = h("tbody");
  const table = h(
    "table",
    { class: "stat-table co-ifaces", attrs: { "aria-label": "Capture interfaces" } },
    h("thead", null, h("tr", null, h("th", { class: "left" }, "Interface"), h("th", { class: "left" }, "Traffic"), h("th", { class: "left" }, "Addresses"))),
    tbody,
  );
  const sparks = new Map<string, HTMLElement>();
  const renderIfaces = (): void => {
    sparks.clear();
    const list = cap.interfaces ?? [];
    const msg = cap.ifaceLoading && !cap.interfaces ? "Looking for interfaces…" : cap.ifaceError ? `Capture interfaces unavailable: ${cap.ifaceError}` : !list.length ? "No capture interfaces found" : "";
    if (msg) {
      tbody.replaceChildren(h("tr", null, h("td", { class: "left co-empty", colSpan: 3 }, msg)));
      return;
    }
    const hadFocus = tbody.contains(document.activeElement);
    tbody.replaceChildren(
      ...list.map((i) => {
        const spark = h("span", { class: "wl-spark" });
        sparks.set(i.name, spark);
        paintSpark(spark, i.name);
        const selected = i.name === capOpts.iface;
        return h(
          "tr",
          { class: selected ? "sel" : "", tabIndex: selected ? 0 : -1, data: { iface: i.name }, title: `Double-click to start capturing on ${i.name}` },
          h("td", { class: "left" }, icon("iface"), " ", i.name, i.description && i.description !== i.name ? h("span", { class: "co-desc" }, ` ${i.description}`) : null),
          h("td", { class: "left" }, spark),
          h("td", { class: "left co-addr", title: i.addresses.join("\n") }, i.addresses.join(", ")),
        );
      }),
    );
    if (hadFocus) tbody.querySelector<HTMLElement>("tr.sel")?.focus();
  };
  const rowOf = (e: Event): HTMLElement | null => (e.target as HTMLElement).closest<HTMLElement>("tr[data-iface]");
  tbody.addEventListener("click", (e) => {
    const row = rowOf(e);
    if (!row) return;
    row.focus();
    if (row.dataset.iface !== capOpts.iface) setOpts({ iface: row.dataset.iface! }, "dlg:iface");
  });
  tbody.addEventListener("dblclick", (e) => {
    const name = rowOf(e)?.dataset.iface;
    if (name) void start(name);
  });
  tbody.addEventListener("keydown", (e) => {
    const rows = [...tbody.querySelectorAll<HTMLElement>("tr[data-iface]")];
    const i = rows.findIndex((r) => r === document.activeElement);
    if (i < 0) return;
    if (e.key === "Enter") void start(rows[i].dataset.iface);
    else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const next = rows[Math.max(0, Math.min(rows.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
      setOpts({ iface: next.dataset.iface! }, "dlg:iface");
    } else return;
    e.preventDefault();
  });

  const filterIn = h("input", { class: "co-filter", type: "text", spellcheck: false, autocomplete: "off", placeholder: "Enter a capture filter … (e.g. tcp port 443)", attrs: { "aria-label": "Capture filter for selected interfaces" } });
  filterIn.addEventListener("input", () => setOpts({ filter: filterIn.value }, "dlg:filter"));
  const filterErr = h("div", { class: "of-err", hidden: true });
  sync.push(() => {
    if (document.activeElement !== filterIn) filterIn.value = capOpts.filter;
    paintFilterInput(filterIn);
    filterErr.textContent = cap.filterState === "error" ? cap.filterError : "";
    filterErr.hidden = cap.filterState !== "error";
  });
  const input = h(
    "div",
    { class: "co-page" },
    h("div", { class: "stat-wrap co-table" }, table),
    h("label", { class: "co-line" }, checkbox("promisc", "Enable promiscuous mode on all interfaces"), "Enable promiscuous mode on all interfaces"),
    h("div", { class: "co-filterrow" }, h("label", null, "Capture filter for selected interfaces:"), filterIn, h("button", { class: "btn", title: "Look for capture interfaces again (F5)", onclick: () => void loadInterfaces() }, icon("refresh"), "Refresh Interfaces")),
    filterErr,
  );

  // ---------------------------------------------------------------- Output
  const dirText = h("span", { class: "co-path" });
  sync.push(() => {
    const dir = app.state?.capture.dir ?? "";
    dirText.textContent = dir;
    dirText.title = dir;
  });
  const newFile = checkbox("newFile", "Create a new file automatically…");
  const newRows = [
    numberRow("newPkts", "100000", "after", "packets", "New file after this many packets"),
    numberRow("newSize", "1", "after", unitSelect("newSizeUnit", SIZE_UNITS), "New file after this size"),
    numberRow("newTime", "1", "after", unitSelect("newTimeUnit", TIME_UNITS), "New file after this time"),
    numberRow("newEvery", "1", "when time is a multiple of", unitSelect("newEveryUnit", TIME_UNITS), "New file when the clock reaches a multiple of this"),
  ];
  const ring = checkbox("ring", "Use a ring buffer");
  const ringFiles = h("input", { class: "co-num", type: "text", inputMode: "numeric", title: "Keep only this many files, deleting the oldest" });
  ringFiles.addEventListener("input", () => setOpts({ ringFiles: ringFiles.value }, "dlg:ringFiles"));
  sync.push(() => {
    if (document.activeElement !== ringFiles) ringFiles.value = capOpts.ringFiles;
    for (const r of newRows) for (const el of r.parts) el.disabled = !capOpts.newFile;
    ring.disabled = !capOpts.newFile;
    ringFiles.disabled = !capOpts.newFile || !capOpts.ring;
  });
  const output = h(
    "div",
    { class: "co-page" },
    h("div", { class: "co-line" }, "Capture files go to", dirText, h("span", { class: "co-hint" }, "(named after the interface and the time; pcapng)")),
    h("fieldset", { class: "co-group" }, h("legend", null, h("label", null, newFile, "Create a new file automatically…")), ...newRows.map((r) => r.row)),
    h("label", { class: "co-line" }, ring, "Use a ring buffer with", ringFiles, "files"),
  );

  // ---------------------------------------------------------------- Options
  const scroll = h("input", { type: "checkbox", onchange: () => act.setAutoScroll(scroll.checked) });
  sync.push(() => (scroll.checked = app.autoScroll));
  const stopRows = {
    pkts: numberRow("stopPkts", "1", "", "packets", "Stop after this many packets"),
    files: numberRow("stopFiles", "1", "", "files", "Stop after this many files"),
    size: numberRow("stopSize", "1", "", unitSelect("stopSizeUnit", SIZE_UNITS), "Stop after this size"),
    time: numberRow("stopTime", "1", "", unitSelect("stopTimeUnit", TIME_UNITS), "Stop after this time"),
  };
  sync.push(() => {
    for (const el of stopRows.files.parts) {
      el.disabled = !capOpts.newFile;
      el.title = capOpts.newFile ? "Stop after this many files" : "Needs new files to be created automatically (Output)";
    }
    // dumpcap reads a size limit as the size of new files
    for (const el of stopRows.size.parts) {
      el.disabled = capOpts.newFile;
      el.title = capOpts.newFile ? "Not with new files created automatically (Output)" : "Stop after this size";
    }
  });
  const options = h(
    "div",
    { class: "co-page" },
    h("fieldset", { class: "co-group" }, h("legend", null, "Display Options"), h("label", { class: "co-line" }, scroll, "Automatically scroll during live capture")),
    h("fieldset", { class: "co-group" }, h("legend", null, "Stop capture automatically after…"), stopRows.pkts.row, stopRows.files.row, stopRows.size.row, stopRows.time.row),
  );

  // ---------------------------------------------------------------- tabs and buttons
  const pages: Record<OptionsTab, HTMLElement> = { input, output, options };
  const tabs = h("div", { class: "tabs", role: "tablist" });
  let shown: OptionsTab = tab;
  const show = (t: OptionsTab): void => {
    shown = t;
    tabs.replaceChildren(
      ...TABS.map(([id, label]) =>
        h("button", { class: `tab${id === t ? " active" : ""}`, role: "tab", attrs: { "aria-selected": id === t ? "true" : "false" }, onclick: () => show(id) }, label),
      ),
    );
    for (const [id, page] of Object.entries(pages)) page.hidden = id !== t;
  };
  d.body.append(tabs, input, output, options);

  const problem = h("span", { class: "of-err" });
  d.footerLeft.append(problem);
  d.button("Help", () => window.open(HELP, "_blank", "noopener"), { title: "Wireshark's user guide on capture options" });
  d.button("Close", () => d.close());
  const startBtn = d.button("Start", () => void start(), { primary: true });

  // Like Wireshark: the dialog closes once the capture starts
  async function start(iface?: string): Promise<void> {
    if (captureActive()) return;
    if (await startCaptureClicked(iface)) d.close();
  }
  d.defaultAction = () => void start();

  const render = (): void => {
    for (const fn of sync) fn();
    const err = optionsError();
    problem.textContent = err && err.tab !== "input" ? err.text : "";
    startBtn.disabled = !canStart();
    startBtn.title = captureActive() ? "A capture is running" : err ? err.text : !capOpts.iface ? "Choose an interface" : "Start capturing with these options";
  };
  offs.push(
    capBus.on("ifaces", renderIfaces),
    capBus.on("check", render),
    capBus.on("opts", () => {
      renderIfaces();
      render();
    }),
    bus.on("state", render),
    bus.on("autoscroll", render),
    activityBus.on("update", () => {
      for (const [name, el] of sparks) paintSpark(el, name);
    }),
  );
  d.onClose = () => {
    for (const off of offs) off();
    current = null;
  };
  current = { d, show };
  show(tab);
  renderIfaces();
  render();
  d.show(shown === "input" ? (tbody.querySelector<HTMLElement>("tr.sel") ?? filterIn) : null);
  if (!cap.interfaces && !cap.ifaceLoading) void loadInterfaces();
  void pollActivity();
}

hooks.captureOptions = (tab) => openCaptureOptions(tab);
watchActivity(() => !!current?.d.isOpen);
