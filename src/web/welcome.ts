/** Start page shown when no capture file is open. */

import type { RecentFiles } from "../shared/api.ts";
import { APP_NAME, get } from "./api.ts";
import * as act from "./actions.ts";
import { activityBus, paintSpark, pollActivity, watchActivity } from "./activity.ts";
import { app, bus, captureActive } from "./app.ts";
import { cap, capBus, capOpts, captureStatusText, loadInterfaces, paintFilterInput, setOpts, startCaptureClicked } from "./capture.ts";
import { openFileDialog } from "./dialogs/openfile.ts";
import { icon } from "./icons.ts";
import { toast } from "./toast.ts";
import { baseName, dirName, fmtDateTime, fmtSize, h, setText } from "./util.ts";

export function createWelcome(): HTMLElement {
  const recentList = h("div", { class: "wl-list" });
  // Like Wireshark's: click selects, double-click or Enter starts capturing
  const ifaceList = h("div", { class: "wl-list wl-ifaces", role: "listbox", attrs: { "aria-label": "Capture interfaces" } });
  const sparks = new Map<string, HTMLElement>();
  const errBox = h("div", { class: "wl-error", hidden: true });
  const capStatus = h("div", { class: "wl-capstatus", hidden: true });
  const filterIn = h("input", {
    class: "wl-filter",
    type: "text",
    spellcheck: false,
    autocomplete: "off",
    placeholder: "Enter a capture filter …",
    value: capOpts.filter,
    attrs: { "aria-label": "Capture filter" },
  });
  const filterErr = h("div", { class: "wl-filter-err", hidden: true });
  filterIn.addEventListener("input", () => setOpts({ filter: filterIn.value }, "welcome"));

  const openBtn = h("button", { class: "btn primary wl-open", onclick: () => openFileDialog() }, icon("open"), h("span", null, "Open…"));

  const loadRecent = async (): Promise<void> => {
    try {
      const r = await get<RecentFiles>("api/recent");
      renderRecent(r.files ?? []);
    } catch {
      recentList.replaceChildren(h("div", { class: "wl-empty" }, "Recent files are unavailable"));
    }
  };

  const renderRecent = (files: RecentFiles["files"]): void => {
    if (!files.length) {
      recentList.replaceChildren(h("div", { class: "wl-empty" }, "No recent capture files"));
      return;
    }
    recentList.replaceChildren(
      ...files.slice(0, 12).map((f) =>
        h(
          "button",
          {
            class: "wl-item",
            title: f.path,
            onclick: async () => {
              const err = await act.openFile(f.path);
              if (err) toast("error", `Can't open ${baseName(f.path)}: ${err}`);
            },
          },
          icon("file"),
          h("span", { class: "wl-item-main" }, h("span", { class: "wl-name" }, baseName(f.path)), h("span", { class: "wl-path" }, dirName(f.path))),
          h("span", { class: "wl-meta" }, `${fmtSize(f.size)} · ${fmtDateTime(f.mtime)}`),
        ),
      ),
    );
  };

  const renderIfaces = (): void => {
    const active = captureActive();
    const hadFocus = ifaceList.contains(document.activeElement);
    if (cap.ifaceLoading && !cap.interfaces) {
      ifaceList.replaceChildren(h("div", { class: "wl-empty" }, "Looking for interfaces…"));
      return;
    }
    if (cap.ifaceError) {
      ifaceList.replaceChildren(h("div", { class: "wl-empty error" }, `Capture interfaces unavailable: ${cap.ifaceError}`));
      return;
    }
    const list = cap.interfaces ?? [];
    sparks.clear();
    if (!list.length) {
      ifaceList.replaceChildren(h("div", { class: "wl-empty" }, "No capture interfaces found"));
      return;
    }
    const current = list.some((i) => i.name === capOpts.iface) ? capOpts.iface : list[0].name;
    ifaceList.replaceChildren(
      ...list.map((i) => {
        const spark = h("span", { class: "wl-spark" });
        sparks.set(i.name, spark);
        paintSpark(spark, i.name);
        const selected = i.name === current;
        return h(
          "div",
          {
            class: `wl-iface${selected ? " current" : ""}`,
            role: "option",
            tabIndex: selected ? 0 : -1,
            title: active ? "A capture is running" : `Double-click to start capturing on ${i.name}`,
            data: { iface: i.name },
            attrs: { "aria-selected": selected ? "true" : "false" },
          },
          icon("iface"),
          h(
            "span",
            { class: "wl-item-main" },
            h("span", { class: "wl-name" }, i.name, i.description && i.description !== i.name ? h("span", { class: "wl-desc" }, ` ${i.description}`) : null, i.loopback ? h("span", { class: "wl-tag" }, "loopback") : null),
            h("span", { class: "wl-path" }, i.addresses.length ? i.addresses.join(", ") : "no addresses"),
          ),
          spark,
        );
      }),
    );
    // Selecting re-renders the list: keep keyboard focus on the selected row
    if (hadFocus) ifaceList.querySelector<HTMLElement>(".wl-iface.current")?.focus();
  };

  const ifaceRow = (e: Event): HTMLElement | null => (e.target as HTMLElement).closest<HTMLElement>(".wl-iface");
  const startOn = (name: string): void => {
    if (!captureActive() && cap.filterState !== "error") void startCaptureClicked(name);
  };
  ifaceList.addEventListener("click", (e) => {
    const row = ifaceRow(e);
    if (!row?.dataset.iface) return;
    row.focus();
    if (row.dataset.iface !== capOpts.iface) setOpts({ iface: row.dataset.iface }, "welcome");
  });
  ifaceList.addEventListener("dblclick", (e) => {
    const name = ifaceRow(e)?.dataset.iface;
    if (name) startOn(name);
  });
  ifaceList.addEventListener("keydown", (e) => {
    const rows = [...ifaceList.querySelectorAll<HTMLElement>(".wl-iface")];
    const i = rows.findIndex((r) => r === document.activeElement);
    if (i < 0) return;
    if (e.key === "Enter") startOn(rows[i].dataset.iface!);
    else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      const next = rows[Math.max(0, Math.min(rows.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))];
      setOpts({ iface: next.dataset.iface! }, "welcome");
    } else return;
    e.preventDefault();
  });

  const renderCheck = (): void => {
    paintFilterInput(filterIn);
    filterErr.textContent = cap.filterState === "error" ? cap.filterError : "";
    filterErr.hidden = cap.filterState !== "error";
    renderIfaces();
  };

  const renderState = (): void => {
    const s = app.state;
    if (!s) return;
    errBox.hidden = !s.loadError;
    setText(errBox, s.loadError ? `Couldn't load the capture: ${s.loadError}` : "");
    const st = captureStatusText(s);
    capStatus.hidden = st.cls === "idle";
    capStatus.className = `wl-capstatus ${st.cls}`;
    setText(capStatus, st.text);
  };

  const root = h(
    "div",
    { class: "welcome" },
    h(
      "div",
      { class: "wl-inner" },
      h("div", { class: "wl-head" }, icon("wireshark", "icon wl-logo"), h("div", null, h("h1", null, `Welcome to ${APP_NAME}`), h("div", { class: "wl-sub" }, "Open a capture file or start a live capture."))),
      errBox,
      h("section", { class: "wl-section" }, h("h2", null, "Open"), h("div", { class: "wl-row" }, openBtn), recentList),
      h(
        "section",
        { class: "wl-section" },
        h("h2", null, "Capture"),
        h("div", { class: "wl-row" }, h("label", { class: "wl-lbl" }, "…using this filter:"), filterIn, h("button", { class: "tb-mini", title: "Refresh interfaces", attrs: { "aria-label": "Refresh interfaces" }, onclick: () => void loadInterfaces() }, icon("refresh"))),
        filterErr,
        capStatus,
        ifaceList,
      ),
    ),
  );

  const shown = (): boolean => !!app.state && !app.state.file && !app.state.loading;
  watchActivity(shown);
  activityBus.on("update", () => {
    for (const [name, el] of sparks) paintSpark(el, name);
  });

  let wasVisible = false;
  bus.on("state", (s) => {
    renderState();
    const visible = !s.file && !s.loading;
    if (visible && !wasVisible) {
      void loadRecent();
      if (!cap.interfaces && !cap.ifaceLoading) void loadInterfaces();
      void pollActivity();
    }
    wasVisible = visible;
    renderIfaces();
  });
  bus.on("tick", renderState);
  capBus.on("ifaces", renderIfaces);
  capBus.on("check", renderCheck);
  capBus.on("opts", (src) => {
    if (src !== "welcome" && document.activeElement !== filterIn) filterIn.value = capOpts.filter;
    renderIfaces();
  });
  recentList.replaceChildren(h("div", { class: "wl-empty" }, "Loading recent files\u2026"));
  renderCheck();
  return root;
}
