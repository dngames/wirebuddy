/** Start page shown when no capture file is open. */

import type { RecentFiles } from "../shared/api.ts";
import { APP_NAME, get } from "./api.ts";
import * as act from "./actions.ts";
import { app, bus, captureActive } from "./app.ts";
import { cap, capBus, capOpts, captureStatusText, loadInterfaces, paintFilterInput, setOpts, startCaptureClicked } from "./capture.ts";
import { openFileDialog } from "./dialogs/openfile.ts";
import { icon } from "./icons.ts";
import { toast } from "./toast.ts";
import { baseName, dirName, fmtDateTime, fmtSize, h, setText } from "./util.ts";

export function createWelcome(): HTMLElement {
  const recentList = h("div", { class: "wl-list" });
  const ifaceList = h("div", { class: "wl-list" });
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
    if (cap.ifaceLoading && !cap.interfaces) {
      ifaceList.replaceChildren(h("div", { class: "wl-empty" }, "Looking for interfaces…"));
      return;
    }
    if (cap.ifaceError) {
      ifaceList.replaceChildren(h("div", { class: "wl-empty error" }, `Capture interfaces unavailable: ${cap.ifaceError}`));
      return;
    }
    const list = cap.interfaces ?? [];
    if (!list.length) {
      ifaceList.replaceChildren(h("div", { class: "wl-empty" }, "No capture interfaces found"));
      return;
    }
    ifaceList.replaceChildren(
      ...list.map((i) => {
        const start = h(
          "button",
          { class: "btn wl-start", disabled: active || cap.filterState === "error", title: `Start capturing on ${i.name}`, onclick: () => void startCaptureClicked(i.name) },
          icon("fin"),
          h("span", null, "Start"),
        );
        return h(
          "div",
          { class: `wl-iface${i.name === capOpts.iface ? " current" : ""}` },
          icon("iface"),
          h(
            "span",
            { class: "wl-item-main" },
            h("span", { class: "wl-name" }, i.name, i.description && i.description !== i.name ? h("span", { class: "wl-desc" }, ` ${i.description}`) : null, i.loopback ? h("span", { class: "wl-tag" }, "loopback") : null),
            h("span", { class: "wl-path" }, i.addresses.length ? i.addresses.join(", ") : "no addresses"),
          ),
          start,
        );
      }),
    );
  };

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

  let wasVisible = false;
  bus.on("state", (s) => {
    renderState();
    const visible = !s.file && !s.loading;
    if (visible && !wasVisible) {
      void loadRecent();
      if (!cap.interfaces && !cap.ifaceLoading) void loadInterfaces();
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
