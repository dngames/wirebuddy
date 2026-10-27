/** WireBuddy web UI entry point: builds the main window and wires the modules. */

import { APP_NAME, token } from "./api.ts";
import * as act from "./actions.ts";
import { app, bus } from "./app.ts";
import { createBanner } from "./banner.ts";
import { clearBytesHighlight, createBytesPane, highlightBytes, setBytesFrame } from "./bytes.ts";
import { createCaptureBar } from "./capture.ts";
import { claimOwnedKey, handleCommandKey } from "./commands.ts";
import { createDetailsPane, selectByOffset, setDetailsFrame } from "./details.ts";
import { closeTopDialog, dialogOpen } from "./dialog.ts";
import { createFilterBar } from "./filterbar.ts";
import { createFindBar } from "./findbar.ts";
import { nodeAtOffset, srcIndex } from "./frame.ts";
import { menuOpen } from "./menu.ts";
import { createMenuBar, menuBarKey } from "./menubar.ts";
import { createPacketList, focusPacketList } from "./packetlist.ts";
import { createPanes } from "./panes.ts";
import { createStatusBar } from "./statusbar.ts";
import { createToastHost, reportProblem, toast } from "./toast.ts";
import { createToolbar } from "./toolbar.ts";
import { baseName, h, isTextInput } from "./util.ts";
import { createWelcome } from "./welcome.ts";
import { connectWs } from "./ws.ts";

function onGlobalKey(e: KeyboardEvent): void {
  if (e.defaultPrevented) return;
  claimOwnedKey(e);
  if (e.key === "Escape" && !menuOpen()) {
    if (closeTopDialog()) e.preventDefault();
    return;
  }
  if (dialogOpen() || menuBarKey(e) || menuOpen()) return;
  handleCommandKey(e);
}

function init(): void {
  const root = document.getElementById("app") ?? document.body.appendChild(h("div", { id: "app" }));
  document.body.appendChild(createToastHost());

  const menuBar = createMenuBar();
  const toolbar = createToolbar();
  const captureBar = createCaptureBar();
  const filterBar = createFilterBar();
  const findBar = createFindBar();
  const banner = createBanner();

  const bytesPane = createBytesPane({
    onByteClick: (src, off) => {
      const fd = app.frame;
      if (fd) selectByOffset(nodeAtOffset(fd, src, off));
    },
  });
  const detailsPane = createDetailsPane({
    onSelect: (n) => {
      const fd = app.frame;
      if (fd && n?.h && n.h[1] > 0) highlightBytes(srcIndex(fd, n), n.h[0], n.h[1]);
      else clearBytesHighlight();
    },
  });
  const welcome = createWelcome();
  const main = h("div", { class: "main" }, welcome);
  // Registered before the packet list so the panes are visible when it measures itself.
  let hadFile = false;
  bus.on("state", (s) => {
    const showWelcome = !s.file && !s.loading;
    welcome.hidden = !showWelcome;
    panes.hidden = showWelcome;
    document.title = s.file ? `${baseName(s.file)} — ${APP_NAME}` : APP_NAME;
    const hasFile = !!s.file;
    if (hasFile && !hadFile && !isTextInput(document.activeElement)) window.setTimeout(focusPacketList, 0);
    hadFile = hasFile;
  });

  const list = createPacketList();
  const panes = createPanes(list, detailsPane, bytesPane);
  panes.hidden = true;
  main.appendChild(panes);

  root.replaceChildren(menuBar, toolbar, captureBar, filterBar, findBar, banner, main, createStatusBar());

  // View > Zoom scales the three panes, not the menus and bars
  const applyZoom = (): void => {
    if (app.zoom === 1) panes.style.removeProperty("zoom");
    else panes.style.setProperty("zoom", String(app.zoom));
  };
  bus.on("view", applyZoom);
  applyZoom();

  // Bytes first: details re-selects a field, which highlights into the new bytes.
  bus.on("frame", (fd) => {
    setBytesFrame(fd);
    setDetailsFrame(fd);
  });

  // Reloaded extensions dissect the shown packet differently
  let extKey = "";
  bus.on("state", (s) => {
    const key = `${s.instance}|${s.extensions.revision}`;
    if (extKey && key !== extKey) act.reloadFrame();
    extKey = key;
  });

  let lastLoadError: string | null = null;
  bus.on("state", (s) => {
    // With an agent attached the server has told it already
    if (s.loadError && s.loadError !== lastLoadError && !s.agent.attached) toast("error", `Loading failed: ${s.loadError}`);
    lastLoadError = s.loadError;
  });

  // Bugs in the page reach the agent too
  window.addEventListener("error", (e) => reportProblem(`Page error: ${e.message}`, { at: `${e.filename}:${e.lineno}:${e.colno}` }));
  window.addEventListener("unhandledrejection", (e) => reportProblem(`Page error: ${e.reason instanceof Error ? e.reason.message : String(e.reason)}`));

  document.addEventListener("keydown", onGlobalKey);
  window.setInterval(() => bus.emit("tick"), 1000);

  if (!token) toast("error", `No session token in the page URL. Open ${APP_NAME} with the link the server printed.`);
  connectWs();
  void act.refreshState();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
