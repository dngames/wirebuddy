/** WireBuddy web UI entry point: builds the main window and wires the modules. */

import { APP_NAME, token } from "./api.ts";
import * as act from "./actions.ts";
import { app, bus } from "./app.ts";
import { createBanner } from "./banner.ts";
import { clearBytesHighlight, createBytesPane, highlightBytes, setBytesFrame } from "./bytes.ts";
import { createCaptureBar } from "./capture.ts";
import { createDetailsPane, selectByOffset, setDetailsFrame } from "./details.ts";
import { closeTopDialog, dialogOpen } from "./dialog.ts";
import { openGotoDialog } from "./dialogs/goto.ts";
import { openFileDialog } from "./dialogs/openfile.ts";
import { createFilterBar, focusFilter } from "./filterbar.ts";
import { nodeAtOffset, srcIndex } from "./frame.ts";
import { menuOpen } from "./menu.ts";
import { createPacketList, focusPacketList, stepPacket } from "./packetlist.ts";
import { createPanes } from "./panes.ts";
import { createStatusBar } from "./statusbar.ts";
import { createToastHost, toast } from "./toast.ts";
import { createToolbar } from "./toolbar.ts";
import { baseName, h, isMod, isTextInput } from "./util.ts";
import { createWelcome } from "./welcome.ts";
import { connectWs } from "./ws.ts";

function onGlobalKey(e: KeyboardEvent): void {
  if (menuOpen() || e.defaultPrevented) return;
  if (e.key === "Escape") {
    if (closeTopDialog()) e.preventDefault();
    return;
  }
  if (dialogOpen()) return;
  const mod = isMod(e);
  const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
  const inText = isTextInput(document.activeElement);
  if (mod && !e.altKey && key === "/") {
    e.preventDefault();
    focusFilter();
  } else if (mod && !e.altKey && !e.shiftKey && key === "g") {
    e.preventDefault();
    openGotoDialog();
  } else if (mod && !e.altKey && !e.shiftKey && key === "o") {
    e.preventDefault();
    openFileDialog();
  } else if (mod && !e.altKey && !e.shiftKey && key === "m" && !inText) {
    e.preventDefault();
    act.toggleMark(app.selFrame);
  } else if (mod && !e.altKey && !e.shiftKey && (key === "ArrowDown" || key === "ArrowUp") && !inText) {
    e.preventDefault();
    stepPacket(key === "ArrowDown" ? 1 : -1);
  }
}

function init(): void {
  const root = document.getElementById("app") ?? document.body.appendChild(h("div", { id: "app" }));
  document.body.appendChild(createToastHost());

  const toolbar = createToolbar();
  const captureBar = createCaptureBar();
  const filterBar = createFilterBar();
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

  root.replaceChildren(toolbar, captureBar, filterBar, banner, main, createStatusBar());

  // Bytes first: details re-selects a field, which highlights into the new bytes.
  bus.on("frame", (fd) => {
    setBytesFrame(fd);
    setDetailsFrame(fd);
  });

  let lastLoadError: string | null = null;
  bus.on("state", (s) => {
    if (s.loadError && s.loadError !== lastLoadError) toast("error", `Loading failed: ${s.loadError}`);
    lastLoadError = s.loadError;
  });

  document.addEventListener("keydown", onGlobalKey);
  window.setInterval(() => bus.emit("tick"), 1000);

  if (!token) toast("error", `No session token in the page URL. Open ${APP_NAME} with the link the server printed.`);
  connectWs();
  void act.refreshState();
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
