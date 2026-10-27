/** Wireshark's menu bar, with the entries WireBuddy supports. */

import type { RecentFiles } from "../shared/api.ts";
import { get } from "./api.ts";
import * as act from "./actions.ts";
import { app, bus, hooks } from "./app.ts";
import { item, type CommandId } from "./commands.ts";
import { fieldCopyItems, fieldFilterItems } from "./details.ts";
import { followItems } from "./dialogs/follow.ts";
import { conversationFilters } from "./frame.ts";
import { closeMenus, menuOpen, menuOwner, SEP, showMenu, toggleMenuAt, type MenuItem } from "./menu.ts";
import { packetCopyItems } from "./packetlist.ts";
import { toast } from "./toast.ts";
import { baseName, h, IS_MAC, isTextInput, keyLetter } from "./util.ts";

interface TopMenu {
  title: string;
  /** Mnemonic letter: Alt+key opens the menu. */
  key: string;
  items: () => MenuItem[];
}

let recent: RecentFiles["files"] = [];
let openAt: (i: number, focusFirst: boolean) => void = () => {};

async function loadRecent(): Promise<void> {
  try {
    recent = (await get<RecentFiles>("api/recent")).files ?? [];
  } catch {
    // keeps the last list
  }
}

function items(...entries: (CommandId | MenuItem)[]): MenuItem[] {
  return entries.map((e) => (typeof e === "string" ? item(e) : e));
}

function link(label: string, url: string): MenuItem {
  return { label, action: () => window.open(url, "_blank", "noopener,noreferrer") };
}

function recentItems(): MenuItem[] {
  if (!recent.length) return [{ label: "No Recent Files", disabled: true }];
  return recent.slice(0, 15).map((f) => ({
    label: f.path,
    action: async () => {
      const err = await act.openFile(f.path);
      if (err) toast("error", `Can't open ${baseName(f.path)}: ${err}`);
    },
  }));
}

/** Marked packets with their notes. */
function markItems(): MenuItem[] {
  const marks = [...app.marks.values()].sort((a, b) => a.frame - b.frame);
  const out: MenuItem[] = marks.slice(0, 300).map((m) => ({
    label: `No. ${m.frame}`,
    detail: m.note || undefined,
    shortcut: m.by === "agent" ? "Claude" : "",
    checked: m.frame === app.selFrame,
    title: m.note || undefined,
    action: () => act.jumpToFrame(m.frame),
  }));
  if (marks.length > 300) out.push({ label: `…and ${marks.length - 300} more`, disabled: true });
  return out;
}

function conversationItems(): MenuItem[] {
  return app.frame ? conversationFilters(app.frame).map((c) => ({ label: c.label, action: () => hooks.setFilter(c.filter, true) })) : [];
}

function analyzeItems(): MenuItem[] {
  const apply = fieldFilterItems(true);
  const conv = conversationItems();
  const follow = followItems(app.frame);
  return [
    item("applyAsColumn"),
    SEP,
    { label: "Apply as Filter", sub: apply, disabled: !apply.length },
    { label: "Prepare as Filter", sub: fieldFilterItems(false), disabled: !apply.length },
    { label: "Conversation Filter", sub: conv, disabled: !conv.length },
    SEP,
    { label: "Follow", sub: follow },
    SEP,
    item("expertInfo"),
  ];
}

const MENUS: TopMenu[] = [
  {
    title: "File",
    key: "F",
    items: () => [item("open"), { label: "Open Recent", sub: recentItems() }, SEP, item("close"), SEP, item("saveAs"), SEP, item("exportSpecified")],
  },
  {
    title: "Edit",
    key: "E",
    items: () => [
      { label: "Copy", sub: [...packetCopyItems(), SEP, ...fieldCopyItems()] },
      SEP,
      ...items("find", "findNext", "findPrevious", SEP, "markToggle", "markAllDisplayed", "unmarkAllDisplayed", "unmarkAll", "nextMark", "previousMark"),
    ],
  },
  {
    title: "View",
    key: "V",
    items: () =>
      items("zoomIn", "zoomOut", "zoomNormal", "resizeColumns", "resetLayout", SEP, "expandSubtrees", "collapseSubtrees", "expandAll", "collapseAll", SEP, "colorize", "autoScroll", SEP, "reload"),
  },
  {
    title: "Go",
    key: "G",
    items: () => [
      ...items("gotoPacket", SEP, "forward", "back", SEP, "nextPacket", "previousPacket", "firstPacket", "lastPacket"),
      SEP,
      { label: "Marked Packets", sub: markItems(), disabled: !app.marks.size },
    ],
  },
  { title: "Capture", key: "C", items: () => items("captureOptions", "startCapture", "stopCapture", "restartCapture", SEP, "refreshInterfaces") },
  { title: "Analyze", key: "A", items: analyzeItems },
  { title: "Statistics", key: "S", items: () => items("protocolHierarchy", "conversations", "endpoints", SEP, "ioGraphs") },
  { title: "Tools", key: "T", items: () => items("openInWireshark", "tlsKeys") },
  {
    title: "Help",
    key: "H",
    items: () => [
      link("Wireshark User's Guide", "https://www.wireshark.org/docs/wsug_html_chunked/"),
      link("Display Filter Reference", "https://www.wireshark.org/docs/dfref/"),
      SEP,
      link("WireBuddy on GitHub", "https://github.com/dngames/wirebuddy"),
    ],
  },
];

/** Alt+<mnemonic> opens a menu, also while another is open; F10 opens or closes the menu bar. */
export function menuBarKey(e: KeyboardEvent): boolean {
  if (e.key === "F10" && !e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
    e.preventDefault();
    if (menuOpen()) closeMenus();
    else openAt(0, true);
    return true;
  }
  // Option+letter types characters on macOS
  if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey || (IS_MAC && isTextInput(document.activeElement))) return false;
  const letter = keyLetter(e);
  const i = MENUS.findIndex((m) => m.key === letter);
  if (i < 0) return false;
  e.preventDefault();
  openAt(i, true);
  return true;
}

export function createMenuBar(): HTMLElement {
  const bar = h("div", { class: "menubar", role: "menubar" });
  const titles = MENUS.map((m) => {
    const k = m.title.indexOf(m.key);
    return h("button", { class: "mb-title", role: "menuitem", attrs: { "aria-haspopup": "menu" } }, m.title.slice(0, k), h("u", null, m.key), m.title.slice(k + 1));
  });
  const side = (i: number) => (d: 1 | -1) => openAt((i + d + MENUS.length) % MENUS.length, true);
  openAt = (i, focusFirst) => {
    const r = titles[i].getBoundingClientRect();
    showMenu(MENUS[i].items(), r.left, r.bottom, { owner: titles[i], focusFirst, onSide: side(i) });
  };
  titles.forEach((btn, i) => {
    // Keyboard focus stays where it was, e.g. in the packet list
    btn.addEventListener("mousedown", (e) => e.preventDefault());
    btn.addEventListener("click", () => toggleMenuAt(btn, MENUS[i].items, { onSide: side(i) }));
    // With a menu open, pointing at another title opens that one
    btn.addEventListener("pointerenter", () => {
      const o = menuOwner();
      if (menuOpen() && o && o !== btn && titles.includes(o as HTMLButtonElement)) openAt(i, false);
    });
    bar.append(btn);
  });

  void loadRecent();
  bus.on("state", (s, prev) => {
    if (!prev || s.file !== prev.file) void loadRecent();
  });
  return bar;
}
