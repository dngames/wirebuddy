/** Analyze > Extensions: the Lua dissectors the agent (or the user) added. */

import type { ExtensionInfo, ExtensionList } from "../../shared/api.ts";
import { errorText, get, post } from "../api.ts";
import * as act from "../actions.ts";
import { agentName, app, bus } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { closePanel, openPanel } from "../panels.ts";
import { h } from "../util.ts";

const STATUS: Record<ExtensionInfo["status"], string> = {
  new: "Not loaded yet",
  loaded: "Loaded",
  error: "Load error",
  off: "Off",
  invalid: "Invalid",
  untrusted: "Not trusted",
};

let current: Dialog | null = null;

export function openExtensionsDialog(): void {
  if (current?.isOpen) return current.raise();
  const d = new Dialog("Extensions", { width: 760, height: 420, cls: "dlg-ext", modal: false });
  current = d;

  const intro = h("div", { class: "ext-intro" });
  const wrap = h("div", { class: "stat-wrap" });
  const err = h("div", { class: "of-err", hidden: true });
  const showErr = (m: string | null): void => {
    err.textContent = m ?? "";
    err.hidden = !m;
  };
  d.body.append(intro, wrap);
  d.footerLeft.append(err);

  let busy = false;
  const render = (list: ExtensionList): void => {
    const who = app.state?.agent.attached ? agentName() : "your agent";
    intro.replaceChildren(
      h("div", null, `Lua dissectors for protocols Wireshark doesn't decode. Ask ${who} to write one for traffic shown as "Data", or add your own folder with an extension.json and .lua files to:`),
      h("div", { class: "ext-dir", title: list.dir }, list.dir),
    );
    if (list.unavailable) intro.append(h("div", { class: "of-err" }, `Extensions are unavailable: ${list.unavailable}`));
    for (const why of list.ignored) intro.append(h("div", { class: "of-err" }, `Not loaded, others could change it: ${why}`));
    // Re-rendering replaces the checkbox that had the focus
    const focused = wrap.contains(document.activeElement) ? (document.activeElement as HTMLElement).dataset.ext : undefined;
    if (!list.extensions.length) {
      wrap.replaceChildren(h("div", { class: "of-empty" }, "No extensions yet."));
      return;
    }
    const rows = list.extensions.flatMap((e) => {
      const toggle = h("input", { type: "checkbox", checked: e.enabled, attrs: { "aria-label": `Use ${e.label}`, "data-ext": e.name } });
      toggle.addEventListener("change", () => void setEnabled(e.name, toggle.checked));
      const row = h(
        "tr",
        null,
        h("td", { class: "left ext-on" }, toggle),
        h("td", { class: "left" }, h("div", { class: "ext-label" }, e.label), e.description ? h("div", { class: "ext-desc" }, e.description) : null),
        h("td", { class: "left" }, e.version),
        h("td", { class: "left ext-protos" }, e.protocols.join(", ")),
        h("td", { class: "left" }, panelCell(e)),
        h("td", { class: `left ext-status ${e.status}` }, STATUS[e.status]),
      );
      row.title = e.folder;
      return e.error ? [row, h("tr", { class: "ext-error" }, h("td"), h("td", { class: "left", colSpan: 5 }, e.error))] : [row];
    });
    wrap.replaceChildren(
      h(
        "table",
        { class: "stat-table ext-table" },
        h("thead", null, h("tr", null, h("th", { class: "left" }, "On"), h("th", { class: "left" }, "Extension"), h("th", { class: "left" }, "Version"), h("th", { class: "left" }, "Protocols"), h("th", { class: "left" }, "Panel"), h("th", { class: "left" }, "Status"))),
        h("tbody", null, rows),
      ),
    );
    if (focused) wrap.querySelector<HTMLElement>(`input[data-ext="${CSS.escape(focused)}"]`)?.focus();
  };

  const refresh = async (): Promise<void> => {
    try {
      render(await get<ExtensionList>("api/extensions"));
      showErr(null);
    } catch (e) {
      showErr(errorText(e));
    }
  };
  const run = async (fn: () => Promise<ExtensionList | null>): Promise<void> => {
    if (busy) return;
    busy = true;
    reloadBtn.disabled = true;
    for (const input of wrap.querySelectorAll("input")) input.disabled = true;
    let list: ExtensionList | null = null;
    try {
      list = await fn();
      showErr(null);
    } catch (e) {
      showErr(errorText(e));
    } finally {
      busy = false;
      reloadBtn.disabled = false;
    }
    // Also after a failure: the server may have switched extensions off meanwhile
    if (list) render(list);
    else await refresh();
  };
  const setEnabled = (name: string, on: boolean): Promise<void> => run(() => post<ExtensionList>("api/extensions/enable", { name, on }));

  // A panel's Open/Close; "files changed" when it shows older files than the folder has, and a broken offer
  const panelCell = (e: ExtensionInfo): (HTMLElement | string)[] => {
    if (!e.panel) return [];
    const usable = e.enabled && e.status !== "invalid" && e.status !== "untrusted";
    const btn = h("button", { class: "btn ext-panel", disabled: !usable, title: e.panel.title }, e.panel.open ? "Close" : "Open");
    btn.addEventListener("click", () => void run(async () => (await (e.panel!.open ? closePanel(e.name) : openPanel(e.name)), null)));
    const notes = [e.panel.stale ? " files changed" : "", e.panel.offerError ? " offer filter invalid" : ""].filter(Boolean);
    return notes.length ? [btn, h("span", { class: "ext-desc", title: e.panel.offerError ?? "" }, notes.join(","))] : [btn];
  };

  const reloadBtn = d.button("Reload", () => void run(() => act.reloadExtensions()), { title: "Load the extensions again from disk (Ctrl+Shift+L)" });
  d.button("Close", () => d.close(), { primary: true });

  // The agent adds, fixes and reloads extensions while the dialog is open
  let key = "";
  const onState = (): void => {
    const s = app.state?.extensions;
    const next = s ? `${s.active}|${s.failing}|${s.revision}` : "";
    if (next !== key && !busy) void refresh();
    key = next;
  };
  const off = bus.on("state", onState);
  d.onClose = () => {
    off();
    current = null;
  };
  d.show();
  onState();
}
