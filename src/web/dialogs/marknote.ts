/** Edit › Mark Packet with Note…: the user's mark with a note on the selected packets, and the menu entry. */

import type { MarkResult } from "../../shared/api.ts";
import { countRanges } from "../../shared/ranges.ts";
import { errorText, HttpError, post } from "../api.ts";
import * as act from "../actions.ts";
import { agentName, app } from "../app.ts";
import { Dialog } from "../dialog.ts";
import type { MenuItem } from "../menu.ts";
import { fmtInt, h } from "../util.ts";

/** As the server keeps it. */
const MAX_NOTE = 200;

let current: Dialog | null = null;

/** Packets selected: the selected rows, else the current packet. */
function selectedCount(): number {
  return countRanges(app.selRows) || (app.selFrame !== null ? 1 : 0);
}

/** The mark of the one packet selected, if it has one. */
function markOfSelected() {
  return selectedCount() === 1 && app.selFrame !== null ? app.marks.get(app.selFrame) : undefined;
}

/** Mark Packet with Note… beside Mark Packet; on a marked packet it edits the note. */
export function markNoteItem(): MenuItem {
  const n = selectedCount();
  const label = markOfSelected() ? "Edit Mark's Note…" : n > 1 ? `Mark ${fmtInt(n)} Packets with Note…` : "Mark Packet with Note…";
  return { label, disabled: !n || !app.state?.file, action: openMarkNoteDialog };
}

export function openMarkNoteDialog(): void {
  const s = app.state;
  if (!s?.file || current?.isOpen) return;
  // The mark goes to the packets selected now, even if the selection changes while typing
  const about = act.packetsAbout(s);
  const count = selectedCount();
  if (!count) return;
  const mark = markOfSelected();
  const d = new Dialog(mark ? "Edit Mark's Note" : "Mark Packet with Note", { width: 460, cls: "dlg-marknote", resizable: false });
  current = d;
  const subject = count > 1 ? `Mark the ${fmtInt(count)} selected packets` : `Mark packet ${about.frame}`;
  const input = h("input", { type: "text", class: "goto-in", maxLength: MAX_NOTE, value: mark?.note ?? "", attrs: { "aria-label": "Note" } });
  const err = h("div", { class: "of-err", hidden: true });
  const replaces = mark?.by === "agent" ? ` ${agentName()} marked it; your mark replaces its mark.` : "";
  d.body.append(h("div", { class: "goto-hint" }, subject), h("div", { class: "dlg-field" }, h("label", null, "Note:", input)), h("div", { class: "goto-hint" }, `Enter saves it.${replaces}`), err);
  const save = async (): Promise<void> => {
    if (okBtn.disabled) return;
    okBtn.disabled = true;
    try {
      await post<MarkResult>("api/marks", { note: input.value.trim(), ...about });
      d.close();
      if (app.conn !== "open") void act.refreshState();
    } catch (e) {
      err.textContent = e instanceof HttpError && e.status === 409 ? act.staleAbout(about) : errorText(e);
      err.hidden = false;
    } finally {
      okBtn.disabled = false;
    }
  };
  const okBtn = d.button("OK", () => void save(), { primary: true });
  d.button("Cancel", () => d.close());
  d.defaultAction = () => void save();
  d.onClose = () => {
    current = null;
  };
  d.show(input);
  input.setSelectionRange(input.value.length, input.value.length);
}
