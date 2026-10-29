/** Edit › Packet Comments: Wireshark's Add Packet Comment and Edit Packet Comment dialogs, and the menu entries. */

import type { CommentResult, FrameDetail } from "../../shared/api.ts";
import { countRanges } from "../../shared/ranges.ts";
import { errorText, HttpError, post } from "../api.ts";
import * as act from "../actions.ts";
import { app } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { SEP, type MenuItem } from "../menu.ts";
import { fmtInt, h, isMod, keyLabel } from "../util.ts";

/** As the server keeps it. */
const MAX_COMMENT = 2000;
/** Characters of a comment a menu entry shows, as in Wireshark. */
const MENU_TEXT = 40;

let current: Dialog | null = null;

/** Packets selected: the selected rows, else the current packet. */
function selectedCount(): number {
  return countRanges(app.selRows) || (app.selFrame !== null ? 1 : 0);
}

/** A comment in a menu entry, as Wireshark shows it: one line, cut short. */
function menuText(text: string): string {
  const line = text.trim().replace(/(\r?\n|\r\n?)+/g, " ");
  if (!line) return "(empty comment)";
  return line.length > MENU_TEXT ? `${line.slice(0, MENU_TEXT)}…` : line;
}

/**
 * Packet Comments ▸ for the selected packets: add, and with one packet
 * selected edit or delete each of its comments, as `fd` (its details) has them.
 */
export function commentItems(fd: FrameDetail | null = app.frame): MenuItem[] {
  const n = selectedCount();
  const items: MenuItem[] = [{ label: "Add New Comment…", shortcut: keyLabel("Ctrl+Alt+C"), disabled: !n || !app.state?.file, action: () => openCommentDialog() }];
  const comments = n === 1 && fd && fd.num === app.selFrame ? (fd.row?.cm ?? []) : [];
  if (fd && comments.length) {
    items.push(SEP, ...comments.map((c, i) => ({ label: `Edit "${menuText(c)}"`, title: c, action: () => openCommentDialog({ frame: fd.num, index: i, text: c }) })));
    items.push(SEP, ...comments.map((c, i) => ({ label: `Delete "${menuText(c)}"`, title: c, action: () => void act.deleteComment(fd.num, i, c) })));
    items.push(SEP, { label: "Delete packet comments", action: () => void act.deleteSelectedComments() });
  }
  if (n > 1) items.push(SEP, { label: `Delete comments from ${fmtInt(n)} packets`, action: () => void act.deleteSelectedComments() });
  return items;
}

/** Add New Comment… for the selected packets, or with `edit` one comment of a packet. */
export function openCommentDialog(edit?: { frame: number; index: number; text: string }): void {
  const s = app.state;
  if (!s?.file || current?.isOpen) return;
  // The comment goes to the packets selected now, even if the selection changes while typing
  const about = { frame: app.selFrame, rows: app.selRows, view: { file: s.file, filter: s.filter, generation: s.generation } };
  const count = countRanges(about.rows) || (about.frame !== null ? 1 : 0);
  if (!edit && !count) return;
  const d = new Dialog(edit ? "Edit Packet Comment" : "Add Packet Comment", { width: 460, cls: "dlg-comment" });
  current = d;
  const subject = edit ? `Comment ${edit.index + 1} of packet ${edit.frame}` : count > 1 ? `To the ${fmtInt(count)} selected packets` : `To packet ${about.frame}`;
  const input = h("textarea", { class: "ask-in", rows: 5, maxLength: MAX_COMMENT, value: edit?.text ?? "" });
  const err = h("div", { class: "of-err", hidden: true });
  d.body.append(h("div", { class: "goto-hint" }, subject), input, h("div", { class: "goto-hint" }, `${keyLabel("Ctrl+Enter")} saves it${edit ? "; an empty comment is deleted" : ""}.`), err);
  const showErr = (text: string): void => {
    err.textContent = text;
    err.hidden = false;
  };
  const save = async (): Promise<void> => {
    const comment = input.value;
    if (!edit && !comment) return showErr("Enter a comment");
    if (okBtn.disabled) return;
    okBtn.disabled = true;
    try {
      if (edit) await post<CommentResult>("api/comments/edit", { frame: edit.frame, index: edit.index, old: edit.text, comment });
      else await post<CommentResult>("api/comments", { comment, ...about });
      d.close();
      if (app.conn !== "open") void act.refreshState();
    } catch (e) {
      const stale = edit ? "The comment changed meanwhile; close this and choose it again" : "The packet list changed; close this and select the packets again";
      showErr(e instanceof HttpError && e.status === 409 ? stale : errorText(e));
    } finally {
      okBtn.disabled = false;
    }
  };
  input.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || !isMod(e) || e.isComposing) return;
    e.preventDefault();
    void save();
  });
  const okBtn = d.button("OK", () => void save(), { primary: true });
  d.button("Cancel", () => d.close());
  d.onClose = () => {
    current = null;
  };
  d.show(input);
  input.setSelectionRange(input.value.length, input.value.length);
}
