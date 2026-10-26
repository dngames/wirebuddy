/** "Go to Packet" dialog (Ctrl+G). */

import * as act from "../actions.ts";
import { app } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { fmtInt, h } from "../util.ts";

let current: Dialog | null = null;

export function openGotoDialog(): void {
  const s = app.state;
  if (!s?.file || current?.isOpen) return;
  const d = new Dialog("Go to Packet", { width: 340, cls: "dlg-goto", resizable: false });
  current = d;
  const input = h("input", { type: "text", inputMode: "numeric", class: "goto-in", placeholder: "Packet number", value: app.selFrame ? String(app.selFrame) : "" });
  const err = h("div", { class: "of-err", hidden: true });
  d.body.append(
    h("div", { class: "dlg-field" }, h("label", null, "Packet number:", input)),
    h("div", { class: "goto-hint" }, `1 – ${fmtInt(s.totalFrames)}`),
    err,
  );
  const go = (): void => {
    const n = Number(input.value.trim());
    const total = app.state?.totalFrames ?? 0;
    if (!Number.isInteger(n) || n < 1 || (total > 0 && n > total)) {
      err.textContent = `Enter a packet number between 1 and ${fmtInt(total)}`;
      err.hidden = false;
      input.select();
      return;
    }
    d.close();
    act.jumpToFrame(n);
  };
  d.button("Go to Packet", go, { primary: true });
  d.button("Cancel", () => d.close());
  d.defaultAction = go;
  d.onClose = () => {
    current = null;
  };
  d.show(input);
  input.select();
}
