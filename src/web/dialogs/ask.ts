/** Ask the agent (packet list context menu): a question about the selected packets that wakes the agent. */

import type { AskResult } from "../../shared/api.ts";
import { countRanges } from "../../shared/ranges.ts";
import { errorText, HttpError, post } from "../api.ts";
import { agentName, app } from "../app.ts";
import { Dialog } from "../dialog.ts";
import { toast } from "../toast.ts";
import { fmtInt, h } from "../util.ts";

/** As the server keeps it. */
const MAX_QUESTION = 2000;

let current: Dialog | null = null;

export function openAskDialog(): void {
  const s = app.state;
  if (!s?.agent.attached || current?.isOpen) return;
  const name = agentName();
  // The question is about the packets shown now, even if the selection changes while typing
  const about = s.file ? { frame: app.selFrame, rows: app.selRows, view: { file: s.file, filter: s.filter, generation: s.generation } } : null;
  const count = about ? countRanges(about.rows) || (about.frame !== null ? 1 : 0) : 0;
  const d = new Dialog(`Ask ${name}`, { width: 460, cls: "dlg-ask" });
  current = d;
  const subject = count > 1 ? `About the ${fmtInt(count)} selected packets` : count === 1 && app.selFrame !== null ? `About packet ${app.selFrame}` : "About the capture";
  const input = h("textarea", { class: "ask-in", rows: 4, maxLength: MAX_QUESTION, placeholder: "What should it look at or explain?" });
  const err = h("div", { class: "of-err", hidden: true });
  const reach = s.agent.watching ? `${name} is watching the viewer: the question wakes it.` : `${name} isn't watching the viewer right now: it gets the question with its next step.`;
  d.body.append(h("div", { class: "goto-hint" }, subject), input, h("div", { class: "goto-hint" }, `Enter sends. ${reach}`), err);
  const showErr = (text: string): void => {
    err.textContent = text;
    err.hidden = false;
  };
  const send = async (): Promise<void> => {
    const question = input.value.trim();
    if (!question) return showErr("Enter a question");
    if (sendBtn.disabled) return;
    sendBtn.disabled = true;
    try {
      const r = await post<AskResult>("api/agent/ask", about ? { question, ...about } : { question });
      d.close();
      toast("info", r.woken ? `Sent to ${name}` : `Sent. ${name} gets it with its next step`);
    } catch (e) {
      showErr(e instanceof HttpError && e.status === 409 ? "The packet list changed; close this and select the packets again" : errorText(e));
    } finally {
      sendBtn.disabled = false;
    }
  };
  input.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.shiftKey || e.isComposing) return;
    e.preventDefault();
    void send();
  });
  const sendBtn = d.button("Send", () => void send(), { primary: true });
  d.button("Cancel", () => d.close());
  d.onClose = () => {
    current = null;
  };
  d.show(input);
}
