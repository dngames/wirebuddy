/** Tools › Questions to the Agent…: what the user asked it this session, with its answers. */

import type { Question } from "../../shared/api.ts";
import * as act from "../actions.ts";
import { agentName, app, bus } from "../app.ts";
import { Dialog } from "../dialog.ts";
import type { MenuItem } from "../menu.ts";
import { otherCapture } from "../../shared/questions.ts";
import { fmtDateTime, h } from "../util.ts";

let current: Dialog | null = null;

/** What a question was about, as the page says packets: "packet 878", "3 packets", "" for none; "packet 878 of tank.pcap" when it is not the open capture's. */
export function aboutPackets(q: Question): string {
  const what = q.count <= 0 || q.frame === null ? "" : q.count === 1 ? `packet ${q.frame}` : `${q.count} packets`;
  const other = otherCapture(q, app.state?.file ?? null);
  return what && other ? `${what} of ${other}` : what;
}

/** The entry in the Tools menu. */
export function questionsItem(): MenuItem {
  return { label: `Questions to ${agentName()}…`, disabled: !app.state?.questions.length, action: openQuestionsDialog };
}

export function openQuestionsDialog(): void {
  if (current?.isOpen) return;
  // Modeless: an entry selects its packet in the list beside it
  const d = new Dialog(`Questions to ${agentName()}`, { width: 520, height: 380, cls: "dlg-questions", modal: false });
  current = d;
  const list = h("div", { class: "q-list" });
  d.body.append(list);
  // Only when the questions changed: a click on an entry must not land on one built again
  let shown: Question[] | undefined;
  let openFile: string | null | undefined;
  const render = (): void => {
    if (app.state?.questions === shown && app.state?.file === openFile) return;
    shown = app.state?.questions;
    openFile = app.state?.file ?? null;
    const questions = [...(shown ?? [])].reverse();
    if (!questions.length) {
      list.replaceChildren(h("div", { class: "goto-hint" }, "No questions asked yet."));
      return;
    }
    list.replaceChildren(
      ...questions.map((q) => {
        const about = aboutPackets(q);
        // Another capture is open now: its packet numbers are other packets
        const goes = q.frame !== null && q.file !== null && q.file === app.state?.file;
        const head = h("div", { class: "q-head" }, `${fmtDateTime(q.at)}${about ? ` · ${about}` : ""}`);
        const answer = q.answer ? h("div", { class: "q-answer" }, h("b", null, `${agentName()} answered: `), q.answer.text) : h("div", { class: "q-wait" }, "Waiting for an answer");
        return h("div", { class: `q-item${goes ? " q-goes" : ""}`, title: goes ? `Select packet ${q.frame}` : undefined, onclick: goes ? () => act.jumpToFrame(q.frame!) : undefined }, head, h("div", { class: "q-text" }, q.text), answer);
      }),
    );
  };
  render();
  const off = bus.on("state", render);
  d.button("Close", () => d.close(), { primary: true });
  d.onClose = () => {
    off();
    current = null;
  };
  d.show();
}
