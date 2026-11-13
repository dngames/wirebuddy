/** Dismissable banner showing the agent's last action (state.agentNotice). */

import type { AgentNotice, Question } from "../shared/api.ts";
import { agentName, app, bus } from "./app.ts";
import { aboutPackets, openQuestionsDialog } from "./dialogs/questions.ts";
import { icon } from "./icons.ts";
import { fmtAgo, h, load, save, setText, setTitle } from "./util.ts";

/** Ids restart with each server process, so the timestamp disambiguates. */
function noticeKey(n: AgentNotice): string {
  return `${n.id}:${n.at}`;
}

export function createBanner(): HTMLElement {
  let dismissed = load<string>("noticedismissed", "");
  const text = h("span", { class: "ab-text" });
  const ago = h("span", { class: "ab-ago" });
  const close = h("button", { class: "ab-close", title: "Dismiss", attrs: { "aria-label": "Dismiss" } }, icon("x"));
  const who = h("span", null, agentName());
  const root = h("div", { class: "agent-banner", hidden: true, role: "status" }, h("span", { class: "ab-badge" }, icon("sparkle"), who), text, ago, close);

  const update = (): void => {
    const n = app.state?.agentNotice ?? null;
    const show = !!n && noticeKey(n) !== dismissed;
    root.hidden = !show;
    if (!n || !show) return;
    setText(who, agentName());
    if (text.textContent !== n.text) text.textContent = n.text;
    setTitle(text, n.text);
    setText(ago, fmtAgo(n.at));
  };

  close.addEventListener("click", () => {
    const n = app.state?.agentNotice;
    if (n) {
      dismissed = noticeKey(n);
      save("noticedismissed", dismissed);
    }
    update();
  });

  bus.on("state", update);
  bus.on("tick", update);
  return root;
}

/** The key an answer is dismissed by: ids restart with each server process, so the time disambiguates. */
function answerKey(q: Question): string {
  return `${q.id}:${q.answer?.at}`;
}

/**
 * Under the agent's banner: a quiet line while questions to the agent wait
 * for an answer, and the latest answer until the user dismisses it. The
 * texts are the agent's and the user's: set as text, never as HTML.
 */
export function createQuestionBanner(): HTMLElement {
  let dismissed = load<string>("answerdismissed", "");
  const link = (): HTMLButtonElement => h("button", { class: "qb-link", onclick: openQuestionsDialog }, "All Questions…");
  const waitText = h("span", { class: "qb-wait-text" });
  const waitLink = link();
  const wait = h("div", { class: "qb-wait", hidden: true }, waitText, waitLink);
  const who = h("b", null);
  const answerText = h("span", { class: "qb-answer-text" });
  const askedText = h("div", { class: "qb-asked" });
  const close = h("button", { class: "ab-close", title: "Dismiss", attrs: { "aria-label": "Dismiss" } }, icon("x"));
  const answer = h("div", { class: "qb-answer", hidden: true, role: "status" }, h("span", { class: "qb-mark" }, icon("sparkle")), h("div", { class: "qb-body" }, h("div", null, who, answerText), askedText), link(), close);
  const root = h("div", { class: "question-banner", hidden: true }, wait, answer);

  const update = (): void => {
    const all = app.state?.questions ?? [];
    const open = all.filter((q) => !q.answer);
    const latest = all.filter((q) => q.answer).sort((a, b) => b.answer!.at - a.answer!.at)[0];
    const showAnswer = !!latest && answerKey(latest) !== dismissed;
    wait.hidden = !open.length;
    answer.hidden = !showAnswer;
    root.hidden = wait.hidden && answer.hidden;
    // One link is enough
    waitLink.hidden = !answer.hidden;
    if (open.length) {
      const about = aboutPackets(open[open.length - 1]);
      setText(waitText, `Asked ${agentName()}${open.length > 1 ? ` ${open.length} questions` : about ? ` about ${about}` : ""} · waiting`);
    }
    if (latest && showAnswer) {
      setText(who, `${agentName()} answered: `);
      setText(answerText, latest.answer!.text);
      setText(askedText, `You asked: ${latest.text}`);
      setTitle(askedText, latest.text);
    }
  };

  close.addEventListener("click", () => {
    const all = app.state?.questions ?? [];
    const latest = all.filter((q) => q.answer).sort((a, b) => b.answer!.at - a.answer!.at)[0];
    if (latest) {
      dismissed = answerKey(latest);
      save("answerdismissed", dismissed);
    }
    update();
  });

  bus.on("state", update);
  return root;
}
