/** Dismissable banner showing the agent's last action (state.agentNotice). */

import type { AgentNotice } from "../shared/api.ts";
import { agentName, app, bus } from "./app.ts";
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
