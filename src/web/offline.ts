/**
 * What the page says when it lost its server: the content on screen stays
 * but is dimmed after a few seconds (it is no longer current), and when the
 * server refuses the page's token (a restarted WireBuddy with another token,
 * a session that ended) a notice over the page says why and where the
 * current address comes from. The page keeps retrying quietly either way.
 */

import { APP_NAME } from "./api.ts";
import { app, bus } from "./app.ts";
import { h } from "./util.ts";
import { reconnectNow } from "./ws.ts";

export function createOfflineNotice(): HTMLElement {
  const retry = h("button", { class: "btn", onclick: () => reconnectNow() }, "Try again now");
  const root = h(
    "div",
    { class: "offline-notice", hidden: true, role: "alert" },
    h("div", { class: "on-title" }, `This page is no longer connected to ${APP_NAME}`),
    h(
      "p",
      null,
      `It belongs to a ${APP_NAME} session that has ended or has another token, so what is shown here is out of date and nothing you do here reaches the viewer. `,
      "The viewer's current address comes from the agent (its tools give it as ",
      h("code", null, "viewer_url"),
      `) or from the terminal ${APP_NAME} runs in.`,
    ),
    h("p", { class: "on-quiet" }, "This page keeps trying and picks up by itself if the token works again.", retry),
  );
  const update = (): void => {
    const closed = app.conn === "closed";
    // The content of a page that lost its server is not current: dimmed (after a few seconds, see the style) so that it doesn't look so
    document.body.classList.toggle("wb-offline", closed);
    root.hidden = !(closed && app.unauthorized);
  };
  bus.on("conn", update);
  update();
  return root;
}
