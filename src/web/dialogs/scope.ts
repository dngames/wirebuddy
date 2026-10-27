/** "Limit to display filter" checkbox shared by the statistics dialogs. */

import { app } from "../app.ts";
import { h } from "../util.ts";

export interface ScopeControl {
  el: HTMLElement;
  /** Display filter to send, or undefined for all packets. */
  filter(): string | undefined;
  /** Footer text describing what the numbers cover. */
  text(): string;
}

export function scopeControl(onChange: () => void): ScopeControl {
  const box = h("input", { type: "checkbox" });
  const f0 = app.state?.filter ?? "";
  box.disabled = !f0;
  const el = h("label", { class: "cb-check stat-scope", title: f0 ? "Only count the packets matching the current display filter" : "No display filter is applied" }, box, "Limit to display filter");
  box.addEventListener("change", onChange);
  const filter = (): string | undefined => (box.checked && app.state?.filter ? app.state.filter : undefined);
  return {
    el,
    filter,
    text: () => {
      const f = filter();
      return f ? `Display filter: ${f.length > 100 ? `${f.slice(0, 100)}…` : f}` : "All packets";
    },
  };
}
