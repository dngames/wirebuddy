/**
 * Transient notifications in the lower right corner. With an agent attached,
 * errors go to the agent instead, which helps in the chat.
 */

import { errorText, HttpError, post } from "./api.ts";
import { app } from "./app.ts";
import { h } from "./util.ts";

let host: HTMLElement | null = null;
const MAX_TOASTS = 5;

export function createToastHost(): HTMLElement {
  host = h("div", { class: "toasts", attrs: { "aria-live": "polite" } });
  return host;
}

export interface ToastAction {
  label: string;
  run: () => void;
}

function agentTakesErrors(): boolean {
  return !!app.state?.agent.attached;
}

/** Tells the agent about a problem only the page knows about. */
export function reportProblem(text: string, details?: Record<string, unknown>): void {
  post("api/events", { level: "ERROR", text, details }).catch(() => {
    // the server is gone; the status bar says so
  });
}

export function toast(level: "info" | "error", text: string, action?: ToastAction): void {
  if (level === "error" && !action && agentTakesErrors()) {
    reportProblem(text);
    return;
  }
  if (!host) {
    console.log(`[${level}] ${text}`);
    return;
  }
  // Repeat of the newest toast: restart it instead of stacking duplicates.
  const last = host.lastElementChild as HTMLElement | null;
  if (last && last.dataset.text === text && !last.classList.contains("out")) last.remove();

  const el = h("div", { class: `toast toast-${level}`, role: level === "error" ? "alert" : "status", data: { text } });
  const remove = (): void => {
    if (el.classList.contains("out")) return;
    el.classList.add("out");
    window.setTimeout(() => el.remove(), 180);
  };
  el.append(h("span", { class: "toast-text" }, text));
  if (action) {
    el.append(
      h("button", {
        class: "toast-action",
        onclick: () => {
          remove();
          action.run();
        },
      }, action.label),
    );
  }
  el.append(h("button", { class: "toast-x", title: "Dismiss", attrs: { "aria-label": "Dismiss" }, onclick: remove }, "×"));
  host.appendChild(el);
  while (host.childElementCount > MAX_TOASTS) host.firstElementChild?.remove();
  // Toasts with an action stay longer so there is time to use it.
  window.setTimeout(remove, action ? 12000 : level === "error" ? 9000 : 4500);
}

export function toastError(e: unknown, prefix?: string): void {
  // The server already told the agent about a request it refused
  if (agentTakesErrors() && e instanceof HttpError && e.status >= 400) return;
  toast("error", prefix ? `${prefix}: ${errorText(e)}` : errorText(e));
}
