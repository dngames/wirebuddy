/**
 * Transient notifications in the lower right corner. An error always shows
 * here. With an agent attached it also goes to the agent, exactly once: the
 * server already logs a request it refused (toastError, toastRefused), so only
 * what the page alone knows about is reported by the page (toast).
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

function agentAttached(): boolean {
  return !!app.state?.agent.attached;
}

/** Tells the agent about a problem only the page knows about. */
export function reportProblem(text: string, details?: Record<string, unknown>): void {
  post("api/events", { level: "ERROR", text, details }).catch(() => {
    // the server is gone; the status bar says so
  });
}

/** Shows `text`; an error without an action also goes to an attached agent, as only the page knows of it. */
export function toast(level: "info" | "error", text: string, action?: ToastAction): void {
  if (level === "error" && !action && agentAttached()) reportProblem(text);
  show(level, text, action);
}

/** An error the server already logged for the agent (it refused the request): shown, not reported again. */
export function toastRefused(text: string): void {
  show("error", text);
}

function show(level: "info" | "error", text: string, action?: ToastAction): void {
  if (!host) {
    console.log(`[${level}] ${text}`);
    return;
  }
  // Repeat of the newest toast: restart it instead of stacking duplicates.
  const last = host.lastElementChild as HTMLElement | null;
  if (last && last.dataset.text === text && !last.classList.contains("out")) last.remove();

  const el = h("div", { class: `toast toast-${level}${action ? " toast-has-action" : ""}`, role: level === "error" ? "alert" : "status", data: { text } });
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
  const text = prefix ? `${prefix}: ${errorText(e)}` : errorText(e);
  // The server logs every request it refused except an unauthorized one
  if (e instanceof HttpError && e.status >= 400 && e.status !== 401 && e.status !== 403) toastRefused(text);
  else toast("error", text);
}
