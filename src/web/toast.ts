/** Transient notifications in the lower right corner. */

import { errorText } from "./api.ts";
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

export function toast(level: "info" | "error", text: string, action?: ToastAction): void {
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
  toast("error", prefix ? `${prefix}: ${errorText(e)}` : errorText(e));
}
