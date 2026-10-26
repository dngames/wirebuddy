/** HTTP client for the WireBuddy server API. */

import type { ApiError } from "../shared/api.ts";

export const APP_NAME = "WireBuddy";

export const token: string = new URLSearchParams(location.search).get("token") ?? "";

export class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "HttpError";
  }
}

type Query = Record<string, string | number | boolean | null | undefined>;

/** Resolves against the page URL so the UI also works behind a path prefix. */
function apiUrl(path: string, query?: Query): string {
  const u = new URL(path.replace(/^\//, ""), document.baseURI);
  u.hash = "";
  u.search = "";
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null) u.searchParams.set(k, String(v));
    }
  }
  return u.href;
}

async function request<T>(method: "GET" | "POST", path: string, query?: Query, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "X-WireBuddy-Token": token, Accept: "application/json" };
  let payload: string | undefined;
  if (method === "POST") {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body ?? {});
  }
  let res: Response;
  try {
    res = await fetch(apiUrl(path, query), { method, headers, body: payload, cache: "no-store" });
  } catch {
    throw new HttpError(0, `Cannot reach the ${APP_NAME} server`);
  }
  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = undefined;
    }
  }
  if (!res.ok) {
    const err = data as Partial<ApiError> | undefined;
    const msg = typeof err?.error === "string" && err.error ? err.error : `${res.status} ${res.statusText}`.trim();
    throw new HttpError(res.status, msg);
  }
  return data as T;
}

export function get<T>(path: string, query?: Query): Promise<T> {
  return request<T>("GET", path, query);
}

export function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>("POST", path, undefined, body);
}

export function wsUrl(): string {
  const u = new URL("ws", document.baseURI);
  u.protocol = u.protocol === "https:" ? "wss:" : "ws:";
  u.hash = "";
  u.search = "";
  u.searchParams.set("token", token);
  return u.href;
}

export function errorText(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
