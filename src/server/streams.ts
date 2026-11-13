/**
 * Follow Stream and Export Objects: a stream's payloads and the files carried
 * in the traffic as sharkd lists them, and saving those files into a folder
 * of their own (objects.ts does the writing). Each reads the viewer through
 * the few members of StreamsView.
 */

import { createHash } from "node:crypto";
import { newObjectFolder, objectDir, objectFileName, writeObject, type CapturedObject, type ObjectKind } from "./objects.ts";
import type { Sharkd } from "./sharkd.ts";
import { StaleGenerationError } from "./stale.ts";
import type { FollowResult } from "../shared/api.ts";

/** Bytes of payload data a follow result may carry before it is cut. */
export const FOLLOW_LIMIT = 4 * 1024 * 1024;
/** Largest object Export Objects saves (sharkd sends it as base64 JSON). */
const MAX_OBJECT_SAVE = 128 * 1024 * 1024;
/** Bytes one save of objects may write. */
const MAX_OBJECTS_SAVE = 1024 * 1024 * 1024;

/** What the streams and objects need of the viewer. */
export interface StreamsView {
  /** The sharkd the view reads from now. */
  engine(): Sharkd;
  requireFile(): void;
  /** Folders extensions load code from: nothing is saved there. */
  codeFolders(): string[];
  notice(text: string): void;
}

export async function follow(v: StreamsView, proto: string, filter: string, limit = FOLLOW_LIMIT): Promise<FollowResult> {
  v.requireFile();
  const r = await v.engine().call<{
    shost: string;
    sport: string;
    chost: string;
    cport: string;
    payloads?: { n: number; d: string; s?: number }[];
  }>("follow", { follow: proto, filter });
  if (r.shost === "NONE" && r.chost === "NONE" && !r.payloads?.length) throw new Error(`no ${proto} stream matches ${filter}`);
  const payloads: FollowResult["payloads"] = [];
  let total = 0;
  let omittedBytes = 0;
  let serverBytes = 0;
  let clientBytes = 0;
  for (const p of r.payloads ?? []) {
    const data = Buffer.from(p.d, "base64");
    if (p.s) serverBytes += data.length;
    else clientBytes += data.length;
    const room = limit - total;
    if (room <= 0) {
      omittedBytes += data.length;
      continue;
    }
    const part = data.length > room ? data.subarray(0, room) : data;
    omittedBytes += data.length - part.length;
    total += part.length;
    payloads.push({ frame: p.n, server: !!p.s, data: part === data ? p.d : part.toString("base64") });
  }
  return {
    proto,
    filter,
    server: { host: r.shost, port: r.sport, bytes: serverBytes },
    client: { host: r.chost, port: r.cport, bytes: clientBytes },
    payloads,
    truncated: omittedBytes > 0,
    omittedBytes,
  };
}

/** Files carried in the traffic (Wireshark's Export Objects) of `kind`. */
export async function capturedObjects(v: StreamsView, kind: ObjectKind, engine: Sharkd): Promise<CapturedObject[]> {
  v.requireFile();
  type Eo = { pkt: number; hostname?: string; type?: string; filename?: string; _download: string; len: number; sha1?: string };
  const r = await engine.call<{ taps?: { objects?: Eo[] }[] }>("tap", { tap0: `eo:${kind}` });
  return (r.taps?.[0]?.objects ?? []).map((o) => ({
    frame: o.pkt,
    host: o.hostname ?? "",
    type: o.type ?? "",
    filename: o.filename ?? "",
    size: o.len,
    sha1: o.sha1 ?? "",
    token: o._download,
  }));
}

/**
 * Saves the objects of `kind` into a new folder in `dir`, made once there is
 * one to save: those `pick.keys` ("frame:sha1") name, else those in
 * `pick.frames`, else all.
 */
export async function saveObjects(
  v: StreamsView,
  kind: ObjectKind,
  pick: { frames?: number[]; keys?: string[] },
  dir: string,
  by: "user" | "agent",
): Promise<{ folder: string | null; saved: (CapturedObject & { name: string })[]; skipped: { object: CapturedObject; reason: string }[] }> {
  const codeFolders = v.codeFolders();
  const real = objectDir(dir, codeFolders);
  // Download tokens belong to the sharkd that listed the objects
  const engine = v.engine();
  const all = await capturedObjects(v, kind, engine);
  const key = (o: CapturedObject): string => `${o.frame}:${o.sha1}`;
  let chosen: CapturedObject[];
  if (pick.keys) {
    const listed = new Set(all.map(key));
    // A key that names nothing came from another capture or dissection
    if (pick.keys.some((k) => !listed.has(k))) throw new StaleGenerationError("the capture changed; list the objects again");
    const want = new Set(pick.keys);
    chosen = all.filter((o) => want.has(key(o)));
  } else {
    const want = pick.frames && new Set(pick.frames);
    chosen = want ? all.filter((o) => want.has(o.frame)) : all;
  }
  if (!all.length) throw new Error(`the capture has no ${kind} objects`);
  if (!chosen.length) throw new Error(`none of the ${kind} objects is in the given frames`);
  let folder: string | null = null;
  const saved: (CapturedObject & { name: string })[] = [];
  const skipped: { object: CapturedObject; reason: string }[] = [];
  let total = 0;
  try {
    for (const o of chosen) {
      // Without one, a token a reload moved would save another object unnoticed
      if (!o.sha1) {
        skipped.push({ object: o, reason: "sharkd gave no checksum to check it by" });
        continue;
      }
      if (o.size > MAX_OBJECT_SAVE) {
        skipped.push({ object: o, reason: `larger than ${MAX_OBJECT_SAVE / 2 ** 20} MiB` });
        continue;
      }
      if (total + o.size > MAX_OBJECTS_SAVE) {
        skipped.push({ object: o, reason: `over the ${MAX_OBJECTS_SAVE / 2 ** 30} GiB one save may write` });
        continue;
      }
      const r = await engine.call<{ data?: string }>("download", { token: o.token });
      const data = Buffer.from(r.data ?? "", "base64");
      // Tokens are positions in sharkd's list: a reload may have moved them
      if (r.data === undefined || createHash("sha1").update(data).digest("hex") !== o.sha1) {
        throw new Error("the capture changed while saving; list the objects again");
      }
      total += data.length;
      folder ??= newObjectFolder(real, kind, codeFolders);
      saved.push({ ...o, name: writeObject(folder, objectFileName(o.frame, o.filename), data) });
    }
  } catch (err) {
    // What is already there stays: say where
    const names = saved.slice(0, 20).map((o) => o.name).join(", ") + (saved.length > 20 ? ", …" : "");
    const done = saved.length ? ` (${saved.length} saved to ${folder}: ${names})` : "";
    throw new Error(`${(err as Error).message}${done}`);
  }
  if (saved.length && by === "agent") v.notice(`Saved ${saved.length} ${kind.toUpperCase()} object${saved.length === 1 ? "" : "s"} to ${folder}`);
  return { folder, saved, skipped };
}
