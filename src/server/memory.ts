/**
 * Memory figures the viewer asks for: what a sharkd process holds, what the
 * system or its cgroup still has free, and whether another full read of a
 * capture would not fit.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

/** What a sharkd holds before it reads a file. */
const SHARKD_BASE_BYTES = 160 * 1024 * 1024;
/** Memory a full read must leave free. */
const MEMORY_MARGIN = 512 * 1024 * 1024;

/**
 * Whether a sharkd reading `next` frames needs more memory than is
 * `available`, beyond what the standby holds already: as much a frame as the
 * active one needs, which read `frames`.
 */
export function memoryShort(m: { activeBytes: number; frames: number; standbyBytes: number; next: number; available: number }): boolean {
  if (!m.frames) return false;
  const perFrame = Math.max(0, m.activeBytes - SHARKD_BASE_BYTES) / m.frames;
  return SHARKD_BASE_BYTES + perFrame * m.next - m.standbyBytes > m.available - MEMORY_MARGIN;
}

/** Where a process's resident memory comes from: /proc where there is one, else ps. */
export type RssSource = { hasProc: boolean; proc: (pid: number) => string; ps: (pid: number) => string };

const rssSource: RssSource = {
  hasProc: existsSync("/proc/self/status"),
  proc: (pid) => readFileSync(`/proc/${pid}/status`, "utf8"),
  ps: (pid) => execFileSync("ps", ["-o", "rss=", "-p", String(pid)], { encoding: "utf8", timeout: 2000, stdio: ["ignore", "pipe", "ignore"] }),
};
/** ps is asked again for a pid after this long. */
const RSS_CACHE_MS = 2000;
const rssCache = new Map<number, { at: number; bytes: number | null }>();

/** Resident memory of a process, or null: from /proc (Linux), else from `ps -o rss=` (KiB), cached for a moment. */
export function rssBytes(pid: number | null, source: RssSource = rssSource, now = Date.now()): number | null {
  if (!pid) return null;
  if (source.hasProc) {
    try {
      const kb = /^VmRSS:\s+(\d+) kB/m.exec(source.proc(pid));
      return kb ? Number(kb[1]) * 1024 : null;
    } catch {
      return null;
    }
  }
  const cached = rssCache.get(pid);
  if (cached && now - cached.at < RSS_CACHE_MS) return cached.bytes;
  let bytes: number | null = null;
  try {
    const kb = /^\s*(\d+)\s*$/.exec(source.ps(pid));
    bytes = kb ? Number(kb[1]) * 1024 : null;
  } catch {
    // the process is gone, or ps is
  }
  for (const [p, c] of rssCache) if (now - c.at >= RSS_CACHE_MS) rssCache.delete(p);
  rssCache.set(pid, { at: now, bytes });
  return bytes;
}

/** Memory the process can still use (Linux), or null: the smaller of the system's figure and its cgroup's headroom; WIREBUDDY_MEM_AVAILABLE (bytes) stands in for both in tests. */
export function availableBytes(): number | null {
  const fake = Number(process.env.WIREBUDDY_MEM_AVAILABLE);
  return fake > 0 ? fake : availableMemory();
}

/** Limits at or above this are the kernel's way of saying "none" (v1 reports 2^63 less a page). */
const NO_LIMIT = 2 ** 62;

/**
 * Memory that is free for this process: /proc/meminfo's MemAvailable, cut down to the headroom of the
 * tightest cgroup limit on its group or any ancestor, since in a container meminfo shows the host's
 * memory. Reclaimable file cache counts as free. Unreadable or absent counts as no limit; null if
 * nothing gives a figure.
 */
export function availableMemory(read: (file: string) => string = (f) => readFileSync(f, "utf8")): number | null {
  const text = (file: string): string => {
    try {
      return read(file);
    } catch {
      return "";
    }
  };
  const num = (file: string): number | null => {
    const n = /^\s*(\d+)\s*$/.exec(text(file));
    return n ? Number(n[1]) : null;
  };
  // Headroom under one group's limit, or null when it has none
  const headroom = (dir: string, limit: string, usage: string, stat: string, inactive: string): number | null => {
    const max = num(`${dir}/${limit}`);
    const used = num(`${dir}/${usage}`);
    if (max === null || max >= NO_LIMIT || used === null) return null;
    const cache = new RegExp(`^${inactive} (\\d+)`, "m").exec(text(`${dir}/${stat}`));
    return max - Math.max(0, used - (cache ? Number(cache[1]) : 0));
  };
  const figures: number[] = [];
  const kb = /^MemAvailable:\s+(\d+) kB/m.exec(text("/proc/meminfo"));
  if (kb) figures.push(Number(kb[1]) * 1024);
  const groups = text("/proc/self/cgroup");
  // v2: the group's own directory and every ancestor up to the root
  const own = /^0::(\/.*)$/m.exec(groups)?.[1] ?? "/";
  for (let dir = own.replace(/\/+$/, ""); ; dir = dir.slice(0, dir.lastIndexOf("/"))) {
    const room = headroom(`/sys/fs/cgroup${dir}`, "memory.max", "memory.current", "memory.stat", "inactive_file");
    if (room !== null) figures.push(room);
    if (!dir) break;
  }
  // v1: the group's folder when it exists, else the root one
  const v1 = /^\d+:(?:[^:]*,)?memory(?:,[^:]*)?:(\/.*)$/m.exec(groups)?.[1].replace(/\/+$/, "") ?? "";
  const folder = v1 && num(`/sys/fs/cgroup/memory${v1}/memory.limit_in_bytes`) !== null ? `/sys/fs/cgroup/memory${v1}` : "/sys/fs/cgroup/memory";
  const room = headroom(folder, "memory.limit_in_bytes", "memory.usage_in_bytes", "memory.stat", "total_inactive_file");
  if (room !== null) figures.push(room);
  return figures.length ? Math.max(0, Math.min(...figures)) : null;
}
