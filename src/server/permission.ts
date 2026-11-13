import { userInfo } from "node:os";

/** The user WireBuddy runs as: its name, else its id. */
function runningAs(): string {
  try {
    return userInfo().username;
  } catch {
    return `uid ${process.getuid?.() ?? "?"}`;
  }
}

/**
 * What a failed write into `folder` says: when it was refused for lack of
 * permission, who WireBuddy runs as, which may not be who the agent's shell
 * or the user's terminal runs as; any other error as it is.
 */
export function writeRefused(err: unknown, folder: string): Error {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code !== "EACCES" && code !== "EPERM") return err instanceof Error ? err : new Error(String(err));
  return new Error(`permission denied: WireBuddy runs as the user ${runningAs()}, and this user can't write to ${folder} (a shell of yours or the agent's may run as another user)`);
}
