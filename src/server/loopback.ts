/**
 * The server's listening sockets: one port on every loopback address, so no
 * other program on this machine can answer for a name that resolves to one
 * of them.
 */

import type { Server } from "node:http";

/** The loopback addresses browsers resolve `localhost` and `*.localhost` names (the panels' hosts) to. */
const LOOPBACK = ["127.0.0.1", "::1"];
/** Ports tried until one is free on every loopback address. */
const PORT_TRIES = 5;

function listen(server: Server, port: number, host: string): Promise<void> {
  return new Promise((resolveListen, reject) => {
    const failed = (err: Error): void => {
      server.off("listening", done);
      reject(err);
    };
    const done = (): void => {
      server.off("error", failed);
      resolveListen();
    };
    server.once("error", failed);
    server.once("listening", done);
    server.listen(port, host);
  });
}

/**
 * Listens on `port` of every address in `hosts`, with a server of `make`
 * each, so that no other program can hold the same port on one of them and
 * get the requests a browser sends there. A port in use (on the first
 * address, or by another program on a later one) gives way to a free one the
 * system picks; an address this machine doesn't have is left out, as nobody
 * else can listen there either.
 */
export async function listenLoopback(make: () => Server, port: number, hosts = LOOPBACK): Promise<{ servers: Server[]; port: number }> {
  for (let attempt = 0; attempt < PORT_TRIES; attempt++) {
    const wanted = attempt === 0 ? port : 0;
    const first = make();
    try {
      await listen(first, wanted, hosts[0]);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EADDRINUSE" && wanted !== 0) continue;
      throw err;
    }
    const address = first.address();
    const bound = typeof address === "object" && address ? address.port : wanted;
    const servers = [first];
    let taken = false;
    for (const host of hosts.slice(1)) {
      const server = make();
      try {
        await listen(server, bound, host);
        servers.push(server);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EADDRINUSE") continue;
        taken = true;
        break;
      }
    }
    if (!taken) return { servers, port: bound };
    await Promise.all(servers.map((s) => new Promise((closed) => s.close(closed))));
  }
  throw new Error(`no port is free on ${hosts.join(" and ")} at once`);
}
