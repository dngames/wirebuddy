// A stand-in for dumpcap that "captures" test/media/traffic.mjs on lo: it lists lo, accepts
// any capture filter, and writes a pcapng the way dumpcap does, at a steady rate, and the TLS
// key log of the traffic next to it (<file>.keys). The capture filter "burst <n> rate <pps>" sets
// the packets written at once, then per second.
// Usage: put an executable named dumpcap first on PATH that runs node test/fake-dumpcap.mjs "$@".
import { appendFileSync, closeSync, openSync, writeSync } from "node:fs";
import { header, packet, traffic } from "./media/traffic.mjs";

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

if (args.includes("-D")) {
  console.log(JSON.stringify([{ lo: { friendly_name: null, vendor_description: "Loopback", addrs: ["127.0.0.1"], loopback: true, extcap: "" } }]));
} else if (args.includes("-d")) {
  console.log("(000) ret      #262144");
} else if (args.includes("-S")) {
  // Interface statistics: lo only, nothing received
  const timer = setInterval(() => console.log("lo\t0\t0"), 1000);
  process.on("SIGTERM", () => (clearInterval(timer), process.exit(0)));
} else {
  const file = opt("-w");
  const [, burst = "0", rate = "1000"] = /burst (\d+) rate (\d+)/.exec(opt("-f") ?? "") ?? [];
  const stops = args.flatMap((a, i) => (args[i - 1] === "-a" ? [a.split(":")] : []));
  const duration = Number(stops.find(([k]) => k === "duration")?.[1] ?? Infinity) * 1000;
  const limit = Number(stops.find(([k]) => k === "packets")?.[1] ?? Infinity);
  const pps = Number(rate);
  const fd = openSync(file, "wx", 0o600);
  writeSync(fd, header());
  process.stderr.write(`Capturing on 'Loopback: lo'\nFile: ${file}\n`);
  const gen = traffic(1, (line) => appendFileSync(`${file}.keys`, line + "\n", { mode: 0o600 }));
  let n = 0;
  const write = (count) => {
    const parts = [];
    for (let k = 0; k < count && n < limit; k++, n++) parts.push(packet(n, gen.next().value, { pps: Math.max(pps, 1) }));
    if (parts.length) writeSync(fd, Buffer.concat(parts));
    process.stderr.write(`\rPackets: ${n} `);
  };
  const end = () => {
    clearInterval(timer);
    closeSync(fd);
    process.stderr.write(`\rPackets captured: ${n}\n`);
    process.exit(0);
  };
  // A burst in pieces, as a busy interface fills the file
  for (let left = Number(burst); left > 0; left -= 20000) write(Math.min(20000, left));
  const started = Date.now();
  let due = n;
  const timer = setInterval(() => {
    due += pps / 20;
    write(Math.floor(due) - n);
    if (n >= limit || Date.now() - started >= duration) end();
  }, 50);
  process.on("SIGINT", end);
  process.on("SIGTERM", end);
}
