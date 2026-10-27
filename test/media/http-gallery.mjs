// HTTP downloads for the http-gallery example: six images (PNG plain, gzip-encoded and
// chunked, BMP, SVG), a PNG that is not one, an HTML page and a JSON file, each on a
// connection of its own from 10.0.0.1 to 10.0.0.2:80.
// Usage: node test/media/http-gallery.mjs <out.pcap>
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { png } from "../gallery.mjs";
import { Pcap } from "./pcap.mjs";

/** A w x h 24-bit BMP: a diagonal stripe pattern. */
function bmp(w, h) {
  const row = Math.ceil((w * 3) / 4) * 4;
  const out = Buffer.alloc(54 + row * h);
  out.write("BM", 0, "latin1");
  out.writeUInt32LE(out.length, 2);
  out.writeUInt32LE(54, 10);
  out.writeUInt32LE(40, 14);
  out.writeInt32LE(w, 18);
  out.writeInt32LE(h, 22);
  out.writeUInt16LE(1, 26);
  out.writeUInt16LE(24, 28);
  out.writeUInt32LE(row * h, 34);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const on = ((x + y) >> 3) % 2 === 0;
      out.set(on ? [40, 160, 230] : [250, 240, 220], 54 + y * row + x * 3);
    }
  }
  return out;
}

const svg = Buffer.from(
  '<svg xmlns="http://www.w3.org/2000/svg" width="96" height="64" viewBox="0 0 96 64">' +
    '<rect width="96" height="64" fill="#223"/><circle cx="48" cy="32" r="22" fill="#e95"/>' +
    '<path d="M10 54 L86 10" stroke="#6cf" stroke-width="5"/></svg>',
);

/** What the fixture serves: path, content type, body, and how it is sent. */
export const FILES = [
  { path: "/img/sunrise.png", type: "image/png", body: png(96, 64, 20), image: true },
  { path: "/img/forest.png", type: "image/png", body: png(120, 80, 120), image: true, gzip: true },
  { path: "/img/ocean.png", type: "image/png", body: png(80, 80, 210), image: true, chunked: true },
  { path: "/img/stripes.bmp", type: "image/bmp", body: bmp(64, 48), image: true },
  { path: "/img/logo.svg", type: "image/svg+xml", body: svg, image: true },
  { path: "/img/dusk.png", type: "image/png", body: png(96, 96, 280), image: true },
  { path: "/img/broken.png", type: "image/png", body: Buffer.from("this is not a PNG at all\n".repeat(8)) },
  { path: "/index.html", type: "text/html", body: Buffer.from("<!doctype html><title>Gallery</title><h1>Pictures</h1>\n") },
  { path: "/api/list.json", type: "application/json", body: Buffer.from(JSON.stringify({ images: 6, updated: "2023-11-14" })) },
];

function response(f) {
  let body = f.gzip ? gzipSync(f.body, { level: 9 }) : f.body;
  const headers = [`HTTP/1.1 200 OK`, `Content-Type: ${f.type}`];
  if (f.gzip) headers.push("Content-Encoding: gzip");
  if (f.chunked) {
    headers.push("Transfer-Encoding: chunked");
    const chunks = [];
    for (let at = 0; at < body.length; at += 1000) {
      const c = body.subarray(at, at + 1000);
      chunks.push(Buffer.from(`${c.length.toString(16)}\r\n`), c, Buffer.from("\r\n"));
    }
    body = Buffer.concat([...chunks, Buffer.from("0\r\n\r\n")]);
  } else headers.push(`Content-Length: ${body.length}`);
  return Buffer.concat([Buffer.from(`${headers.join("\r\n")}\r\n\r\n`), body]);
}

/** Writes the capture; returns the files, those with `image` set are images. */
export function writeHttpGallery(path) {
  const pcap = new Pcap();
  let t = 0.1;
  FILES.forEach((f, i) => {
    const request = Buffer.from(`GET ${f.path} HTTP/1.1\r\nHost: gallery.example\r\nAccept-Encoding: gzip\r\n\r\n`);
    t = pcap.http(t, "10.0.0.1", 41000 + i, "10.0.0.2", request, response(f)) + 0.05;
  });
  pcap.write(path);
  return FILES;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const files = writeHttpGallery(process.argv[2] ?? "http-gallery.pcap");
  console.log(`${files.filter((f) => f.image).length} images, ${files.filter((f) => !f.image).length} other files`);
}
