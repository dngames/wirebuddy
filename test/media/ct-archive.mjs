// The CT-archive investigation (examples/investigations/ct-archive) as a capture on lo: the
// reconstruction server's exporter (AE title RECON) sends the head scan's two CT series to the
// archive (ARCHIVE on 127.0.0.1:11112) over one DICOM association, a C-STORE at a time, each
// answered with Success. Images and encoding come from the example's app.mjs.
//   By default with the app's bug: SOP Instance UIDs from the table position in whole mm, so 60 of
//   the 160 thin slices share their UID with the slice before; 184 C-STOREs, 124 UIDs.
//   --fixed: UIDs by instance number, 184 UIDs.
//   --then-fixed: the export with the bug, then the fixed one over a second association, as in a
//   capture that runs on across the fix.
// Usage: node test/media/ct-archive.mjs <out.pcap> [--fixed | --then-fixed]
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { C_STORE_RSP, PDU, SCAN, UID, associateRq, command, dataset, item, pData, pdu, slices, storeRq, uid, us } from "../../examples/investigations/ct-archive/app.mjs";
import { Pcap } from "./pcap.mjs";

export const PORT = 11112;
const HOST = "127.0.0.1";
const APP_PORT = 49352;
const MAX_PDU = 16384;
/** device.mjs's implementation class UID and version. */
const ARCHIVE_UID = "2.25.148319916397976774951993427761131673038";
const ARCHIVE_VERSION = "ARCHIVE_4_2";
const SYN = 0x02;
const FIN = 0x01;
const PSH = 0x08;
const ACK = 0x10;

const ascii = (s) => Buffer.from(s, "latin1");

/** The archive's A-ASSOCIATE-AC to the app's request, as device.mjs answers it. */
function associateAc(rq) {
  const head = Buffer.from(rq.subarray(6, 74));
  const maxLength = Buffer.alloc(4);
  maxLength.writeUInt32BE(MAX_PDU);
  return pdu(
    PDU.ASSOCIATE_AC,
    Buffer.concat([
      head,
      item(0x10, ascii(UID.applicationContext)),
      item(0x21, Buffer.concat([Buffer.from([1, 0, 0, 0]), item(0x40, ascii(UID.explicitLittleEndian))])),
      item(0x50, Buffer.concat([item(0x51, maxLength), item(0x52, ascii(ARCHIVE_UID)), item(0x55, ascii(ARCHIVE_VERSION))])),
    ]),
  );
}

function storeRsp(messageId, sopUid) {
  const rsp = command([
    [0x00000002, uid(UID.ctImageStorage)],
    [0x00000100, us(C_STORE_RSP)],
    [0x00000120, us(messageId)],
    [0x00000800, us(0x0101)],
    [0x00000900, us(0)],
    [0x00001000, uid(sopUid)],
  ]);
  return Buffer.concat(pData(1, true, rsp, MAX_PDU));
}

/**
 * Writes the capture; returns its frame count and the C-STOREs in order: the frame their dataset
 * ends in, series number, instance number, table position and SOP Instance UID; with the UIDs and
 * the C-STOREs overwritten, also per export.
 */
export function writeCtCapture(path, { fixed = false, thenFixed = false } = {}) {
  let seed = fixed ? 4111 : 1144;
  const rand = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const pcap = new Pcap();
  let frames = 0;
  let t = 0.2;
  /** One segment after `wait` seconds (give or take a fifth); returns its frame. */
  const tcp = (wait, from, to, flags, payload = Buffer.alloc(0)) => {
    t += wait * (0.8 + 0.4 * rand());
    pcap.tcp(t, from.ip, from.port, to.ip, to.port, from.seq, flags & ACK ? to.seq : 0, flags, payload);
    from.seq = (from.seq + payload.length + (flags & (SYN | FIN) ? 1 : 0)) >>> 0;
    return ++frames;
  };

  /** One export: an association on a connection of its own; returns its C-STOREs. */
  const exportScan = (fixedApp, connection) => {
    const app = { ip: HOST, port: APP_PORT + connection, seq: (0x5a1d0c3e + connection * 0x01000193) >>> 0 };
    const archive = { ip: HOST, port: PORT, seq: (0x0b7e44a1 + connection * 0x01000193) >>> 0 };
    tcp(0, app, archive, SYN);
    tcp(0.00003, archive, app, SYN | ACK);
    tcp(0.00002, app, archive, ACK);
    const rq = associateRq();
    tcp(0.0001, app, archive, PSH | ACK, rq);
    tcp(0.0002, archive, app, PSH | ACK, associateAc(rq));
    const stores = [];
    for (const series of SCAN.series) {
      for (const slice of slices(series)) {
        const sop = fixedApp ? `${series.uid}.${slice.instance}` : `${series.uid}.${Math.round(slice.location)}`;
        const id = stores.length + 1;
        // A segment per PDU, as the app writes them; the next image is made between C-STOREs
        let frame = tcp(series.thickness > 1 ? 0.0062 : 0.0024, app, archive, PSH | ACK, pData(1, true, storeRq(id, sop), MAX_PDU)[0]);
        for (const p of pData(1, false, dataset(series, slice, sop), MAX_PDU)) frame = tcp(0.00003, app, archive, PSH | ACK, p);
        tcp(0.0004, archive, app, PSH | ACK, storeRsp(id, sop));
        stores.push({ frame, series: series.number, instance: slice.instance, location: slice.location, sop });
      }
    }
    tcp(0.0002, app, archive, PSH | ACK, pdu(PDU.RELEASE_RQ, Buffer.alloc(4)));
    tcp(0.0001, archive, app, PSH | ACK, pdu(PDU.RELEASE_RP, Buffer.alloc(4)));
    tcp(0.00002, archive, app, FIN | ACK);
    tcp(0.00004, app, archive, FIN | ACK);
    tcp(0.00002, archive, app, ACK);
    return stores;
  };

  const exports = [exportScan(fixed, 0)];
  if (thenFixed) {
    t += 3;
    exports.push(exportScan(true, 1));
  }
  pcap.write(path);
  const count = (stores) => {
    const uids = new Set(stores.map((s) => s.sop));
    return { stores, uids: uids.size, overwritten: stores.length - uids.size };
  };
  return { frames, ...count(exports.flat()), exports: exports.map(count) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: { fixed: { type: "boolean", default: false }, "then-fixed": { type: "boolean", default: false } } });
  const s = writeCtCapture(positionals[0] ?? "ct-archive.pcap", { fixed: values.fixed, thenFixed: values["then-fixed"] });
  console.log(`${s.frames} frames: ${s.exports.map((e) => `${e.stores.length} C-STOREs, ${e.uids} SOP Instance UIDs, ${e.overwritten} overwritten`).join("; then ")}`);
}
