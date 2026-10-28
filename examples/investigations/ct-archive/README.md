# CT archive: where do the thin slices go?

An investigation to try WireBuddy on, with the agent: thin-slice CT series that reach the image
archive with a third of their images missing. Everything runs on your machine over loopback, an
emulated image archive and the reconstruction server's exporter that sends it the images.

| File | What it is |
|---|---|
| `device.mjs` | The image archive, emulated: a DICOM storage SCP, AE title ARCHIVE, on TCP port 11112; it keeps the images in memory |
| `app.mjs` | The reconstruction server's exporter, AE title RECON: makes a head scan of a phantom and sends its 5 mm and 0.625 mm series in one association |
| `CONFORMANCE.md` | The archive vendor's DICOM conformance statement |
| `solution/` | Spoilers, see [Solution](#solution) |

## The symptom

Since the site added a 0.625 mm thin-slice reconstruction to the head protocol, radiologists find
those series in the archive with about 100 of their 160 images, and the reformats made from them
have steps. The 5 mm series of the same scans are complete. The exporter logs every image as stored
with status Success, and the archive team says the archive keeps whatever it receives.

## Run it

Node 22 or later, no dependencies. From the repository root, the archive in a terminal of its own
(or in the background with `&`), then the exporter:

```bash
node examples/investigations/ct-archive/device.mjs
node examples/investigations/ct-archive/app.mjs
```

```
association RECON -> ARCHIVE at 127.0.0.1:11112: CT Image Storage, Explicit VR Little Endian, max PDU 16384
series 2  Head 5.0     24 images, 24 Success
series 3  Head 0.625  160 images, 160 Success
184 images sent, 184 Success
```

The archive logs each association and how many images it holds of each series it received:

```
[1] RECON at 127.0.0.1:45136: association accepted, CT Image Storage in Explicit VR Little Endian
[1] released after 184 C-STORE: 184 Success
[1] series 2 (5 mm): 24 instances
[1] series 3 (0.625 mm): 100 instances
```

Both take `--port` (default 11112). The archive runs until you stop it with Ctrl+C; restart it for
an empty archive.

## Investigate it with the agent

Register WireBuddy with Claude Code and give `dumpcap` its capture permissions (see the main
[README](../../../README.md)), start the archive, then ask:

> Radiologists say our new 0.625 mm thin-slice head series show up in the archive with only about
> 100 of 160 images, and the reformats have steps; the 5 mm series from the same scan are complete.
> Our reconstruction server's exporter, examples/investigations/ct-archive/app.mjs, logs every image
> as stored with status Success. The archive vendor's conformance statement is
> examples/investigations/ct-archive/CONFORMANCE.md. The archive is running on port 11112. Capture
> an export and find out where the slices go.

To make the agent work from the traffic alone, ask it not to read `app.mjs` until it has an answer
from the capture.

### What to expect

1. The agent captures on `lo` with a capture filter for port 11112, runs the exporter and stops the
   capture when it is done: a few seconds, about 6 MB.
2. Wireshark decodes the DICOM traffic without help: the association, 184 C-STOREs and their
   responses, every one Success, and quiet expert info. Nothing is lost on the wire.
3. It lists the images with `export_objects`: 184 of them, but only 124 different SOP Instance
   UIDs. `inspect_frame` on two images with the same UID shows neighbouring thin slices.
4. It marks the pairs and may write a panel that shows the images, the series as sent and as the
   archive keeps it, and where the UIDs repeat.
5. It names the cause, shows it in the packets and in the code, and proposes a fix; it can save the
   images with `export_objects` for your own DICOM viewer. Apply the fix, restart the archive, and
   let the agent capture another export to confirm.

## Tests

`npm run test:examples` runs the archive and the exporter over loopback without a capture: it checks
the archive against PS3.8 and `CONFORMANCE.md` (association rejects and accepts, PDVs split at any
byte, release, aborts), that the exporter as shipped gets 184 Success while the archive keeps 24 of
24 and 100 of 160 images, and that `solution/fix.diff` gets all 160 kept. `npm run test:live`
captures an export on `lo` and checks that Wireshark exports its 184 images. `npm run test:browser`
opens `solution/ctseries` on captures made by `test/media/ct-archive.mjs`.

## Solution

**Spoilers from here on.**

In the capture, the exporter sends 184 C-STOREs and the archive answers each with Success. Export
Objects lists 184 images, but only 124 different SOP Instance UIDs: 60 UIDs of the thin series come
twice, each time on neighbouring slices, for example instances 2 and 3 at 870.625 and 871.25 mm,
both ending in `.871`. The archive does what its conformance statement says: an instance with a SOP
Instance UID it already holds replaces the stored one, and the C-STORE is answered with Success. So
60 thin slices are overwritten by their neighbours, the series keeps 100 images, and a viewer that
stacks them at 0.625 mm shows the head squashed, with steps.

The exporter keeps each slice's UID the same from one export to the next, so that a re-sent series
replaces itself instead of adding a copy. It builds the UID from the series UID and the table
position in whole millimetres:

```js
const sopUid = `${series.uid}.${Math.round(slice.location)}`;
```

At 5 mm every slice has a millimetre of its own. At 0.625 mm, 1.6 slices fall into each millimetre,
and 3 of every 8 round to the same number as the slice before.

The fix numbers the UIDs by instance number, which stay the same for a re-send,
[`solution/fix.diff`](solution/fix.diff):

```bash
git apply examples/investigations/ct-archive/solution/fix.diff
```

Restart the archive, which still holds the old UIDs, and export again:

```
[1] released after 184 C-STORE: 184 Success
[1] series 2 (5 mm): 24 instances
[1] series 3 (0.625 mm): 160 instances
```

Without the restart it logs 48 and 260 instances: the fix gives the images of both series new UIDs,
and the archive keeps the old ones next to them, as a real archive does until someone deletes them.

`solution/ctseries/` is a panel as the agent might write it: the series' images with brain and bone
windows, sagittal reformats as sent and as the archive keeps them, and every C-STORE in capture
order with the repeated UIDs in red; a click selects the C-STORE's packet. It shows one association
at a time, the latest unless you pick another, so a capture that runs on across the fix shows each
export apart. Copy it into `~/.local/share/wirebuddy/extensions/` to compare; WireBuddy offers it in
the status bar for captures with DICOM.
