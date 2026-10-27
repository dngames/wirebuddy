# Example extensions

Panels to copy and adapt, each written against the `wb` API that the panel guide describes
(`extensions` action `"guide"`, topic `"panel"`).

| Folder | Shows | Lua |
|---|---|---|
| `http-gallery` | Images sent over HTTP as thumbnails, other files in a list, full size with frame, host, size and SHA-1 on a click | none |
| `rtp-video` | H.264 over RTP, depacketized in JavaScript (RFC 6184) and played with WebCodecs; a stream picker, play and seek | `rtp-h264.lua` decodes UDP port 5004 as RTP and payload type 96 as H.264, like Decode As |
| `lidar-wbpc` | A made-up lidar protocol, `wbpc`, as a point cloud in WebGL2: orbit, zoom, color by intensity, height or ring, scan stepping | `wbpc.lua` decodes UDP port 7502 |

To try one, copy its folder into `~/.local/share/wirebuddy/extensions/` (not writable by others),
make a capture for it and open the panel from View › Panels:

```bash
node test/media/http-gallery.mjs gallery.pcap
node test/media/rtp-h264.mjs rtp.pcap
node test/media/lidar-wbpc.mjs lidar.pcap
```

`npm run test:browser` opens each one on its capture in headless Chrome.
