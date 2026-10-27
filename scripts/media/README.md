# README media

Scripts that regenerate `docs/demo.mp4`, `docs/demo.gif` and `docs/screenshot.png` from a real
WireBuddy server, real MCP calls and a real loopback capture. Not part of the build or the tests.

You need Node.js ≥ 22, Google Chrome (or Chromium; `screenshot.mjs` takes its path from
`CHROME`) and `ffmpeg`. Build first (`npm run build`).

```bash
# 1. a headless Chrome to drive
google-chrome --headless=new --remote-debugging-port=9350 --user-data-dir=/tmp/wb-chrome \
  --no-first-run --disable-gpu --hide-scrollbars --window-size=1600,900 about:blank &

# 2. record (~45 s; pings 127.0.0.1 and captures on lo during the live part)
CDP_PORT=9350 node scripts/media/record.mjs "$PWD" /tmp/wb-video

# 3. encode
ffmpeg -f concat -safe 0 -i /tmp/wb-video/frames.txt -vf "fps=30,format=yuv420p" \
  -c:v libx264 -crf 22 -preset slow -movflags +faststart docs/demo.mp4
ffmpeg -i docs/demo.mp4 -vf "fps=10,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" docs/demo.gif

# screenshot (same Chrome)
CDP_PORT=9350 node scripts/media/screenshot.mjs "$PWD" docs/screenshot.png
```

`stage.html` is the frame around the UI (scripted chat, captions, title and end cards).
The recorder runs the server with an empty `HOME`, keeps the UI hidden until a capture is
open, and pauses while the capture bar opens, so no recent-file history or network addresses
from the recording machine end up in the video. Check the result before publishing anyway.
