# README media

Scripts that regenerate `docs/demo.mp4`, `docs/demo.gif` and `docs/screenshot.png` from a real
WireBuddy server, real MCP calls and real loopback captures. Not part of the build or the tests.

The demo is the robot-arm investigation of `examples/investigations/robot-arm`: the agent captures
the stuttering app's traffic, writes the dissector (the example's `solution/armc`), finds the
40 ms per command, opens the trajectory panel, applies `solution/fix.diff` to a copy of the app and
captures again. The chat is scripted; every tool call and its result is real.

You need Node.js ≥ 22, Google Chrome (or Chromium; `screenshot.mjs` takes its path from
`CHROME`), `ffmpeg`, `dumpcap` allowed to capture on `lo`, and ports 7700 and 7701 free for the
emulated arm controller. Build first (`npm run build`).

```bash
# 1. a headless Chrome to drive
google-chrome --headless=new --remote-debugging-port=9350 --user-data-dir=/tmp/wb-chrome \
  --no-first-run --disable-gpu --hide-scrollbars --window-size=1600,900 about:blank &

# 2. record (~50 s; runs the arm controller and the app, captures on lo twice)
CDP_PORT=9350 node scripts/media/record.mjs "$PWD" /tmp/wb-video

# 3. encode
ffmpeg -f concat -safe 0 -i /tmp/wb-video/frames.txt -vf "fps=30,format=yuv420p" \
  -c:v libx264 -crf 22 -preset slow -movflags +faststart docs/demo.mp4
ffmpeg -i docs/demo.mp4 -vf "fps=10,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" docs/demo.gif

# screenshot (same Chrome)
CDP_PORT=9350 node scripts/media/screenshot.mjs "$PWD" docs/screenshot.png
```

To follow the story in a browser of your own instead, run `WATCH=1 node scripts/media/record.mjs
"$PWD" /tmp/wb-watch`: it prints the viewer's URL and waits for `kill -USR1 <pid>` before each
step.

`stage.html` is the frame around the UI (scripted chat, captions, title and end cards). The
recorder runs the server with an empty `HOME`, so no recent-file history appears. WireBuddy's
start page lists the machine's interfaces with their addresses: the recorder shows the UI only
once a capture is on screen, and fails instead of writing `frames.txt` if the start page was ever
visible while recording. Check the result before publishing anyway.
