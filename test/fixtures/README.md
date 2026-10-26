# Test fixtures

`http.pcapng` — 29 frames of loopback traffic: two HTTP/1.0 requests to a local
`python3 -m http.server`, one for an ~80 KB text file (reassembled over several TCP segments)
and one for a missing file (404). The response body is random base64 text.

To regenerate a similar capture:

```bash
mkdir -p /tmp/www && head -c 60000 /dev/urandom | base64 > /tmp/www/big.txt
(cd /tmp/www && exec python3 -m http.server 18080 --bind 127.0.0.1) & server=$!
dumpcap -i lo -f "tcp port 18080" -a duration:3 -w http.pcapng & capture=$!
sleep 1; curl -s http://127.0.0.1:18080/big.txt >/dev/null; curl -s http://127.0.0.1:18080/nothere >/dev/null
wait $capture; kill $server
```

The tests assert exact frame numbers, so update them if you replace the fixture.
