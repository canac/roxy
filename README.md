# roxy

A scriptable man-in-the-middle HTTP(S) proxy, like mitmproxy, scripted in JavaScript with web-standard `Request` / `Response` APIs. It runs on Deno's crates (`deno_core`, `deno_web`, `deno_fetch`) in a single V8 isolate.

## Usage

```sh
cargo install --path .
roxy run script.js --port 8080        # or ROXY_PORT=8080 roxy run script.js
```

roxy always binds to `127.0.0.1`. Point a client at it as an HTTP proxy:

```sh
curl -x http://127.0.0.1:8080 https://example.com/
```

### Scripts

A script is an ES module that exports `onRequest` and/or `onResponse`. Both are optional.

```js
import rules from "./rules.json" with { type: "json" };
import banner from "./banner.txt" with { type: "text" };

export async function onRequest(req) {
  if (new URL(req.url).pathname === "/mock") {
    return Response.json({ mocked: true });  // answer without contacting upstream
  }
  req.headers.set("x-roxy", "1");            // in-place changes are kept
}

export async function onResponse(req, res) {
  if (res.headers.get("content-type")?.includes("text/html")) {
    const html = await res.text();           // decoded (gzip, br, ...) on read
    return new Response(banner + html, res);
  }
}
```

- Returning `undefined` passes the (possibly modified) message through.
- `onRequest` may return a `Request` to replace the request, or a `Response` to reply directly.
- `onResponse` may return a `Response`. Its `req` has the body that went upstream, but only if `onRequest` read or replaced it and it is at most 4 MiB.
- roxy keeps at most 4 MiB of what a hook reads. A hook that reads more of a body and then returns it unchanged (or throws) gets a 502, since roxy can no longer forward the original. Return a new `Request`/`Response` built from what you read instead.
- Bodies a hook never reads are streamed through untouched, still encoded.
- If `onResponse` changes the status or body, caching headers copied from `res.headers` are dropped and `Cache-Control: no-store` is added so the client doesn't cache the fake. Set your own `Cache-Control` to keep caching.
- If a hook throws or returns something invalid, roxy logs it and passes the original traffic through.
- WebSocket and other protocol upgrades pass through: `onRequest` sees the handshake, then roxy relays the raw bytes.
- Hooks run concurrently and can use `fetch()`, timers, streams, `URL`, `TextEncoder`, `Blob`, `FormData`, `console`, and more.

The script and everything it imports reload when they change on disk. A save that fails to load keeps the previous script running, and in-flight hooks finish on the old one.

### Options

| Flag | Env | Default |
| --- | --- | --- |
| `-p, --port` | `ROXY_PORT` | `8080` |
| `--auto-register` | | off (macOS, see below) |
| log filter | `ROXY_LOG` | `info` |

Metrics (requests, responses, time spent in hooks) are logged every minute while there is traffic, and once on shutdown. When stdout is a terminal, they show in a status line pinned to the bottom row, updated every second, instead.

### HTTPS

On first run roxy creates a CA in your per-user data directory and mints a certificate per intercepted host. HTTP/1.1 and HTTP/2 are negotiated with ALPN. Upstream certificates are always verified.

| OS | CA directory |
| --- | --- |
| macOS | `~/Library/Application Support/roxy` |
| Linux | `$XDG_DATA_HOME/roxy` or `~/.local/share/roxy` |
| Windows | `%APPDATA%\roxy` |

`roxy trust` adds the CA (`ca.pem` in that directory) to the trust store so clients accept roxy's certificates:

```sh
roxy trust
```

macOS only:

```sh
roxy register --port 8080           # set the system web + secure web proxy
roxy unregister                     # clear it
roxy run script.js --auto-register  # register on start, unregister on exit
```

Registering also adds `localhost`, `*.localhost`, `127.0.0.1` and `::1` to the proxy bypass list so local servers stay unproxied.

Only the first `--auto-register` instance sets the system proxy. Later ones log the `roxy register --port <port>` command to point it at themselves instead. On exit, an instance only clears system proxy settings that still point at its own port. `roxy unregister` always clears the system proxy, which also fixes things after a crash.

## Agent Skills

roxy ships a skill that teaches coding agents to write and run roxy scripts:

```sh
npx skills add canac/roxy
```

## Development

```sh
lefthook install   # pre-commit: fmt (auto-fixes), clippy, tests
cargo test
cargo clippy --all-targets
cargo fmt --check
```
