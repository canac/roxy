---
name: roxy
description: Use when debugging, logging, mocking, or rewriting HTTP(S) traffic with the roxy MITM proxy, such as inspecting URLs, editing request headers, or changing responses.
---

# roxy

roxy is a MITM proxy scripted with a JS module exporting `onRequest(req)` and/or `onResponse(req, res)`, using web-standard `Request`/`Response`. Full docs: https://github.com/canac/roxy#readme.

Write the script to the scratchpad and run it in the background. It hot reloads on save.

```sh
roxy run hooks.js --auto-register
```

Return nothing to pass through, a `Request` to replace the request, or a `Response` to reply without hitting upstream.

## Concurrent agents

`--auto-register` sets the system proxy, which all agents share. If other agents might run roxy too, let roxy pick a free port instead and proxy only your own client:

```sh
roxy run hooks.js --port 0   # logs "roxy listening on http://127.0.0.1:<port>"
```

- curl: `curl --proxy http://localhost:<port> https://example.com/`
- Most CLIs: set `HTTP_PROXY` and `HTTPS_PROXY` to `http://localhost:<port>`.
- node: also set `NODE_USE_ENV_PROXY=1` and `NODE_EXTRA_CA_CERTS` to roxy's CA:
  - macOS: `~/Library/Application Support/roxy/ca.pem`
  - Linux: `${XDG_DATA_HOME:-~/.local/share}/roxy/ca.pem`
  - Windows: `%APPDATA%\roxy\ca.pem`
- Chrome: a separate instance with its own `--user-data-dir` and `--proxy-server=http://localhost:<port>`.

## Examples

Log every URL:

```js
export function onRequest(req) {
  console.log(req.method, req.url);
}
```

Add a request header:

```js
export function onRequest(req) {
  req.headers.set("Authorization", "Bearer test-token");
}
```

Mock an endpoint:

```js
export function onRequest(req) {
  if (new URL(req.url).pathname === "/api/flags") {
    return Response.json({ newCheckout: true });
  }
}
```

Edit a JSON response:

```js
export async function onResponse(req, res) {
  if (!req.url.includes("/api/user")) return;
  const body = await res.json();
  body.role = "admin";
  return Response.json(body, { status: res.status });
}
```
