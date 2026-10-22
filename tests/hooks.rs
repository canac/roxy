#![allow(clippy::unwrap_used)]

mod common;

use std::time::{Duration, Instant};

use common::{COOKIES, GZIP_TEXT, gzip, json, start, try_start, try_start_with, upstream};
use roxy::body::RETAIN_LIMIT;

#[tokio::test]
async fn no_hooks_pass_traffic_through() {
    let up = upstream().await;
    let h = start("export const unrelated = 1;\n", &[], |_| {}).await;
    let res = h
        .client()
        .post(up.url("/echo?q=1"))
        .body("hi")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let echo = json(res).await;
    assert_eq!(echo["method"], "POST");
    assert_eq!(echo["path"], "/echo?q=1");
    assert_eq!(echo["body"], "hi");
}

#[tokio::test]
async fn hooks_returning_undefined_keep_in_place_changes() {
    let up = upstream().await;
    let script = r#"
        export function onRequest(req) {
          req.headers.set("x-added", "req");
          req.headers.delete("x-remove-me");
        }
        export function onResponse(req, res) {
          res.headers.set("x-seen-method", req.method);
          res.headers.set("x-seen-url", new URL(req.url).pathname);
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let res = h
        .client()
        .get(up.url("/echo"))
        .header("x-remove-me", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.headers()["x-seen-method"], "GET");
    assert_eq!(res.headers()["x-seen-url"], "/echo");
    assert_eq!(res.headers()["x-upstream"], "1");
    let echo = json(res).await;
    assert_eq!(echo["headers"]["x-added"], "req");
    assert!(echo["headers"].get("x-remove-me").is_none());
}

#[tokio::test]
async fn on_request_can_replace_the_request() {
    let up = upstream().await;
    let script = r#"
        export async function onRequest(req) {
          const body = (await req.text()).toUpperCase();
          return new Request(req.url.replace("/old", "/new"), {
            method: "PUT",
            headers: { "x-replaced": "yes" },
            body,
          });
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let res = h
        .client()
        .post(up.url("/old"))
        .body("shout")
        .send()
        .await
        .unwrap();
    let echo = json(res).await;
    assert_eq!(echo["method"], "PUT");
    assert_eq!(echo["path"], "/new");
    assert_eq!(echo["headers"]["x-replaced"], "yes");
    assert_eq!(echo["body"], "SHOUT");
}

#[tokio::test]
async fn on_request_can_answer_without_upstream() {
    let up = upstream().await;
    let script = r#"
        export function onRequest(req) {
          if (new URL(req.url).pathname === "/mock") {
            return new Response("mocked", { status: 418, headers: { "x-mock": "1" } });
          }
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let res = h.client().get(up.url("/mock")).send().await.unwrap();
    assert_eq!(res.status(), 418);
    assert_eq!(res.headers()["x-mock"], "1");
    assert_eq!(res.text().await.unwrap(), "mocked");
    assert_eq!(up.hits(), 0);
}

#[tokio::test]
async fn on_response_can_replace_the_response() {
    let up = upstream().await;
    let script = r"
        export async function onResponse(_req, res) {
          const echo = await res.json();
          return Response.json({ wrapped: echo.path }, { status: 201 });
        }
    ";
    let h = start(script, &[], |_| {}).await;
    let res = h.client().get(up.url("/echo")).send().await.unwrap();
    assert_eq!(res.status(), 201);
    assert_eq!(json(res).await["wrapped"], "/echo");
}

#[tokio::test]
async fn on_response_sees_request_body_only_if_on_request_read_it() {
    let up = upstream().await;
    let script = r#"
        export async function onRequest(req) {
          if (req.headers.has("x-read")) await req.text();
        }
        export async function onResponse(req, res) {
          res.headers.set("x-req-body", req.body === null ? "<none>" : await req.text());
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();
    let read = client
        .post(up.url("/echo"))
        .header("x-read", "1")
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(read.headers()["x-req-body"], "payload");
    assert_eq!(json(read).await["body"], "payload");

    let unread = client
        .post(up.url("/echo"))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(unread.headers()["x-req-body"], "<none>");
    assert_eq!(json(unread).await["body"], "payload");
}

#[tokio::test]
async fn on_response_sees_the_replaced_request_body() {
    let up = upstream().await;
    let script = r#"
        export async function onRequest(req) {
          const mode = req.headers.get("x-mode");
          if (mode === "string") {
            return new Request(req.url, { method: "POST", body: "replaced" });
          }
          if (mode === "stream") {
            const body = new Blob(["str", "eamed"]).stream();
            return new Request(req.url, { method: "POST", body, duplex: "half" });
          }
          if (mode === "empty") {
            await req.text();
            return new Request(req.url, { method: "POST" });
          }
        }
        export async function onResponse(req, res) {
          res.headers.set("x-req-body", req.body === null ? "<none>" : await req.text());
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();
    for (mode, expected) in [
        ("string", "replaced"),
        ("stream", "streamed"),
        ("empty", "<none>"),
    ] {
        let res = client
            .post(up.url("/echo"))
            .header("x-mode", mode)
            .body("original")
            .send()
            .await
            .unwrap();
        assert_eq!(res.headers()["x-req-body"], expected, "{mode}");
        let sent = if expected == "<none>" { "" } else { expected };
        assert_eq!(json(res).await["body"], sent, "{mode}");
    }
}

#[tokio::test]
async fn unread_bodies_stay_encoded_and_read_bodies_are_decoded() {
    let up = upstream().await;
    let script = r#"
        export async function onResponse(req, res) {
          if (req.headers.has("x-read")) {
            const text = await res.text();
            res.headers.set("x-hook-saw", text);
          }
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();

    let raw = client.get(up.url("/gzip")).send().await.unwrap();
    assert_eq!(raw.headers()["content-encoding"], "gzip");
    let bytes = raw.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), gzip(GZIP_TEXT.as_bytes()).as_slice());

    let read = client
        .get(up.url("/gzip"))
        .header("x-read", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(read.headers()["x-hook-saw"], GZIP_TEXT);
    assert!(read.headers().get("content-encoding").is_none());
    assert_eq!(read.text().await.unwrap(), GZIP_TEXT);
}

#[tokio::test]
async fn ignored_response_body_streams_without_buffering() {
    let up = upstream().await;
    let h = start(
        "export function onResponse(_req, res) { res.headers.set('x-hooked', '1'); }",
        &[],
        |_| {},
    )
    .await;
    let mut res = h.client().get(up.url("/stall")).send().await.unwrap();
    assert_eq!(res.headers()["x-hooked"], "1");
    // The upstream withholds the rest until released, so a buffering proxy would hang here.
    let first = tokio::time::timeout(Duration::from_secs(5), res.chunk()).await;
    assert_eq!(first.unwrap().unwrap().unwrap().as_ref(), b"first");
    up.release.notify_one();
    assert_eq!(res.chunk().await.unwrap().unwrap().as_ref(), b"rest");
}

#[tokio::test]
async fn ignored_request_body_streams_without_buffering() {
    let up = upstream().await;
    let h = start(
        "export function onRequest(req) { req.headers.set('x-hooked', '1'); }",
        &[],
        |_| {},
    )
    .await;
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(1);
    let stream =
        futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|c| (c, rx)) });
    tx.send(Ok(bytes::Bytes::from_static(b"early")))
        .await
        .unwrap();
    let send = h
        .client()
        .post(up.url("/first-chunk"))
        .body(reqwest::Body::wrap_stream(stream))
        .send();
    // The client never finishes its body, so only a streaming proxy lets the reply through.
    let res = tokio::time::timeout(Duration::from_secs(5), send)
        .await
        .unwrap()
        .unwrap();
    let mut res = res;
    let chunk = tokio::time::timeout(Duration::from_secs(5), res.chunk()).await;
    assert_eq!(chunk.unwrap().unwrap().unwrap().as_ref(), b"early");
    drop(tx);
}

#[tokio::test]
async fn large_ignored_body_passes_through_intact() {
    let up = upstream().await;
    let h = start(
        "export function onResponse() {}\nexport function onRequest() {}",
        &[],
        |_| {},
    )
    .await;
    let n: u64 = 64 * 1024 * 1024 + 7;
    let mut res = h
        .client()
        .get(up.url(&format!("/big?n={n}")))
        .send()
        .await
        .unwrap();
    let mut total = 0u64;
    while let Some(chunk) = res.chunk().await.unwrap() {
        total += chunk.len() as u64;
    }
    assert_eq!(total, n);
}

#[tokio::test]
async fn failing_hooks_fail_open() {
    let up = upstream().await;
    let script = r#"
        export function onRequest(req) {
          const mode = req.headers.get("x-mode");
          req.headers.set("x-mutated", "1");
          if (mode === "throw") throw new Error("boom");
          if (mode === "number") return 42;
          if (mode === "bad-status") return Response.error();
        }
        export async function onResponse(req, res) {
          if (req.headers.get("x-mode") === "read-then-throw") {
            await res.text();
            throw new Error("late boom");
          }
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();
    for mode in ["throw", "number"] {
        let res = client
            .get(up.url("/echo"))
            .header("x-mode", mode)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "{mode}");
        let echo = json(res).await;
        assert!(
            echo["headers"].get("x-mutated").is_none(),
            "{mode} must send the original"
        );
    }
    let res = client
        .get(up.url("/echo"))
        .header("x-mode", "bad-status")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);

    let res = client
        .get(up.url("/gzip"))
        .header("x-mode", "read-then-throw")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), GZIP_TEXT);
}

#[tokio::test]
async fn hooks_run_in_parallel_and_errors_are_isolated() {
    let up = upstream().await;
    let script = r#"
        export async function onRequest(req) {
          if (req.headers.has("x-throw")) throw new Error("isolated");
          await new Promise((r) => setTimeout(r, 300));
          req.headers.set("x-slept", "1");
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();
    let started = Instant::now();
    let slow = (0..8).map(|_| {
        let client = client.clone();
        let url = up.url("/echo");
        tokio::spawn(async move { json(client.get(url).send().await.unwrap()).await })
    });
    let slow: Vec<_> = slow.collect();
    let failing = client
        .get(up.url("/echo"))
        .header("x-throw", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(failing.status(), 200);
    for task in slow {
        assert_eq!(task.await.unwrap()["headers"]["x-slept"], "1");
    }
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn metrics_count_traffic_and_hook_time_only() {
    let up = upstream().await;
    let script = r#"
        export async function onRequest(req) {
          if (req.headers.has("x-sleep")) await new Promise((r) => setTimeout(r, 200));
        }
        export function onResponse() {}
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();
    let res = client.get(up.url("/slow?ms=400")).send().await.unwrap();
    assert_eq!(res.text().await.unwrap(), "slow");
    let after_slow_upstream = h.proxy.metrics();
    assert_eq!(after_slow_upstream.requests, 1);
    assert_eq!(after_slow_upstream.responses, 1);
    assert!(
        after_slow_upstream.overhead < Duration::from_millis(200),
        "{after_slow_upstream}"
    );

    client
        .get(up.url("/echo"))
        .header("x-sleep", "1")
        .send()
        .await
        .unwrap();
    let after_slow_hook = h.proxy.shutdown().await;
    assert_eq!(after_slow_hook.requests, 2);
    assert_eq!(after_slow_hook.responses, 2);
    assert!(
        after_slow_hook.overhead >= Duration::from_millis(200),
        "{after_slow_hook}"
    );
}

#[tokio::test]
async fn upstream_failures_become_502() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let h = start("export function onRequest() {}", &[], |_| {}).await;
    let res = h
        .client()
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
}

#[tokio::test]
async fn hooks_can_fetch() {
    let up = upstream().await;
    let script = format!(
        r#"
        export async function onRequest(req) {{
          if (new URL(req.url).pathname !== "/via-fetch") return;
          const r = await fetch("{}", {{ method: "POST", body: "from-hook" }});
          const echo = await r.json();
          return new Response(echo.body, {{ headers: {{ "x-fetched": String(r.status) }} }});
        }}
    "#,
        up.url("/echo")
    );
    let h = start(&script, &[], |_| {}).await;
    let res = h.client().get(up.url("/via-fetch")).send().await.unwrap();
    assert_eq!(res.headers()["x-fetched"], "200");
    assert_eq!(res.text().await.unwrap(), "from-hook");
}

#[tokio::test]
async fn scripts_import_text_and_json_with_attributes() {
    let up = upstream().await;
    let script = r#"
        import { name } from "./lib/helper.js";
        import greeting from "./lib/greeting.txt" with { type: "text" };
        export function onResponse(_req, res) {
          res.headers.set("x-json", name);
          res.headers.set("x-text", greeting);
        }
    "#;
    let files = [
        ("lib/config.json", r#"{"name":"json-value"}"#),
        ("lib/greeting.txt", "text-value"),
        (
            "lib/helper.js",
            r#"import config from "./config.json" with { type: "json" };
               export const name = config.name;"#,
        ),
    ];
    let h = try_start_with(script, &files, &[], |_| {}).await.unwrap();
    let res = h.client().get(up.url("/echo")).send().await.unwrap();
    assert_eq!(res.headers()["x-json"], "json-value");
    assert_eq!(res.headers()["x-text"], "text-value");
}

#[tokio::test]
async fn bad_scripts_fail_to_start() {
    for script in [
        r#"import "./missing.js";"#,
        r#"import data from "./data.json";"#,
        "export const onRequest = 5;",
        "throw new Error('load-time');",
        "this is not javascript",
    ] {
        assert!(try_start(script, &[], |_| {}).await.is_err(), "{script}");
    }
}

#[tokio::test]
async fn top_level_sync_loop_fails_to_start_after_load_timeout() {
    let started = Instant::now();
    let result = try_start("while (true) {}", &[], |c| {
        c.load_timeout = Duration::from_millis(300);
    })
    .await;
    let error = format!("{:#}", result.err().unwrap());
    assert!(error.contains("did not finish loading"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn web_apis_are_available() {
    let up = upstream().await;
    let script = r#"
        export async function onRequest(req) {
          const checks = [
            new URL("https://a.test/x?y=1").searchParams.get("y") === "1",
            new TextDecoder().decode(new TextEncoder().encode("ok")) === "ok",
            atob(btoa("b64")) === "b64",
            await new Blob(["blob"]).text() === "blob",
            new File(["f"], "f.txt").name === "f.txt",
            new FormData() instanceof FormData,
            new AbortController().signal.aborted === false,
            typeof structuredClone({}) === "object",
            new Event("x").type === "x",
            typeof ReadableStream === "function",
            typeof console.log === "function",
          ];
          return new Response(checks.map(String).join(","));
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let body = h
        .client()
        .get(up.url("/"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.split(',').all(|c| c == "true"), "{body}");
}

#[tokio::test]
async fn responses_can_be_rebuilt_from_the_original() {
    let up = upstream().await;
    let script = r#"
        export async function onResponse(_req, res) {
          const text = await res.text();
          return new Response("prefix:" + text, res);
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let res = h.client().get(up.url("/gzip")).send().await.unwrap();
    assert_eq!(res.headers()["content-type"], "text/plain");
    assert!(res.headers().get("content-encoding").is_none());
    assert_eq!(res.text().await.unwrap(), format!("prefix:{GZIP_TEXT}"));
}

#[tokio::test]
async fn script_built_bodies_get_exact_content_length() {
    let up = upstream().await;
    let script = r#"
        export function onRequest(req) {
          const path = new URL(req.url).pathname;
          if (path === "/short") return new Response("short!");
          if (path === "/echo") return new Request(req.url, { method: "POST", body: "héllo" });
        }
        export async function onResponse(req, res) {
          if (req.method === "HEAD") return new Response("abc");
          if (new URL(req.url).pathname === "/gzip") {
            return new Response("prefix:" + (await res.text()), res);
          }
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();

    let res = client.get(up.url("/short")).send().await.unwrap();
    assert_eq!(res.headers()["content-length"], "6");
    assert!(res.headers().get("transfer-encoding").is_none());

    let echo = json(client.get(up.url("/echo")).send().await.unwrap()).await;
    assert_eq!(echo["headers"]["content-length"], "6");
    assert!(echo["headers"].get("transfer-encoding").is_none());

    let res = client.get(up.url("/gzip")).send().await.unwrap();
    let expected = format!("prefix:{GZIP_TEXT}");
    assert_eq!(
        res.headers()["content-length"],
        expected.len().to_string().as_str()
    );
    assert_eq!(res.text().await.unwrap(), expected);

    let res = client.head(up.url("/other")).send().await.unwrap();
    assert!(res.headers().get("content-length").is_none());
}

#[tokio::test]
async fn fully_read_bodies_get_content_length_of_what_was_read() {
    let up = upstream().await;
    let script = r"
        export async function onRequest(req) { await req.text(); }
        export async function onResponse(_req, res) { await res.text(); }
    ";
    let h = start(script, &[], |_| {}).await;
    let client = h.client();

    let res = client
        .post(up.url("/echo"))
        .body("payload")
        .send()
        .await
        .unwrap();
    let length: usize = res.headers()["content-length"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let body = res.text().await.unwrap();
    assert_eq!(length, body.len());
    let echo: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(echo["headers"]["content-length"], "7");
    assert!(echo["headers"].get("transfer-encoding").is_none());

    let res = client.get(up.url("/gzip")).send().await.unwrap();
    assert!(res.headers().get("content-encoding").is_none());
    assert_eq!(
        res.headers()["content-length"],
        GZIP_TEXT.len().to_string().as_str()
    );
    assert_eq!(res.text().await.unwrap(), GZIP_TEXT);
}

#[tokio::test]
async fn unreadable_body_after_a_failed_read_is_a_502() {
    let up = upstream().await;
    let script = r#"
        export async function onResponse(req, res) {
          if (req.headers.has("x-read")) await res.text();
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();
    let res = client
        .get(up.url("/bad-gzip"))
        .header("x-read", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);

    let res = client.get(up.url("/bad-gzip")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-encoding"], "gzip");
    assert_eq!(res.text().await.unwrap(), "this is not gzip");
}

#[tokio::test]
async fn bodyless_304_has_no_content_length() {
    let up = upstream().await;
    let script = "export function onResponse() { return new Response(null, { status: 304 }); }";
    let h = start(script, &[], |_| {}).await;
    let res = h.client().get(up.url("/echo")).send().await.unwrap();
    assert_eq!(res.status(), 304);
    assert!(res.headers().get("content-length").is_none());
    assert!(res.headers().get("transfer-encoding").is_none());
    assert!(res.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn on_response_returning_a_request_fails_open() {
    let up = upstream().await;
    let script = r#"
        export function onResponse(_req, res) {
          res.headers.set("x-mutated", "1");
          return new Request("http://x.test/");
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let res = h.client().get(up.url("/echo")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["x-upstream"], "1");
    assert!(res.headers().get("x-mutated").is_none());
    assert_eq!(json(res).await["path"], "/echo");
}

#[tokio::test]
async fn set_cookie_headers_with_commas_stay_separate() {
    let up = upstream().await;
    let script = r#"
        export function onRequest(req) {
          if (new URL(req.url).pathname === "/mock") {
            const headers = new Headers();
            headers.append("set-cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/");
            headers.append("set-cookie", "b=2; Expires=Thu, 22 Oct 2026 07:28:00 GMT");
            return new Response("mocked", { headers });
          }
        }
        export function onResponse(_req, res) { res.headers.set("x-hooked", "1"); }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();
    for path in ["/cookies", "/mock"] {
        let res = client.get(up.url(path)).send().await.unwrap();
        let cookies: Vec<_> = res
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        assert_eq!(cookies, COOKIES, "{path}");
    }
}

fn pattern(len: usize) -> String {
    (0..len)
        .map(|i| char::from(b'a' + u8::try_from(i % 26).unwrap()))
        .collect()
}

#[tokio::test]
async fn built_request_bodies_past_the_retain_limit_forward_intact() {
    let up = upstream().await;
    let script = r#"
        export function onRequest(req) { return new Request(req); }
        export async function onResponse(req, res) {
          const seen = req.body === null ? "<none>" : (await req.arrayBuffer()).byteLength;
          res.headers.set("x-req-body", String(seen));
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let client = h.client();
    for (len, seen) in [(7, "7"), (2 * RETAIN_LIMIT + 7, "<none>")] {
        let sent = pattern(len);
        let res = client
            .post(up.url("/echo"))
            .body(sent.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(res.headers()["x-req-body"], seen, "{len}");
        assert!(json(res).await["body"] == sent.as_str(), "{len}");
    }
}

#[tokio::test]
async fn bodies_streamed_through_the_script_past_the_retain_limit_forward_intact() {
    let up = upstream().await;
    let script = r"
        export function onResponse(_req, res) {
          return new Response(res.body.pipeThrough(new TransformStream()), res);
        }
    ";
    let h = start(script, &[], |_| {}).await;
    let n = 3 * RETAIN_LIMIT + 7;
    let mut res = h
        .client()
        .get(up.url(&format!("/big?n={n}")))
        .send()
        .await
        .unwrap();
    let mut total = 0;
    while let Some(chunk) = res.chunk().await.unwrap() {
        assert!(chunk.iter().all(|b| *b == b'x'));
        total += chunk.len();
    }
    assert_eq!(total, n);
}

#[tokio::test]
async fn forwarding_a_body_read_past_the_retain_limit_is_a_502() {
    let up = upstream().await;
    let script = format!(
        r"
        export async function onRequest(req) {{ await req.arrayBuffer(); }}
        export async function onResponse(_req, res) {{
          const reader = res.body.getReader();
          let n = 0;
          while (n <= {RETAIN_LIMIT}) n += (await reader.read()).value.byteLength;
          reader.releaseLock();
        }}
    "
    );
    let h = start(&script, &[], |_| {}).await;
    let client = h.client();
    let res = client
        .post(up.url("/echo"))
        .body(pattern(RETAIN_LIMIT + 1))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert!(
        res.text()
            .await
            .unwrap()
            .contains("onRequest read over 4 MiB")
    );
    assert_eq!(up.hits(), 0);

    let n = 2 * RETAIN_LIMIT;
    let res = client
        .get(up.url(&format!("/big?n={n}")))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert!(
        res.text()
            .await
            .unwrap()
            .contains("onResponse read over 4 MiB")
    );
}

#[tokio::test]
async fn unchanged_urls_are_forwarded_verbatim() {
    let up = upstream().await;
    let script = r#"
        export function onRequest(req) {
          if (req.headers.has("x-replace")) return new Request(req.url + "&added", req);
          req.headers.set("x-hooked", "1");
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let path = "/echo/a%2Fb/../c?q=a%20b&x=%7e&y='";
    for (extra, expected) in [("", path.to_owned()), ("x-replace: 1\r\n", String::new())] {
        let mut conn = tokio::net::TcpStream::connect(h.proxy.local_addr())
            .await
            .unwrap();
        let request = format!(
            "GET http://{addr}{path} HTTP/1.1\r\nHost: {addr}\r\n{extra}Connection: close\r\n\r\n",
            addr = up.addr,
        );
        tokio::io::AsyncWriteExt::write_all(&mut conn, request.as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut conn, &mut out)
            .await
            .unwrap();
        let body = out.split_once("\r\n\r\n").unwrap().1;
        let echo: serde_json::Value = serde_json::from_str(body).unwrap();
        if expected.is_empty() {
            assert_eq!(echo["path"], "/echo/c?q=a%20b&x=%7e&y=%27&added");
        } else {
            assert_eq!(echo["path"], expected.as_str());
        }
    }
}

#[tokio::test]
async fn partial_encoded_responses_are_read_raw() {
    let up = upstream().await;
    let script = r#"
        export async function onResponse(req, res) {
          res.headers.set("x-read", String((await res.arrayBuffer()).byteLength));
        }
    "#;
    let h = start(script, &[], |_| {}).await;
    let res = h
        .client()
        .get(up.url("/partial-gzip"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 206);
    assert_eq!(res.headers()["x-read"], "8");
    assert_eq!(res.headers()["content-encoding"], "gzip");
    let expected = &gzip(GZIP_TEXT.as_bytes())[2..10];
    assert_eq!(res.bytes().await.unwrap().as_ref(), expected);
}

#[tokio::test]
async fn split_cookie_headers_are_joined_with_semicolons() {
    let up = upstream().await;
    for script in ["export {};", "export function onRequest() {}"] {
        let h = start(script, &[], |_| {}).await;
        let mut conn = tokio::net::TcpStream::connect(h.proxy.local_addr())
            .await
            .unwrap();
        let request = format!(
            "GET http://{addr}/echo HTTP/1.1\r\nHost: {addr}\r\nCookie: sid=abc\r\nCookie: csrf=xyz\r\nConnection: close\r\n\r\n",
            addr = up.addr,
        );
        tokio::io::AsyncWriteExt::write_all(&mut conn, request.as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut conn, &mut out)
            .await
            .unwrap();
        let body = out.split_once("\r\n\r\n").unwrap().1;
        let echo: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(echo["headers"]["cookie"], "sid=abc; csrf=xyz", "{script}");
    }
}

#[tokio::test]
async fn header_order_survives_hooks() {
    let up = upstream().await;
    let script = r#"export function onRequest(req) { req.headers.set("x-added", "1"); }"#;
    let h = start(script, &[], |_| {}).await;
    let mut conn = tokio::net::TcpStream::connect(h.proxy.local_addr())
        .await
        .unwrap();
    let request = format!(
        "GET http://{addr}/order HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: ua\r\nProxy-Connection: keep-alive\r\nZebra: 1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        addr = up.addr,
    );
    tokio::io::AsyncWriteExt::write_all(&mut conn, request.as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut conn, &mut out)
        .await
        .unwrap();
    let body = out.split_once("\r\n\r\n").unwrap().1;
    assert_eq!(body, "user-agent,zebra,accept,x-added,host");
}

#[tokio::test]
async fn repeated_response_headers_stay_separate_through_hooks() {
    let up = upstream().await;
    let script = r#"export function onResponse(req, res) { res.headers.set("x-seen", "1"); }"#;
    let h = start(script, &[], |_| {}).await;
    let res = h.client().get(up.url("/links")).send().await.unwrap();
    let links: Vec<_> = res.headers().get_all("link").iter().collect();
    assert_eq!(links, ["</a.css>; rel=preload", "</b.js>; rel=preload"]);
    assert_eq!(res.headers()["x-seen"], "1");
}
