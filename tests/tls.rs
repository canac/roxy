#![allow(clippy::unwrap_used)]

mod common;

use common::{Alpn, Upstream, json, start, tls_upstream, upstream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const SCRIPT: &str = r#"
    export function onRequest(req) {
      req.headers.set("x-intercepted", new URL(req.url).protocol);
    }
    export function onResponse(_req, res) {
      res.headers.set("x-hooked", "1");
    }
"#;

#[tokio::test]
async fn intercepts_https_over_connect_with_http1() {
    let up = tls_upstream(common::Alpn::Both).await;
    let h = start(SCRIPT, &[&up], |_| {}).await;
    let client = h.client_builder().http1_only().build().unwrap();
    let res = client.get(up.url("/echo")).send().await.unwrap();
    assert_eq!(res.version(), http::Version::HTTP_11);
    assert_eq!(res.headers()["x-hooked"], "1");
    let echo = json(res).await;
    assert_eq!(echo["headers"]["x-intercepted"], "https:");
    assert_eq!(echo["path"], "/echo");
}

#[tokio::test]
async fn negotiates_http2_on_both_legs() {
    let up = tls_upstream(Alpn::H2Only).await;
    let h = start(SCRIPT, &[&up], |_| {}).await;
    let res = h
        .client()
        .post(up.url("/echo"))
        .body("h2 body")
        .send()
        .await
        .unwrap();
    assert_eq!(res.version(), http::Version::HTTP_2);
    assert_eq!(res.headers()["x-hooked"], "1");
    let echo = json(res).await;
    assert_eq!(echo["version"], "HTTP/2.0");
    assert_eq!(echo["body"], "h2 body");
}

#[tokio::test]
async fn http2_streams_are_multiplexed_through_hooks() {
    let up = tls_upstream(Alpn::Both).await;
    let script =
        "export async function onRequest() { await new Promise((r) => setTimeout(r, 200)); }";
    let h = start(script, &[&up], |_| {}).await;
    let client = h.client();
    let started = std::time::Instant::now();
    let tasks: Vec<_> = (0..6)
        .map(|_| {
            let (client, url) = (client.clone(), up.url("/echo"));
            tokio::spawn(async move { client.get(url).send().await.unwrap().version() })
        })
        .collect();
    for task in tasks {
        assert_eq!(task.await.unwrap(), http::Version::HTTP_2);
    }
    assert!(started.elapsed() < std::time::Duration::from_millis(1000));
}

#[tokio::test]
async fn rejects_untrusted_upstream_certificates() {
    let up = tls_upstream(Alpn::Both).await;
    let h = start(SCRIPT, &[], |_| {}).await;
    let res = h.client().get(up.url("/echo")).send().await.unwrap();
    assert_eq!(res.status(), 502);
    assert_eq!(up.hits(), 0);
}

#[tokio::test]
async fn hooks_can_fetch_https_with_verification() {
    let trusted = tls_upstream(Alpn::Both).await;
    let untrusted = tls_upstream(Alpn::Both).await;
    let plain = upstream().await;
    let script = format!(
        r#"
        export async function onRequest() {{
          const ok = await fetch("{ok}");
          let bad;
          try {{ await fetch("{bad}"); bad = "accepted"; }} catch (e) {{ bad = "rejected"; }}
          return new Response((await ok.json()).path, {{ headers: {{ "x-untrusted": bad }} }});
        }}
    "#,
        ok = trusted.url("/fetched"),
        bad = untrusted.url("/nope"),
    );
    let h = start(&script, &[&trusted], |_| {}).await;
    let res = h.client().get(plain.url("/")).send().await.unwrap();
    assert_eq!(res.headers()["x-untrusted"], "rejected");
    assert_eq!(res.text().await.unwrap(), "/fetched");
    assert_eq!(untrusted.hits(), 0);
}

#[tokio::test]
async fn plain_http_inside_connect_is_hooked() {
    let up = upstream().await;
    let h = start(SCRIPT, &[], |_| {}).await;
    let mut tunnel = tokio::net::TcpStream::connect(h.proxy.local_addr())
        .await
        .unwrap();
    let target = up.addr;
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\nGET /echo HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    );
    tokio::io::AsyncWriteExt::write_all(&mut tunnel, request.as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut tunnel, &mut out)
        .await
        .unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("x-hooked: 1"), "{out}");
    assert!(out.contains(r#""x-intercepted":"http:""#), "{out}");
}

async fn upgrade_echoes(up: &Upstream) {
    let h = start(SCRIPT, &[up], |_| {}).await;
    let client = h.client_builder().http1_only().build().unwrap();
    let res = client
        .get(up.url("/upgrade"))
        .header("connection", "upgrade")
        .header("upgrade", "echo")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 101);
    assert_eq!(res.headers()["upgrade"], "echo");
    let mut io = res.upgrade().await.unwrap();
    io.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    io.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
}

#[tokio::test]
async fn protocol_upgrades_pass_through_over_http() {
    upgrade_echoes(&upstream().await).await;
}

#[tokio::test]
async fn protocol_upgrades_pass_through_over_https() {
    upgrade_echoes(&tls_upstream(Alpn::Both).await).await;
}
