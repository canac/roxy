#![allow(clippy::unwrap_used)]

// Alone in its own binary because the isolate count is process-wide.

mod common;

use std::time::Duration;

use common::{eventually, start, upstream};

#[tokio::test]
async fn reload_terminates_hooks_stuck_in_sync_loops() {
    let up = upstream().await;
    let spin =
        "export function onRequest(req) { if (req.headers.has('x-spin')) while (true) {} }\n";
    let h = start(spin, &[], |c| {
        c.watch = false;
        c.drain_timeout = Duration::from_millis(300);
    })
    .await;
    let client = h.client();
    assert_eq!(roxy::engine::live_isolates(), 1);
    let hung = tokio::spawn({
        let (client, url) = (client.clone(), up.url("/echo"));
        async move {
            client
                .get(url)
                .header("x-spin", "1")
                .send()
                .await
                .unwrap()
                .status()
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.write("script.js", "export function onRequest() {}\n");
    h.proxy.reload();
    assert!(
        eventually(Duration::from_secs(10), || async {
            roxy::engine::live_isolates() == 1
        })
        .await
    );
    assert_eq!(hung.await.unwrap(), 200);
    assert_eq!(
        client.get(up.url("/echo")).send().await.unwrap().status(),
        200
    );
}
