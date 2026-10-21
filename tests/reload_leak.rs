#![allow(clippy::unwrap_used)]

// Alone in its own binary because the isolate count is process-wide.

mod common;

use std::time::Duration;

use common::{eventually, start, upstream};

#[tokio::test]
async fn reloads_do_not_accumulate_isolates() {
    let up = upstream().await;
    let h = start("export function onRequest() {}\n", &[], |c| c.watch = false).await;
    let client = h.client();
    assert_eq!(roxy::engine::live_isolates(), 1);
    for i in 0..20 {
        h.write(
            "script.js",
            &format!("const big = new Array(100000).fill({i});\nexport function onRequest(r) {{ r.headers.set('x-n', String(big[0])); }}\n"),
        );
        h.proxy.reload();
        let url = up.url("/echo");
        let expected = i.to_string();
        assert!(
            eventually(Duration::from_secs(10), || async {
                let echo = common::json(client.get(&url).send().await.unwrap()).await;
                echo["headers"]["x-n"] == expected.as_str()
            })
            .await
        );
    }
    assert!(
        eventually(Duration::from_secs(10), || async {
            roxy::engine::live_isolates() == 1
        })
        .await
    );
}
