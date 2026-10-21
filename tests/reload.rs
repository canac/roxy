#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{eventually, start, try_start_with, upstream};

fn tagged(tag: &str) -> String {
    format!("export function onResponse(_req, res) {{ res.headers.set('x-tag', '{tag}'); }}\n")
}

async fn tag(client: &reqwest::Client, url: &str) -> String {
    let res = client.get(url).send().await.unwrap();
    res.headers()
        .get("x-tag")
        .map_or_else(String::new, |v| v.to_str().unwrap().to_owned())
}

const WAIT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn reloads_on_save_and_keeps_last_good_script() {
    let up = upstream().await;
    let h = start(&tagged("one"), &[], |_| {}).await;
    let (client, url) = (h.client(), up.url("/echo"));
    assert_eq!(tag(&client, &url).await, "one");

    h.write("script.js", &tagged("two"));
    assert!(eventually(WAIT, || async { tag(&client, &url).await == "two" }).await);

    for broken in [
        "export function (",
        "import './missing.js';",
        "throw new Error('x');",
    ] {
        h.write("script.js", broken);
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(tag(&client, &url).await, "two", "{broken}");
    }

    h.write("script.js", &tagged("three"));
    assert!(eventually(WAIT, || async { tag(&client, &url).await == "three" }).await);

    h.write("script.js", "export {};\n");
    assert!(eventually(WAIT, || async { tag(&client, &url).await.is_empty() }).await);
}

#[tokio::test]
async fn reloads_when_an_import_changes() {
    let up = upstream().await;
    let script = r#"
        import tag from "./tag.txt" with { type: "text" };
        export function onResponse(_req, res) { res.headers.set("x-tag", tag.trim()); }
    "#;
    let h = try_start_with(script, &[("tag.txt", "first")], &[], |_| {})
        .await
        .unwrap();
    let (client, url) = (h.client(), up.url("/echo"));
    assert_eq!(tag(&client, &url).await, "first");
    h.write("tag.txt", "second");
    assert!(eventually(WAIT, || async { tag(&client, &url).await == "second" }).await);
}

#[tokio::test]
async fn fixing_a_missing_import_triggers_reload() {
    let up = upstream().await;
    let h = start(&tagged("before"), &[], |_| {}).await;
    let (client, url) = (h.client(), up.url("/echo"));
    h.write(
        "script.js",
        "import tag from './later.txt' with { type: 'text' };\nexport function onResponse(_req, res) { res.headers.set('x-tag', tag); }\n",
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(tag(&client, &url).await, "before");
    h.write("later.txt", "after");
    assert!(eventually(WAIT, || async { tag(&client, &url).await == "after" }).await);
}

#[tokio::test]
async fn in_flight_hooks_finish_on_the_old_script() {
    let up = upstream().await;
    let slow_old = r#"
        export async function onResponse(_req, res) {
          await new Promise((r) => setTimeout(r, 800));
          res.headers.set("x-tag", "old");
        }
    "#;
    let h = start(slow_old, &[], |_| {}).await;
    let (client, url) = (h.client(), up.url("/echo"));
    let in_flight = tokio::spawn({
        let (client, url) = (client.clone(), url.clone());
        async move { tag(&client, &url).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.write("script.js", &tagged("new"));
    assert!(eventually(WAIT, || async { tag(&client, &url).await == "new" }).await);
    assert_eq!(in_flight.await.unwrap(), "old");
}

#[tokio::test]
async fn stuck_hooks_are_abandoned_after_the_drain_timeout() {
    let up = upstream().await;
    let stuck = "export function onRequest() { return new Promise(() => {}); }\n";
    let h = start(stuck, &[], |c| c.drain_timeout = Duration::from_millis(300)).await;
    let (client, url) = (h.client(), up.url("/echo"));
    let hung = tokio::spawn({
        let (client, url) = (client.clone(), url.clone());
        async move { client.get(url).send().await.unwrap().status() }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.write("script.js", &tagged("fresh"));
    assert!(eventually(WAIT, || async { tag(&client, &url).await == "fresh" }).await);
    assert_eq!(
        tokio::time::timeout(WAIT, hung).await.unwrap().unwrap(),
        200
    );
}

#[tokio::test]
async fn top_level_sync_loops_time_out_and_keep_last_good_script() {
    let up = upstream().await;
    let h = start(&tagged("good"), &[], |c| {
        c.load_timeout = Duration::from_millis(300);
    })
    .await;
    let (client, url) = (h.client(), up.url("/echo"));
    h.write("script.js", "while (true) {}\n");
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert_eq!(tag(&client, &url).await, "good");

    h.write("script.js", &tagged("fixed"));
    assert!(eventually(WAIT, || async { tag(&client, &url).await == "fixed" }).await);
}
