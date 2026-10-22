#![allow(clippy::unwrap_used)]

mod common;

use std::process::{Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_roxy");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn run_requires_a_script() {
    let out = Command::new(BIN).arg("run").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("<SCRIPT>"));
}

#[test]
fn help_lists_every_subcommand() {
    let out = Command::new(BIN).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    for cmd in ["run", "trust", "register", "unregister"] {
        assert!(help.contains(cmd), "{help}");
    }
}

#[tokio::test]
async fn runs_on_port_from_env_and_logs_metrics_on_shutdown() {
    let up = common::upstream().await;
    let home = tempfile::tempdir().unwrap();
    let script = home.path().join("hook.js");
    std::fs::write(
        &script,
        "export function onResponse(_req, r) { console.log('seen', { n: 1 }); r.headers.set('x-cli', '1'); }",
    )
    .unwrap();
    let port = free_port();
    let child = Command::new(BIN)
        .args(["run", script.to_str().unwrap()])
        .env("ROXY_PORT", port.to_string())
        .env("HOME", home.path())
        .env("ROXY_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{port}")).unwrap())
        .build()
        .unwrap();
    let url = up.url("/echo");
    let ok = common::eventually(Duration::from_secs(10), || async {
        client
            .get(&url)
            .send()
            .await
            .is_ok_and(|r| r.headers().contains_key("x-cli"))
    })
    .await;
    assert!(ok);
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let logs = String::from_utf8_lossy(&out.stdout);
    assert!(logs.contains("final metrics: requests="), "{logs}");
    assert!(logs.contains("seen { n: 1 }"), "{logs}");
    if cfg!(target_os = "macos") {
        assert!(
            home.path()
                .join("Library/Application Support/roxy/ca.pem")
                .exists()
        );
    }
}

#[tokio::test]
async fn raises_a_low_open_file_limit() {
    let home = tempfile::tempdir().unwrap();
    let script = home.path().join("hook.js");
    std::fs::write(&script, "export {};").unwrap();
    let port = free_port();
    let child = Command::new("sh")
        .args(["-c", r#"ulimit -Sn 256 && exec "$0" run "$1""#, BIN])
        .arg(&script)
        .env("ROXY_PORT", port.to_string())
        .env("HOME", home.path())
        .env("ROXY_LOG", "roxy=debug")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let up = common::eventually(Duration::from_secs(10), || async {
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
    })
    .await;
    assert!(up);
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let logs = String::from_utf8_lossy(&out.stdout);
    let limit: u64 = logs
        .split("open file limit is ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.trim_matches(|c: char| !c.is_ascii_digit()).parse().ok())
        .unwrap_or_else(|| panic!("{logs}"));
    assert!(limit > 256, "{logs}");
}
