#![allow(clippy::unwrap_used, dead_code)]

use std::convert::Infallible;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use roxy::body::{self, Body};
use roxy::ca::CertificateAuthority;
use roxy::proxy::{Config, Proxy};
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use rustls::sign::SingleCertAndKey;
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

pub const GZIP_TEXT: &str = "hello from a gzip body";
pub const COOKIES: [&str; 2] = [
    "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/",
    "b=2; Expires=Thu, 22 Oct 2026 07:28:00 GMT",
];

/// Routes of the local upstream used by the integration tests.
pub struct Upstream {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
    pub release: Arc<Notify>,
    _ca_dir: TempDir,
    pub ca_der: Option<CertificateDer<'static>>,
}

impl Upstream {
    pub fn url(&self, path: &str) -> String {
        match self.ca_der {
            Some(_) => format!("https://localhost:{}{path}", self.addr.port()),
            None => format!("http://127.0.0.1:{}{path}", self.addr.port()),
        }
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Alpn {
    Both,
    H2Only,
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn query_num(req: &Request<Incoming>, key: &str) -> u64 {
    req.uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0)
}

#[allow(clippy::too_many_lines, reason = "one arm per test route")]
async fn route(mut req: Request<Incoming>, release: Arc<Notify>) -> Response<Body> {
    match req.uri().path() {
        "/upgrade" => {
            let upgrade = hyper::upgrade::on(&mut req);
            tokio::spawn(async move {
                let mut io = TokioIo::new(upgrade.await.unwrap());
                let (mut reader, mut writer) = tokio::io::split(&mut io);
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
            Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("connection", "upgrade")
                .header("upgrade", "echo")
                .body(body::empty())
                .unwrap()
        }
        "/gzip" => Response::builder()
            .header("content-encoding", "gzip")
            .header("content-type", "text/plain")
            .body(body::full(gzip(GZIP_TEXT.as_bytes())))
            .unwrap(),
        "/order" => {
            let names: Vec<&str> = req.headers().keys().map(http::HeaderName::as_str).collect();
            Response::new(body::full(names.join(",")))
        }
        "/links" => Response::builder()
            .header("link", "</a.css>; rel=preload")
            .header("link", "</b.js>; rel=preload")
            .body(body::full("links"))
            .unwrap(),
        "/partial-gzip" => {
            let encoded = gzip(GZIP_TEXT.as_bytes());
            Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header("content-encoding", "gzip")
                .header("content-range", format!("bytes 2-9/{}", encoded.len()))
                .body(body::full(encoded[2..10].to_vec()))
                .unwrap()
        }
        "/bad-gzip" => Response::builder()
            .header("content-encoding", "gzip")
            .body(body::full("this is not gzip"))
            .unwrap(),
        p if p.starts_with("/cached") => Response::builder()
            .header("cache-control", "max-age=3600")
            .header("etag", "\"v1\"")
            .header("last-modified", "Wed, 21 Oct 2015 07:28:00 GMT")
            .header("expires", "Thu, 01 Jan 2099 00:00:00 GMT")
            .header("age", "5")
            .body(body::full("cached"))
            .unwrap(),
        "/cookies" => Response::builder()
            .header("set-cookie", COOKIES[0])
            .header("set-cookie", COOKIES[1])
            .body(body::full("cookies"))
            .unwrap(),
        "/slow" => {
            tokio::time::sleep(Duration::from_millis(query_num(&req, "ms"))).await;
            Response::new(body::full("slow"))
        }
        "/big" => {
            let total = query_num(&req, "n");
            let chunk = Bytes::from(vec![b'x'; 64 * 1024]);
            let stream = futures::stream::unfold(0u64, move |sent| {
                let chunk = chunk.clone();
                async move {
                    (sent < total).then(|| {
                        let n = chunk.len().min(usize::try_from(total - sent).unwrap());
                        (Ok::<_, Infallible>(chunk.slice(..n)), sent + n as u64)
                    })
                }
            });
            Response::new(body::from_stream(stream))
        }
        "/stall" => {
            let stream = futures::stream::unfold(0, move |step| {
                let release = Arc::clone(&release);
                async move {
                    match step {
                        0 => Some((Ok::<_, Infallible>(Bytes::from_static(b"first")), 1)),
                        1 => {
                            release.notified().await;
                            Some((Ok(Bytes::from_static(b"rest")), 2))
                        }
                        _ => None,
                    }
                }
            });
            Response::new(body::from_stream(stream))
        }
        "/first-chunk" => {
            let mut incoming = req.into_body();
            let first = loop {
                match incoming.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data()
                            && !data.is_empty()
                        {
                            break data;
                        }
                    }
                    _ => break Bytes::new(),
                }
            };
            Response::new(body::full(first))
        }
        _ => {
            let method = req.method().to_string();
            let path = req
                .uri()
                .path_and_query()
                .map(ToString::to_string)
                .unwrap_or_default();
            let version = format!("{:?}", req.version());
            let headers: serde_json::Map<String, serde_json::Value> = req
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or(""))))
                .collect();
            let body = req.into_body().collect().await.unwrap().to_bytes();
            let echo = json!({
                "method": method,
                "path": path,
                "version": version,
                "headers": headers,
                "body": String::from_utf8_lossy(&body),
            });
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("x-upstream", "1")
                .body(body::full(echo.to_string()))
                .unwrap()
        }
    }
}

async fn serve_io<I>(io: I, hits: Arc<AtomicUsize>, release: Arc<Notify>, alpn: Alpn)
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        hits.fetch_add(1, Ordering::SeqCst);
        let release = Arc::clone(&release);
        async move { Ok::<_, Infallible>(route(req, release).await) }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    if alpn == Alpn::H2Only {
        builder = builder.http2_only();
    }
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(io), service)
        .await;
}

async fn spawn(
    tls: Option<(Arc<ServerConfig>, Alpn)>,
    ca: Option<(TempDir, CertificateDer<'static>)>,
) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let (h, r) = (Arc::clone(&hits), Arc::clone(&release));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (h, r, tls) = (Arc::clone(&h), Arc::clone(&r), tls.clone());
            tokio::spawn(async move {
                match tls {
                    Some((config, alpn)) => {
                        if let Ok(tls) = TlsAcceptor::from(config).accept(stream).await {
                            serve_io(tls, h, r, alpn).await;
                        }
                    }
                    None => serve_io(stream, h, r, Alpn::Both).await,
                }
            });
        }
    });
    let (ca_home, ca_der) = match ca {
        Some((dir, der)) => (dir, Some(der)),
        None => (tempfile::tempdir().unwrap(), None),
    };
    Upstream {
        addr,
        hits,
        release,
        _ca_dir: ca_home,
        ca_der,
    }
}

/// A plain-HTTP upstream on 127.0.0.1.
pub async fn upstream() -> Upstream {
    spawn(None, None).await
}

/// A TLS upstream for `localhost`, signed by its own fresh CA.
pub async fn tls_upstream(alpn: Alpn) -> Upstream {
    let dir = tempfile::tempdir().unwrap();
    let ca = CertificateAuthority::load_or_create(dir.path()).unwrap();
    let leaf = ca.leaf_for("localhost").unwrap();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(leaf)));
    config.alpn_protocols = match alpn {
        Alpn::Both => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        Alpn::H2Only => vec![b"h2".to_vec()],
    };
    let der = ca.cert_der().clone();
    spawn(Some((Arc::new(config), alpn)), Some((dir, der))).await
}

pub struct Harness {
    pub proxy: Proxy,
    pub dir: TempDir,
    pub script: PathBuf,
}

impl Harness {
    /// A client that sends everything through the proxy and trusts only roxy's CA.
    pub fn client(&self) -> reqwest::Client {
        self.client_builder().build().unwrap()
    }

    pub fn client_builder(&self) -> reqwest::ClientBuilder {
        let ca = reqwest::Certificate::from_der(&self.proxy.ca_cert_der()).unwrap();
        reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.proxy.local_addr())).unwrap())
            .tls_certs_only([ca])
            .timeout(Duration::from_secs(20))
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn write(&self, name: &str, contents: &str) {
        write_atomic(&self.path(name), contents);
    }
}

/// Saves like most editors do: write a sibling file, then rename it into place.
pub fn write_atomic(path: &Path, contents: &str) {
    let tmp = path.with_extension("tmp~");
    std::fs::write(&tmp, contents).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ROXY_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

pub async fn start(
    script: &str,
    trusted: &[&Upstream],
    tweak: impl FnOnce(&mut Config),
) -> Harness {
    try_start(script, trusted, tweak).await.unwrap()
}

pub async fn try_start(
    script: &str,
    trusted: &[&Upstream],
    tweak: impl FnOnce(&mut Config),
) -> anyhow::Result<Harness> {
    try_start_with(script, &[], trusted, tweak).await
}

/// Like [`try_start`], but first writes `files` (relative path, contents) beside the script.
pub async fn try_start_with(
    script: &str,
    files: &[(&str, &str)],
    trusted: &[&Upstream],
    tweak: impl FnOnce(&mut Config),
) -> anyhow::Result<Harness> {
    init_tracing();
    let dir = tempfile::tempdir().unwrap();
    for (name, contents) in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let path = dir.path().join("script.js");
    std::fs::write(&path, script).unwrap();
    let mut config = Config::new(&path, 0);
    config.ca_dir = Some(dir.path().join("ca"));
    config.extra_roots = trusted.iter().filter_map(|u| u.ca_der.clone()).collect();
    config.drain_timeout = Duration::from_secs(5);
    config.metrics_interval = Duration::from_secs(3600);
    tweak(&mut config);
    let proxy = Proxy::start(config).await?;
    Ok(Harness {
        proxy,
        dir,
        script: path,
    })
}

/// Polls `check` until it returns true or `timeout` passes.
pub async fn eventually<F, Fut>(timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

pub async fn json(res: reqwest::Response) -> serde_json::Value {
    serde_json::from_str(&res.text().await.unwrap()).unwrap()
}
