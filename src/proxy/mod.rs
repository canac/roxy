//! The proxy server: accepts connections on 127.0.0.1 and routes them through the hooks.

mod connect;
mod handler;
mod headers;
mod upstream;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ca::{self, CertificateAuthority};
use crate::engine::{Engine, EngineConfig};
use crate::metrics::{Metrics, Snapshot};
use crate::status;
use handler::{Ctx, Origin};

/// Most hooks allowed to run at once; the rest wait their turn.
const MAX_CONCURRENT_HOOKS: usize = 256;

#[derive(Debug, Clone)]
pub struct Config {
    pub script: PathBuf,
    /// Port on 127.0.0.1; 0 picks a free one.
    pub port: u16,
    /// Where the CA lives; `None` means the per-user default.
    pub ca_dir: Option<PathBuf>,
    /// Additional trusted roots for upstream TLS and `fetch()`.
    pub extra_roots: Vec<CertificateDer<'static>>,
    pub metrics_interval: Duration,
    /// Show metrics in the terminal status line instead of logging them.
    pub live_metrics: bool,
    pub watch: bool,
    pub drain_timeout: Duration,
    pub load_timeout: Duration,
}

impl Config {
    #[must_use]
    pub fn new(script: impl Into<PathBuf>, port: u16) -> Self {
        Self {
            script: script.into(),
            port,
            ca_dir: None,
            extra_roots: Vec::new(),
            metrics_interval: Duration::from_secs(60),
            live_metrics: false,
            watch: true,
            drain_timeout: Duration::from_secs(10),
            load_timeout: Duration::from_secs(10),
        }
    }
}

pub struct Proxy {
    addr: SocketAddr,
    ctx: Arc<Ctx>,
    cancel: CancellationToken,
    accept: JoinHandle<()>,
    metrics_task: JoinHandle<()>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl Proxy {
    /// Loads the CA and script, then starts listening.
    ///
    /// # Errors
    /// Fails when the CA or script cannot be loaded or the port cannot be bound.
    pub async fn start(config: Config) -> Result<Self> {
        let ca_dir = match config.ca_dir.clone() {
            Some(dir) => dir,
            None => ca::default_dir()?,
        };
        let ca = Arc::new(CertificateAuthority::load_or_create(&ca_dir)?);
        let roots = Arc::new(upstream::root_store(&config.extra_roots));
        let engine = Engine::start(EngineConfig {
            script: config.script.clone(),
            watch: config.watch,
            drain_timeout: config.drain_timeout,
            load_timeout: config.load_timeout,
            roots: Arc::clone(&roots),
        })
        .await?;
        let hooks = engine.hooks();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, config.port))
            .await
            .with_context(|| format!("binding 127.0.0.1:{}", config.port))?;
        let addr = listener.local_addr()?;
        let metrics = Arc::new(Metrics::default());
        let ctx = Arc::new(Ctx {
            listen: addr,
            engine,
            client: upstream::client(Arc::clone(&roots)),
            upgrade_client: upstream::h1_client(roots),
            metrics: Arc::clone(&metrics),
            hook_slots: Semaphore::new(MAX_CONCURRENT_HOOKS),
            ca,
        });
        let cancel = CancellationToken::new();
        let accept = tokio::spawn(accept_loop(listener, Arc::clone(&ctx), cancel.clone()));
        let interval = config.metrics_interval;
        let live = config.live_metrics;
        let metrics_task = tokio::spawn(async move {
            metrics
                .report_periodically(interval, |s| {
                    if live {
                        status::set(s.to_string());
                    } else {
                        tracing::info!("metrics: {s}");
                    }
                })
                .await;
        });
        tracing::info!(
            on_request = hooks.on_request,
            on_response = hooks.on_response,
            "roxy listening on http://{addr} with {}",
            config.script.display()
        );
        Ok(Self {
            addr,
            ctx,
            cancel,
            accept,
            metrics_task,
        })
    }

    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    #[must_use]
    pub fn metrics(&self) -> Snapshot {
        self.ctx.metrics.snapshot()
    }

    #[must_use]
    pub fn ca_cert_der(&self) -> CertificateDer<'static> {
        self.ctx.ca.cert_der().clone()
    }

    /// Reloads the script without waiting for a file change.
    pub fn reload(&self) {
        self.ctx.engine.reload();
    }

    /// Stops accepting connections and logs the final metrics.
    pub async fn shutdown(self) -> Snapshot {
        self.cancel.cancel();
        let _ = self.accept.await;
        self.metrics_task.abort();
        status::clear();
        let snapshot = self.ctx.metrics.snapshot();
        tracing::info!("final metrics: {snapshot}");
        snapshot
    }
}

async fn accept_loop(listener: TcpListener, ctx: Arc<Ctx>, cancel: CancellationToken) {
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, _peer)) => {
                let _ = stream.set_nodelay(true);
                let ctx = Arc::clone(&ctx);
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        () = cancel.cancelled() => {}
                        () = connect::serve(ctx, stream, Origin::Forward) => {}
                    }
                });
            }
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
