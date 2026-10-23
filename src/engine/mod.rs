//! The JavaScript engine: runs user hooks in a V8 isolate and live-reloads the script.

mod loader;
mod net_stub;
mod ops;
mod snapshot;
mod worker;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Result, bail};
use bytes::Bytes;
use deno_tls::rustls::RootCertStore;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::body::BodySlot;
use crate::watch::FileWatcher;
pub use worker::live_isolates;
use worker::{Control, Exit, LoadReport, WorkerConfig, WorkerHandle};

const DEBOUNCE: Duration = Duration::from_millis(50);
const RESTART_BACKOFF: Duration = Duration::from_secs(1);

pub type HeaderPairs = Vec<(String, String)>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HookFlags {
    pub on_request: bool,
    pub on_response: bool,
}

impl HookFlags {
    const fn bits(self) -> u8 {
        (self.on_request as u8) | ((self.on_response as u8) << 1)
    }

    const fn from_bits(bits: u8) -> Self {
        Self {
            on_request: bits & 1 != 0,
            on_response: bits & 2 != 0,
        }
    }
}

/// The request as the upstream saw it, handed to `onResponse`.
pub struct RequestView {
    pub method: String,
    pub url: String,
    pub headers: HeaderPairs,
    pub body: Option<Arc<BodySlot>>,
}

/// One hook invocation.
pub struct Job {
    pub kind: &'static str,
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub headers: HeaderPairs,
    pub body: Option<Arc<BodySlot>>,
    pub request: Option<RequestView>,
    reply: oneshot::Sender<Outcome>,
}

impl Job {
    /// A job for `onRequest`.
    #[must_use]
    pub fn request(
        method: String,
        url: String,
        headers: HeaderPairs,
        body: Option<Arc<BodySlot>>,
    ) -> (Self, oneshot::Receiver<Outcome>) {
        let (reply, rx) = oneshot::channel();
        let job = Self {
            kind: "request",
            method,
            url,
            status: None,
            headers,
            body,
            request: None,
            reply,
        };
        (job, rx)
    }

    /// A job for `onResponse`.
    #[must_use]
    pub fn response(
        status: u16,
        headers: HeaderPairs,
        body: Option<Arc<BodySlot>>,
        request: RequestView,
    ) -> (Self, oneshot::Receiver<Outcome>) {
        let (reply, rx) = oneshot::channel();
        let job = Self {
            kind: "response",
            method: String::new(),
            url: String::new(),
            status: Some(status),
            headers,
            body,
            request: Some(request),
            reply,
        };
        (job, rx)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestPayload {
    method: String,
    url: String,
    headers: HeaderPairs,
    body_id: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JobPayload {
    id: u32,
    kind: &'static str,
    method: String,
    url: String,
    status: Option<u16>,
    headers: HeaderPairs,
    body_id: Option<u32>,
    request: Option<RequestPayload>,
}

#[derive(Deserialize)]
struct WireBody {
    kind: String,
    id: Option<u32>,
}

#[derive(Deserialize)]
struct WireResult {
    action: String,
    method: Option<String>,
    url: Option<String>,
    status: Option<f64>,
    headers: Option<HeaderPairs>,
    body: Option<WireBody>,
    error: Option<String>,
}

/// Where the body of a hook's result comes from.
pub enum BodyOut {
    /// The proxied body, untouched unless the hook read it.
    Original,
    Empty,
    /// A body produced by the script, with its length when known up front.
    Stream {
        rx: mpsc::Receiver<std::io::Result<Bytes>>,
        length: Option<u64>,
    },
}

pub struct HookMessage {
    pub method: Option<String>,
    pub url: Option<String>,
    pub status: Option<f64>,
    pub headers: HeaderPairs,
    pub body: BodyOut,
}

pub enum Outcome {
    /// Send this request upstream.
    Continue(HookMessage),
    /// Reply to the client with this response.
    Respond(HookMessage),
    /// The hook failed; the caller passes the original traffic through.
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub script: PathBuf,
    pub watch: bool,
    pub drain_timeout: Duration,
    pub load_timeout: Duration,
    pub roots: Arc<RootCertStore>,
}

struct Shared {
    current: RwLock<Option<mpsc::UnboundedSender<Job>>>,
    flags: AtomicU8,
}

impl Shared {
    fn install(&self, jobs: Option<mpsc::UnboundedSender<Job>>, flags: HookFlags) {
        if let Ok(mut current) = self.current.write() {
            *current = jobs;
        }
        self.flags.store(flags.bits(), Ordering::Release);
    }
}

enum Command {
    Reload,
}

enum Event {
    Reload,
    Changed,
    Exited(Option<Exit>),
}

/// Handle to the running script. Dropping it shuts the script down.
pub struct Engine {
    shared: Arc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("hooks", &self.hooks())
            .finish()
    }
}

impl Engine {
    /// Loads the script and starts watching it for changes.
    ///
    /// # Errors
    /// Fails when the script cannot be loaded initially.
    pub async fn start(mut config: EngineConfig) -> Result<Self> {
        // The watcher needs a real parent directory, which `script.js` alone lacks.
        config.script = std::path::absolute(&config.script)?;
        let (report, handle) = worker::spawn(worker_config(&config), 0).await?;
        let (flags, files) = match report {
            LoadReport::Loaded { flags, files } => (flags, files),
            LoadReport::Failed { error, .. } => bail!("failed to load script: {error}"),
        };
        let shared = Arc::new(Shared {
            current: RwLock::new(None),
            flags: AtomicU8::new(0),
        });
        let (commands, command_rx) = mpsc::unbounded_channel();
        let (changes_tx, changes) = mpsc::unbounded_channel();
        let watcher = if config.watch {
            let mut watcher = FileWatcher::new(move || {
                let _ = changes_tx.send(());
            })?;
            watcher.set_files(files.iter().cloned());
            Some(watcher)
        } else {
            None
        };
        let mut manager = Manager {
            config,
            shared: Arc::clone(&shared),
            generation: 0,
            current: None,
            watcher,
            good_files: files,
        };
        if let Some(handle) = handle {
            manager.adopt(handle, flags);
        }
        tokio::spawn(manager.run(command_rx, changes));
        Ok(Self { shared, commands })
    }

    #[must_use]
    pub fn hooks(&self) -> HookFlags {
        HookFlags::from_bits(self.shared.flags.load(Ordering::Acquire))
    }

    /// Runs a hook job, resolving to [`Outcome::Failed`] if the script is unavailable.
    pub async fn call(&self, job: Job, reply: oneshot::Receiver<Outcome>) -> Outcome {
        let sender = self.shared.current.read().ok().and_then(|c| c.clone());
        let Some(sender) = sender else {
            return Outcome::Failed("no script is loaded".to_owned());
        };
        if sender.send(job).is_err() {
            return Outcome::Failed("script runtime is gone".to_owned());
        }
        drop(sender);
        reply
            .await
            .unwrap_or_else(|_| Outcome::Failed("script runtime dropped the hook call".to_owned()))
    }

    /// Reloads the script as if it had changed on disk.
    pub fn reload(&self) {
        let _ = self.commands.send(Command::Reload);
    }
}

fn worker_config(config: &EngineConfig) -> WorkerConfig {
    WorkerConfig {
        script: config.script.clone(),
        load_timeout: config.load_timeout,
        roots: Arc::clone(&config.roots),
    }
}

struct Manager {
    config: EngineConfig,
    shared: Arc<Shared>,
    generation: u64,
    current: Option<Control>,
    watcher: Option<FileWatcher>,
    good_files: Vec<PathBuf>,
}

impl Manager {
    fn adopt(&mut self, handle: WorkerHandle, flags: HookFlags) {
        self.shared.install(Some(handle.jobs), flags);
        if let Some(old) = self.current.replace(handle.control) {
            retire(old, self.config.drain_timeout);
        }
    }

    async fn run(
        mut self,
        mut commands: mpsc::UnboundedReceiver<Command>,
        mut changes: mpsc::UnboundedReceiver<()>,
    ) {
        loop {
            let event = {
                let exited = async {
                    match self.current.as_mut() {
                        Some(control) => (&mut control.exited).await.ok(),
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    cmd = commands.recv() => match cmd {
                        Some(Command::Reload) => Event::Reload,
                        None => break,
                    },
                    Some(()) = changes.recv() => Event::Changed,
                    exit = exited => Event::Exited(exit),
                }
            };
            match event {
                Event::Reload => self.reload().await,
                Event::Changed => {
                    tokio::time::sleep(DEBOUNCE).await;
                    while changes.try_recv().is_ok() {}
                    self.reload().await;
                }
                Event::Exited(exit) => {
                    self.current = None;
                    self.shared.install(None, HookFlags::default());
                    if let Some(Exit::Crashed(e)) = exit {
                        tracing::error!("script runtime crashed: {e}");
                    } else {
                        tracing::error!("script runtime exited unexpectedly");
                    }
                    tokio::time::sleep(RESTART_BACKOFF).await;
                    self.reload().await;
                }
            }
        }
        self.shared.install(None, HookFlags::default());
        if let Some(current) = self.current.take() {
            retire(current, self.config.drain_timeout);
        }
    }

    async fn reload(&mut self) {
        self.generation += 1;
        let spawned = worker::spawn(worker_config(&self.config), self.generation).await;
        let (report, handle) = match spawned {
            Ok(spawned) => spawned,
            Err(e) => {
                tracing::error!("reload failed: {e:#}");
                return;
            }
        };
        match report {
            LoadReport::Loaded { flags, files } => {
                if let Some(handle) = handle {
                    self.adopt(handle, flags);
                }
                tracing::info!(
                    on_request = flags.on_request,
                    on_response = flags.on_response,
                    "reloaded {}",
                    self.config.script.display()
                );
                self.watch(&files, &[]);
                self.good_files = files;
            }
            LoadReport::Failed { error, files } => {
                let keeping = if self.current.is_some() {
                    "keeping the previous script"
                } else {
                    "no script is running; traffic passes through"
                };
                tracing::error!("reload failed, {keeping}: {error}");
                let good = std::mem::take(&mut self.good_files);
                self.watch(&good, &files);
                self.good_files = good;
            }
        }
    }

    fn watch(&mut self, a: &[PathBuf], b: &[PathBuf]) {
        if let Some(watcher) = self.watcher.as_mut() {
            let mut files = vec![self.config.script.clone()];
            files.extend(a.iter().chain(b).cloned());
            watcher.set_files(files);
        }
    }
}

/// Lets a replaced generation finish its in-flight hooks, killing it after `timeout`.
fn retire(mut control: Control, timeout: Duration) {
    tokio::spawn(async move {
        if tokio::time::timeout(timeout, &mut control.exited)
            .await
            .is_err()
        {
            tracing::warn!("in-flight hooks did not finish within {timeout:?}; abandoning them");
            control.kill();
        }
    });
}
