//! One generation of the script: a thread owning the V8 isolate it was loaded into.
#![allow(
    clippy::future_not_send,
    clippy::significant_drop_tightening,
    reason = "the isolate and its futures never leave the worker thread, and the drop lint misreads the moved runtime"
)]

use std::cell::{Cell, RefCell};
use std::future::poll_fn;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use deno_core::{JsRuntime, ModuleSpecifier, PollEventLoopOptions, RuntimeOptions, v8};
use deno_tls::RootCertStoreProvider;
use deno_tls::rustls::RootCertStore;
use futures::FutureExt as _;
use tokio::sync::{mpsc, oneshot};

use super::loader::ScriptLoader;
use super::net_stub::deno_net;
use super::ops::{HostState, roxy_ext};
use super::snapshot::{RESIDUAL_LAZY_ESM, RESIDUAL_LAZY_JS, SNAPSHOT};
use super::{HookFlags, Job};

pub struct WorkerConfig {
    pub script: PathBuf,
    pub load_timeout: Duration,
    pub roots: Arc<RootCertStore>,
}

pub enum LoadReport {
    Loaded {
        flags: HookFlags,
        files: Vec<PathBuf>,
    },
    Failed {
        error: String,
        files: Vec<PathBuf>,
    },
}

pub enum Exit {
    Drained,
    Stopped,
    Crashed(String),
}

/// Handle to a worker thread; dropping `jobs` lets it drain and exit.
pub struct WorkerHandle {
    pub jobs: mpsc::UnboundedSender<Job>,
    pub control: Control,
}

/// Ways to end a worker that is not draining on its own.
pub struct Control {
    pub stop: oneshot::Sender<()>,
    pub exited: oneshot::Receiver<Exit>,
    pub isolate: v8::IsolateHandle,
}

impl Control {
    /// Stops the worker, interrupting any script that is running right now.
    pub fn kill(self) {
        let _ = self.stop.send(());
        // `stop` is only polled between event loop turns, which a sync loop never yields.
        self.isolate.terminate_execution();
    }
}

static LIVE_ISOLATES: AtomicUsize = AtomicUsize::new(0);

/// Number of script generations whose isolate is still alive, across all engines.
pub fn live_isolates() -> usize {
    LIVE_ISOLATES.load(Ordering::SeqCst)
}

struct LiveGuard;

impl LiveGuard {
    fn new() -> Self {
        LIVE_ISOLATES.fetch_add(1, Ordering::SeqCst);
        Self
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        LIVE_ISOLATES.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Roots(Arc<RootCertStore>);

impl RootCertStoreProvider for Roots {
    fn get_or_try_init(&self) -> Result<&RootCertStore, deno_error::JsErrorBox> {
        Ok(&self.0)
    }
}

/// Spawns a worker thread and waits until its script has loaded (or failed to).
///
/// # Errors
/// Fails only when the OS refuses to spawn the thread.
pub async fn spawn(
    config: WorkerConfig,
    generation: u64,
) -> Result<(LoadReport, Option<WorkerHandle>)> {
    let (jobs_tx, jobs_rx) = mpsc::unbounded_channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let (exit_tx, exit_rx) = oneshot::channel();
    let (load_tx, load_rx) = oneshot::channel();
    std::thread::Builder::new()
        .name(format!("roxy-js-{generation}"))
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let error = format!("creating script runtime: {e}");
                    let files = Vec::new();
                    let _ = load_tx.send((LoadReport::Failed { error, files }, None));
                    return;
                }
            };
            let exit = runtime.block_on(run(config, jobs_rx, load_tx, stop_rx));
            if let Some(exit) = exit {
                let _ = exit_tx.send(exit);
            }
        })
        .context("spawning script thread")?;
    let (report, isolate) = load_rx.await.unwrap_or_else(|_| {
        let error = "script thread exited during load".to_owned();
        let files = Vec::new();
        (LoadReport::Failed { error, files }, None)
    });
    let handle = isolate.map(|isolate| WorkerHandle {
        jobs: jobs_tx,
        control: Control {
            stop: stop_tx,
            exited: exit_rx,
            isolate,
        },
    });
    Ok((report, handle))
}

async fn run(
    config: WorkerConfig,
    jobs: mpsc::UnboundedReceiver<Job>,
    load_tx: oneshot::Sender<(LoadReport, Option<v8::IsolateHandle>)>,
    mut stop: oneshot::Receiver<()>,
) -> Option<Exit> {
    let _live = LiveGuard::new();
    let files = Rc::new(RefCell::new(Vec::new()));
    let inflight = Rc::new(Cell::new(0));
    let closed = Rc::new(Cell::new(false));
    let ready = Rc::new(Cell::new(None));
    let host = HostState::new(
        jobs,
        Rc::clone(&inflight),
        Rc::clone(&closed),
        Rc::clone(&ready),
    );
    let loading = load(&config, host, Rc::clone(&files));
    let loaded = tokio::time::timeout(config.load_timeout, loading)
        .await
        .unwrap_or_else(|_| {
            Err(anyhow!(
                "script did not finish loading within {:?}",
                config.load_timeout
            ))
        });
    let files = files.borrow().clone();
    let mut runtime = match loaded {
        Ok(runtime) => runtime,
        Err(e) => {
            let error = format!("{e:#}");
            let _ = load_tx.send((LoadReport::Failed { error, files }, None));
            return None;
        }
    };
    let flags = match ready.take() {
        Some(Ok(flags)) => flags,
        failed => {
            let error = failed
                .and_then(Result::err)
                .unwrap_or_else(|| "script did not finish initializing".to_owned());
            let _ = load_tx.send((LoadReport::Failed { error, files }, None));
            return None;
        }
    };
    let isolate = runtime.v8_isolate().thread_safe_handle();
    let _ = load_tx.send((LoadReport::Loaded { flags, files }, Some(isolate)));
    let exit = poll_fn(|cx| {
        if stop.poll_unpin(cx).is_ready() {
            return Poll::Ready(Exit::Stopped);
        }
        match runtime.poll_event_loop(cx, PollEventLoopOptions::default()) {
            Poll::Ready(Err(e)) => return Poll::Ready(Exit::Crashed(format!("{e:#}"))),
            Poll::Ready(Ok(())) => return Poll::Ready(Exit::Drained),
            Poll::Pending => {}
        }
        if closed.get() && inflight.get() == 0 {
            return Poll::Ready(Exit::Drained);
        }
        Poll::Pending
    })
    .await;
    drop(runtime);
    Some(exit)
}

async fn load(
    config: &WorkerConfig,
    host: HostState,
    files: Rc<RefCell<Vec<PathBuf>>>,
) -> Result<JsRuntime> {
    let fetch_options = deno_fetch::Options {
        user_agent: format!("roxy/{}", env!("CARGO_PKG_VERSION")),
        root_cert_store_provider: Some(Arc::new(Roots(Arc::clone(&config.roots)))),
        ..deno_fetch::Options::default()
    };
    let mut runtime = JsRuntime::new(RuntimeOptions {
        module_loader: Some(Rc::new(ScriptLoader::new(files))),
        startup_snapshot: Some(SNAPSHOT),
        residual_lazy_js_sources: RESIDUAL_LAZY_JS,
        residual_lazy_esm_sources: RESIDUAL_LAZY_ESM,
        // Must match `snapshot_extensions` in build.rs.
        extensions: vec![
            deno_webidl::deno_webidl::init(),
            deno_web::deno_web::init(
                Arc::new(deno_web::BlobStore::default()),
                None,
                false,
                deno_web::InMemoryBroadcastChannel::default(),
            ),
            deno_net::init(),
            deno_fetch::deno_fetch::init(fetch_options),
            roxy_ext::init(host),
        ],
        ..RuntimeOptions::default()
    });
    runtime
        .op_state()
        .borrow_mut()
        .put(deno_permissions::PermissionsContainer::allow_all(Arc::new(
            deno_permissions::RuntimePermissionDescriptorParser::new(sys_traits::impls::RealSys),
        )));

    let watchdog = Watchdog::arm(
        runtime.v8_isolate().thread_safe_handle(),
        config.load_timeout,
    );
    let evaluated = evaluate(config, &mut runtime).await;
    if watchdog.disarm() {
        return Err(anyhow!(
            "script did not finish loading within {:?}",
            config.load_timeout
        ));
    }
    evaluated?;
    Ok(runtime)
}

/// Terminates the isolate from another thread if loading outlives the timeout.
struct Watchdog {
    disarm: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<bool>,
}

impl Watchdog {
    fn arm(isolate: v8::IsolateHandle, timeout: Duration) -> Self {
        let (disarm, disarmed) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            // The loader's tokio timeout can't fire while top-level code spins synchronously.
            let fired = matches!(
                disarmed.recv_timeout(timeout),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            );
            if fired {
                isolate.terminate_execution();
            }
            fired
        });
        Self { disarm, thread }
    }

    /// Returns whether the watchdog fired, in which case the isolate is unusable.
    fn disarm(self) -> bool {
        drop(self.disarm);
        self.thread.join().unwrap_or(true)
    }
}

async fn evaluate(config: &WorkerConfig, runtime: &mut JsRuntime) -> Result<()> {
    runtime.execute_script(
        "roxy:bootstrap",
        "{\nconst key = Symbol.for(\"roxy.bootstrap\");\nconst bootstrap = globalThis[key];\ndelete globalThis[key];\nbootstrap();\n}\n",
    )?;
    let path = std::path::absolute(&config.script)
        .with_context(|| format!("resolving {}", config.script.display()))?;
    let main = ModuleSpecifier::from_file_path(&path)
        .map_err(|()| anyhow!("invalid script path {}", path.display()))?;
    let id = runtime.load_main_es_module(&main).await?;
    let evaluated = runtime.mod_evaluate(id);
    runtime
        .with_event_loop_future(evaluated.boxed_local(), PollEventLoopOptions::default())
        .await?;

    let start = ModuleSpecifier::parse("roxy:start").context("start specifier")?;
    let code = format!(
        "import * as script from {main};\nconst key = Symbol.for(\"roxy.start\");\nconst start = globalThis[key];\ndelete globalThis[key];\nstart(script);\n",
        main = deno_core::serde_json::to_string(main.as_str())?,
    );
    let id = runtime.load_side_es_module_from_code(&start, code).await?;
    let evaluated = runtime.mod_evaluate(id);
    runtime
        .with_event_loop_future(evaluated.boxed_local(), PollEventLoopOptions::default())
        .await?;
    Ok(())
}
