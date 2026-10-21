//! Ops connecting the JS job loop to the proxy.
#![allow(
    clippy::future_not_send,
    clippy::significant_drop_tightening,
    reason = "ops run on the isolate's own thread, and `op2` expands to code we cannot tighten"
)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use bytes::Bytes;
use deno_core::convert::Uint8Array;
use deno_core::{JsBuffer, OpState, op2};
use deno_error::JsErrorBox;
use tokio::sync::{mpsc, oneshot};

pub use self::deno_net as net_stub;
use super::{
    BodyOut, HookFlags, HookMessage, Job, JobPayload, Outcome, RequestPayload, WireResult,
};
use crate::body::BodySlot;

const SINK_CAPACITY: usize = 8;

/// What the start shim reported: the exported hooks, or why the exports are unusable.
pub type Readiness = Result<HookFlags, String>;

struct JobEntry {
    reply: Option<oneshot::Sender<Outcome>>,
    bodies: Vec<u32>,
}

/// Per-isolate bookkeeping for jobs, bodies, and response sinks.
pub struct HostState {
    queue: Option<mpsc::UnboundedReceiver<Job>>,
    jobs: HashMap<u32, JobEntry>,
    bodies: HashMap<u32, Arc<BodySlot>>,
    sinks: HashMap<u32, mpsc::Sender<io::Result<Bytes>>>,
    sink_receivers: HashMap<u32, (mpsc::Receiver<io::Result<Bytes>>, Option<u64>)>,
    next_id: u32,
    inflight: Rc<Cell<usize>>,
    closed: Rc<Cell<bool>>,
    ready: Rc<Cell<Option<Readiness>>>,
}

impl HostState {
    pub fn new(
        queue: mpsc::UnboundedReceiver<Job>,
        inflight: Rc<Cell<usize>>,
        closed: Rc<Cell<bool>>,
        ready: Rc<Cell<Option<Readiness>>>,
    ) -> Self {
        Self {
            queue: Some(queue),
            jobs: HashMap::new(),
            bodies: HashMap::new(),
            sinks: HashMap::new(),
            sink_receivers: HashMap::new(),
            next_id: 0,
            inflight,
            closed,
            ready,
        }
    }

    const fn alloc_id(&mut self) -> u32 {
        self.next_id = self.next_id.wrapping_add(1);
        self.next_id
    }

    fn add_body(&mut self, slot: Option<Arc<BodySlot>>, owned: &mut Vec<u32>) -> Option<u32> {
        let slot = slot?;
        let id = self.alloc_id();
        self.bodies.insert(id, slot);
        owned.push(id);
        Some(id)
    }

    fn register(&mut self, job: Job) -> JobPayload {
        let id = self.alloc_id();
        let mut owned = Vec::new();
        let body_id = self.add_body(job.body, &mut owned);
        let request = job.request.map(|r| RequestPayload {
            body_id: self.add_body(r.body, &mut owned),
            method: r.method,
            url: r.url,
            headers: r.headers,
        });
        self.inflight.set(self.inflight.get() + 1);
        self.jobs.insert(
            id,
            JobEntry {
                reply: Some(job.reply),
                bodies: owned,
            },
        );
        JobPayload {
            id,
            kind: job.kind,
            method: job.method,
            url: job.url,
            status: job.status,
            headers: job.headers,
            body_id,
            request,
        }
    }

    fn finish(&mut self, id: u32) {
        if let Some(entry) = self.jobs.remove(&id) {
            for body in entry.bodies {
                self.bodies.remove(&body);
            }
            self.inflight.set(self.inflight.get().saturating_sub(1));
        }
    }
}

impl Drop for HostState {
    fn drop(&mut self) {
        let leftover = self.jobs.len();
        self.inflight
            .set(self.inflight.get().saturating_sub(leftover));
    }
}

fn into_outcome(host: &mut HostState, wire: WireResult) -> Outcome {
    let body = match wire.body.as_ref().map(|b| (b.kind.as_str(), b.id)) {
        None | Some(("empty", _)) => BodyOut::Empty,
        Some(("original", _)) => BodyOut::Original,
        Some(("sink", Some(id))) => match host.sink_receivers.remove(&id) {
            Some((rx, length)) => BodyOut::Stream { rx, length },
            None => return Outcome::Failed(format!("unknown body sink {id}")),
        },
        Some((other, _)) => return Outcome::Failed(format!("unknown body kind {other:?}")),
    };
    let message = HookMessage {
        method: wire.method,
        url: wire.url,
        status: wire.status,
        headers: wire.headers.unwrap_or_default(),
        body,
    };
    match wire.action.as_str() {
        "continue" => Outcome::Continue(message),
        "respond" => Outcome::Respond(message),
        "error" => Outcome::Failed(wire.error.unwrap_or_else(|| "unknown error".to_owned())),
        other => Outcome::Failed(format!("unknown hook action {other:?}")),
    }
}

#[op2]
#[serde]
pub async fn op_roxy_next_job(state: Rc<RefCell<OpState>>) -> Option<JobPayload> {
    let mut queue = state.borrow_mut().borrow_mut::<HostState>().queue.take()?;
    let job = queue.recv().await;
    let mut state = state.borrow_mut();
    let host = state.borrow_mut::<HostState>();
    let Some(job) = job else {
        host.closed.set(true);
        return None;
    };
    host.queue = Some(queue);
    Some(host.register(job))
}

#[op2]
pub async fn op_roxy_body_read(
    state: Rc<RefCell<OpState>>,
    #[smi] id: u32,
) -> Result<Option<Uint8Array>, JsErrorBox> {
    let slot = state
        .borrow()
        .borrow::<HostState>()
        .bodies
        .get(&id)
        .cloned()
        .ok_or_else(|| JsErrorBox::generic("body is no longer available"))?;
    let chunk = slot
        .read_chunk()
        .await
        .map_err(|e| JsErrorBox::type_error(format!("reading body: {e}")))?;
    Ok(chunk.map(|c| Uint8Array::from(c.to_vec())))
}

#[op2]
pub fn op_roxy_complete(state: &mut OpState, #[smi] id: u32, #[serde] result: WireResult) {
    let host = state.borrow_mut::<HostState>();
    let outcome = into_outcome(host, result);
    if let Some(reply) = host.jobs.get_mut(&id).and_then(|j| j.reply.take()) {
        let _ = reply.send(outcome);
    }
}

#[op2(fast)]
pub fn op_roxy_job_done(state: &mut OpState, #[smi] id: u32) {
    state.borrow_mut::<HostState>().finish(id);
}

#[op2]
#[smi]
pub fn op_roxy_sink_open(state: &mut OpState, length: Option<f64>) -> u32 {
    let host = state.borrow_mut::<HostState>();
    let id = host.alloc_id();
    let (tx, rx) = mpsc::channel(SINK_CAPACITY);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "JS body lengths are non-negative integers"
    )]
    let length = length.filter(|l| *l >= 0.0).map(|l| l as u64);
    host.sinks.insert(id, tx);
    host.sink_receivers.insert(id, (rx, length));
    id
}

#[op2]
pub async fn op_roxy_sink_write(
    state: Rc<RefCell<OpState>>,
    #[smi] id: u32,
    #[buffer] chunk: JsBuffer,
) -> Result<(), JsErrorBox> {
    let tx = state
        .borrow()
        .borrow::<HostState>()
        .sinks
        .get(&id)
        .cloned()
        .ok_or_else(|| JsErrorBox::generic("body sink is closed"))?;
    tx.send(Ok(Bytes::copy_from_slice(&chunk)))
        .await
        .map_err(|_| JsErrorBox::generic("peer stopped reading the body"))
}

#[op2]
pub async fn op_roxy_sink_close(
    state: Rc<RefCell<OpState>>,
    #[smi] id: u32,
    #[string] error: Option<String>,
) {
    let tx = {
        let mut state = state.borrow_mut();
        let host = state.borrow_mut::<HostState>();
        host.sink_receivers.remove(&id);
        host.sinks.remove(&id)
    };
    if let (Some(tx), Some(error)) = (tx, error) {
        // A closed channel means the client hung up, which is routine.
        if tx.is_closed() {
            tracing::debug!("script body stream stopped: {error}");
            return;
        }
        tracing::warn!("script body stream failed: {error}");
        let _ = tx.send(Err(io::Error::other(error))).await;
    }
}

#[op2]
pub fn op_roxy_ready(
    state: &OpState,
    on_request: bool,
    on_response: bool,
    #[string] error: Option<String>,
) {
    let readiness = error.map_or(
        Ok(HookFlags {
            on_request,
            on_response,
        }),
        Err,
    );
    state.borrow::<HostState>().ready.set(Some(readiness));
}

#[op2(fast)]
pub fn op_roxy_log(#[smi] level: i32, #[string] message: &str) {
    match level {
        0 => tracing::debug!(target: "roxy::script", "{message}"),
        2 => tracing::warn!(target: "roxy::script", "{message}"),
        3 => tracing::error!(target: "roxy::script", "{message}"),
        4 => tracing::trace!(target: "roxy::script", "{message}"),
        _ => tracing::info!(target: "roxy::script", "{message}"),
    }
}

// deno_fetch lazily imports this script even though only Deno.createHttpClient uses it.
deno_core::extension!(
    deno_net,
    lazy_loaded_js = [dir "src/engine/stubs", "02_tls.js"],
);

deno_core::extension!(
    roxy_ext,
    deps = [deno_webidl, deno_web, deno_net, deno_fetch],
    ops = [
        op_roxy_next_job,
        op_roxy_body_read,
        op_roxy_complete,
        op_roxy_job_done,
        op_roxy_sink_open,
        op_roxy_sink_write,
        op_roxy_sink_close,
        op_roxy_ready,
        op_roxy_log,
    ],
    esm_entry_point = "ext:roxy_ext/runtime.js",
    esm = [dir "src/engine", "runtime.js"],
    options = { host: HostState },
    state = |state, options| {
        state.put(options.host);
    },
);
