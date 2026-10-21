// Bootstraps web globals and runs the hook job loop inside the isolate.
import { core, internals } from "ext:core/mod.js";

const {
  op_roxy_body_read,
  op_roxy_complete,
  op_roxy_job_done,
  op_roxy_log,
  op_roxy_next_job,
  op_roxy_ready,
  op_roxy_sink_close,
  op_roxy_sink_open,
  op_roxy_sink_write,
} = core.ops;

const load = (name) => core.loadExtScript(name);

// Telemetry is TypeScript in Deno and unused here; these no-ops keep fetch from loading it.
internals.__telemetry ??= {
  TRACING_ENABLED: false,
  PROPAGATORS: [],
  DID_NOT_ENTER: Symbol("DID_NOT_ENTER"),
  builtinTracer() {},
  ContextManager: { active() {} },
  enterSpan() {},
  exitSpan() {},
};
internals.__telemetryUtil ??= {
  updateSpanFromClientResponse() {},
  updateSpanFromError() {},
  updateSpanFromRequest() {},
};

const url = load("ext:deno_web/00_url.js");
const urlPattern = load("ext:deno_web/01_urlpattern.js");
const console_ = load("ext:deno_web/01_console.js");
const domException = load("ext:deno_web/01_dom_exception.js");
const event = load("ext:deno_web/02_event.js");
const structuredClone = load("ext:deno_web/02_structured_clone.js");
const timers = load("ext:deno_web/02_timers.js");
const abort = load("ext:deno_web/03_abort_signal.js");
const base64 = load("ext:deno_web/05_base64.js");
const streams = load("ext:deno_web/06_streams.js");
const encoding = load("ext:deno_web/08_text_encoding.js");
const file = load("ext:deno_web/09_file.js");
const fileReader = load("ext:deno_web/10_filereader.js");
const messagePort = load("ext:deno_web/13_message_port.js");
const compression = load("ext:deno_web/14_compression.js");
const performance = load("ext:deno_web/15_performance.js");
const headers = load("ext:deno_fetch/20_headers.js");
const formData = load("ext:deno_fetch/21_formdata.js");
const request = load("ext:deno_fetch/23_request.js");
const response = load("ext:deno_fetch/23_response.js");
const fetch = load("ext:deno_fetch/26_fetch.js");

const { Request, toInnerRequest } = request;
const { Response, toInnerResponse } = response;
const { ReadableStream } = streams;

const LEVELS = { debug: 0, log: 1, warn: 2, error: 3 };

function log(level, message) {
  op_roxy_log(level, message);
}

function expose(values) {
  for (const [name, value] of Object.entries(values)) {
    Object.defineProperty(globalThis, name, {
      value,
      writable: true,
      configurable: true,
      enumerable: false,
    });
  }
}

// tracing escapes ANSI codes, so colored inspect output would show up as literal "\x1b[33m".
console_.setNoColorFns(() => true, () => true);
const consoleImpl = new console_.Console((msg, level) => {
  op_roxy_log(level, msg.endsWith("\n") ? msg.slice(0, -1) : msg);
});

performance.setTimeOrigin();
event.saveGlobalThisReference(globalThis);

expose({
  AbortController: abort.AbortController,
  AbortSignal: abort.AbortSignal,
  Blob: file.Blob,
  ByteLengthQueuingStrategy: streams.ByteLengthQueuingStrategy,
  CompressionStream: compression.CompressionStream,
  CountQueuingStrategy: streams.CountQueuingStrategy,
  CustomEvent: event.CustomEvent,
  DOMException: domException.DOMException,
  DecompressionStream: compression.DecompressionStream,
  ErrorEvent: event.ErrorEvent,
  Event: event.Event,
  EventTarget: event.EventTarget,
  File: file.File,
  FileReader: fileReader.FileReader,
  FormData: formData.FormData,
  Headers: headers.Headers,
  MessageChannel: messagePort.MessageChannel,
  MessagePort: messagePort.MessagePort,
  ReadableStream,
  ReadableStreamDefaultReader: streams.ReadableStreamDefaultReader,
  Request,
  Response,
  TextDecoder: encoding.TextDecoder,
  TextDecoderStream: encoding.TextDecoderStream,
  TextEncoder: encoding.TextEncoder,
  TextEncoderStream: encoding.TextEncoderStream,
  TransformStream: streams.TransformStream,
  URL: url.URL,
  URLPattern: urlPattern.URLPattern,
  URLSearchParams: url.URLSearchParams,
  WritableStream: streams.WritableStream,
  atob: base64.atob,
  btoa: base64.btoa,
  clearInterval: timers.clearInterval,
  clearTimeout: timers.clearTimeout,
  console: consoleImpl,
  fetch: fetch.fetch,
  performance: performance.performance,
  queueMicrotask: globalThis.queueMicrotask,
  reportError: event.reportError,
  setInterval: timers.setInterval,
  setTimeout: timers.setTimeout,
  structuredClone: structuredClone.structuredClone,
});

function describe(err) {
  if (err instanceof Error) return err.stack ?? String(err);
  try {
    return console_.inspect(err);
  } catch {
    return String(err);
  }
}

core.setUnhandledPromiseRejectionHandler((_promise, reason) => {
  log(LEVELS.error, `unhandled promise rejection in script: ${describe(reason)}`);
  return true;
});
core.setReportExceptionCallback((err) => {
  log(LEVELS.error, `uncaught exception in script: ${describe(err)}`);
});

let hooks = { onRequest: undefined, onResponse: undefined };

// A body backed by the proxy that is only fetched from Rust when someone reads it.
function lazyBody(id) {
  if (id === null || id === undefined) return null;
  return new ReadableStream(
    {
      async pull(controller) {
        const chunk = await op_roxy_body_read(id);
        if (chunk === null) {
          controller.close();
        } else {
          controller.enqueue(chunk);
        }
      },
    },
    { highWaterMark: 0 },
  );
}

function headerList(h) {
  return Array.from(h);
}

// deno_fetch leaves `length` null for string bodies, so measure static bodies here.
function staticBytes(streamOrStatic) {
  if (streamOrStatic instanceof ReadableStream) return null;
  const { body } = streamOrStatic;
  return typeof body === "string" ? core.encode(body) : body;
}

// `passed` is the object given to the hook; returning it unchanged keeps the proxied body.
function bodyWire(inner, owner, lazy, passed) {
  const body = inner.body;
  if (body === null) return { wire: { kind: owner === passed ? "original" : "empty" } };
  if (lazy !== null && body.streamOrStatic === lazy) {
    return { wire: { kind: "original" } };
  }
  if (owner.bodyUsed) {
    throw new TypeError("returned body was already consumed by the hook");
  }
  const fixed = staticBytes(body.streamOrStatic);
  const length = fixed?.byteLength ?? (typeof body.length === "number" ? body.length : null);
  const id = op_roxy_sink_open(length);
  const stream = fixed === null ? owner.body : null;
  const pump = async () => {
    try {
      if (fixed !== null) {
        if (fixed.byteLength > 0) await op_roxy_sink_write(id, fixed);
      } else {
        const reader = stream.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value.byteLength > 0) await op_roxy_sink_write(id, value);
        }
      }
      op_roxy_sink_close(id, null);
    } catch (err) {
      op_roxy_sink_close(id, describe(err));
    }
  };
  return { wire: { kind: "sink", id, length }, pump };
}

// `given` is the URL the hook was handed; an unchanged URL is sent as it arrived, not normalized.
function continueWith(req, lazy, passed, given) {
  const { wire, pump } = bodyWire(toInnerRequest(req), req, lazy, passed);
  return {
    wire: {
      action: "continue",
      method: req.method,
      url: req.url === given.url ? given.raw : req.url,
      headers: headerList(req.headers),
      body: wire,
    },
    pump,
  };
}

function respondWith(res, lazy, passed) {
  const { wire, pump } = bodyWire(toInnerResponse(res), res, lazy, passed);
  return {
    wire: {
      action: "respond",
      status: res.status,
      headers: headerList(res.headers),
      body: wire,
    },
    pump,
  };
}

function kindOf(value) {
  if (value === null) return "null";
  if (typeof value === "object") return value.constructor?.name ?? "object";
  return typeof value;
}

function makeRequest(info, body) {
  return new Request(info.url, {
    method: info.method,
    headers: info.headers,
    body,
    duplex: "half",
  });
}

async function runRequest(job) {
  const lazy = lazyBody(job.bodyId);
  const req = makeRequest(job, lazy);
  const given = { url: req.url, raw: job.url };
  const ret = await hooks.onRequest(req);
  if (ret === undefined) return continueWith(req, lazy, req, given);
  if (ret instanceof Request) return continueWith(ret, lazy, req, given);
  if (ret instanceof Response) return respondWith(ret, lazy, null);
  throw new TypeError(
    `onRequest returned ${kindOf(ret)}; expected undefined, a Request, or a Response`,
  );
}

async function runResponse(job) {
  const req = makeRequest(job.request, lazyBody(job.request.bodyId));
  const lazy = lazyBody(job.bodyId);
  const res = new Response(lazy, { status: job.status, headers: job.headers });
  const ret = await hooks.onResponse(req, res);
  if (ret === undefined) return respondWith(res, lazy, res);
  if (ret instanceof Response) return respondWith(ret, lazy, res);
  throw new TypeError(
    `onResponse returned ${kindOf(ret)}; expected undefined or a Response`,
  );
}

async function handle(job) {
  try {
    let result;
    try {
      result = job.kind === "request" ? await runRequest(job) : await runResponse(job);
    } catch (err) {
      result = { wire: { action: "error", error: describe(err) } };
    }
    op_roxy_complete(job.id, result.wire);
    if (result.pump) await result.pump();
  } catch (err) {
    log(LEVELS.error, `internal hook error: ${describe(err)}`);
  } finally {
    op_roxy_job_done(job.id);
  }
}

async function jobLoop() {
  while (true) {
    const job = await op_roxy_next_job();
    if (job === null) return;
    handle(job);
  }
}

function start(mod) {
  const { onRequest, onResponse } = mod;
  for (const [name, hook] of [["onRequest", onRequest], ["onResponse", onResponse]]) {
    if (hook !== undefined && typeof hook !== "function") {
      op_roxy_ready(false, false, `export ${name} must be a function, got ${kindOf(hook)}`);
      return;
    }
  }
  hooks = { onRequest, onResponse };
  op_roxy_ready(onRequest !== undefined, onResponse !== undefined, null);
  jobLoop();
}

Object.defineProperty(globalThis, Symbol.for("roxy.start"), {
  value: start,
  configurable: true,
  enumerable: false,
});
