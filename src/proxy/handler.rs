//! Per-request flow: run hooks, talk to the upstream, and fail open on hook errors.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode, Uri, Version};
use http_body::Body as _;
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::sync::{Semaphore, mpsc, oneshot};

use super::headers::{
    self as hdrs, from_pairs, join_cookies, restore_layout, strip_hop_by_hop, to_pairs,
};
use super::upstream::UpstreamClient;
use crate::body::{self, Body, BodyCopy, BodySlot, RETAIN_LIMIT};
use crate::ca::CertificateAuthority;
use crate::engine::{BodyOut, Engine, HookMessage, Job, Outcome, RequestView};
use crate::metrics::Metrics;

pub struct Ctx {
    /// Where roxy listens, so requests aimed back at it can be refused.
    pub listen: SocketAddr,
    pub engine: Engine,
    pub client: UpstreamClient,
    pub upgrade_client: UpstreamClient,
    pub metrics: Arc<Metrics>,
    pub hook_slots: Semaphore,
    pub ca: Arc<CertificateAuthority>,
}

/// How a request reached us: as a forward-proxy request, or inside a CONNECT tunnel.
#[derive(Clone)]
pub enum Origin {
    Forward,
    Tunnel {
        scheme: &'static str,
        authority: http::uri::Authority,
    },
}

/// Entry point for every request served by roxy.
pub async fn handle(
    ctx: Arc<Ctx>,
    origin: Origin,
    req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    if matches!(origin, Origin::Forward) && req.method() == Method::CONNECT {
        return Ok(super::connect::handle(ctx, req));
    }
    Ok(proxy(&ctx, &origin, req).await)
}

fn text(status: StatusCode, message: &str) -> Response<Body> {
    let mut res = Response::new(body::full(format!("{message}\n")));
    *res.status_mut() = status;
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    res
}

fn target_url(origin: &Origin, parts: &http::request::Parts) -> Result<Uri, String> {
    match origin {
        Origin::Forward => {
            if parts.uri.scheme().is_none() || parts.uri.authority().is_none() {
                return Err("roxy is a proxy: requests need an absolute URL".to_owned());
            }
            Ok(parts.uri.clone())
        }
        Origin::Tunnel { scheme, authority } => {
            let host = parts
                .uri
                .authority()
                .map(ToString::to_string)
                .or_else(|| {
                    parts
                        .headers
                        .get(header::HOST)
                        .and_then(|h| h.to_str().ok())
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| without_default_port(scheme, authority));
            let path = parts
                .uri
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str);
            format!("{scheme}://{host}{path}")
                .parse()
                .map_err(|e| format!("invalid request target: {e}"))
        }
    }
}

/// Whether `url` reaches roxy's own listener, which would only proxy the request to itself.
fn targets_self(url: &Uri, listen: SocketAddr) -> bool {
    let default = if url.scheme_str() == Some("https") {
        443
    } else {
        80
    };
    if url.port_u16().unwrap_or(default) != listen.port() {
        return false;
    }
    let host = url.host().unwrap_or_default();
    host.eq_ignore_ascii_case("localhost") || host.parse::<IpAddr>() == Ok(listen.ip())
}

fn without_default_port(scheme: &str, authority: &http::uri::Authority) -> String {
    let default = if scheme == "https" { 443 } else { 80 };
    match authority.port_u16() {
        Some(port) if port == default => authority.host().to_owned(),
        _ => authority.to_string(),
    }
}

/// A request or response body that may or may not have been handed to a hook.
enum Pending {
    Raw(Body),
    Slot(Arc<BodySlot>),
}

const fn has_null_body(status: StatusCode) -> bool {
    matches!(status.as_u16(), 101 | 103 | 204 | 205 | 304)
}

fn status_from(raw: Option<f64>) -> StatusCode {
    let parsed = raw
        .filter(|s| s.fract() == 0.0 && (200.0..=999.0).contains(s))
        .and_then(|s| {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "range checked above"
            )]
            StatusCode::from_u16(s as u16).ok()
        });
    parsed.unwrap_or_else(|| {
        tracing::warn!("hook returned invalid status {raw:?}; using 502");
        StatusCode::BAD_GATEWAY
    })
}

fn receiver_body(rx: mpsc::Receiver<std::io::Result<bytes::Bytes>>) -> Body {
    body::from_stream(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }))
}

/// Resolves a hook's body choice. `original` is the slot the hook was given.
async fn resolve_body(
    choice: BodyOut,
    original: Pending,
    original_encoding: Option<&HeaderValue>,
    headers: &mut HeaderMap,
) -> Body {
    match choice {
        BodyOut::Original => pending_body(original, headers).await,
        BodyOut::Empty => {
            hdrs::remove(headers, &header::CONTENT_LENGTH);
            drop_inherited_encoding(headers, original_encoding);
            body::empty()
        }
        BodyOut::Stream { rx, length } => {
            if let Pending::Slot(slot) = &original {
                slot.stop_retaining().await;
            }
            match length {
                Some(len) => {
                    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
                }
                None => hdrs::remove(headers, &header::CONTENT_LENGTH),
            }
            drop_inherited_encoding(headers, original_encoding);
            receiver_body(rx)
        }
    }
}

/// A body the script built is plain bytes, so an encoding copied from the original is wrong.
fn drop_inherited_encoding(headers: &mut HeaderMap, original: Option<&HeaderValue>) {
    if original.is_some() && headers.get(header::CONTENT_ENCODING) == original {
        hdrs::remove(headers, &header::CONTENT_ENCODING);
    }
}

async fn pending_body(pending: Pending, headers: &mut HeaderMap) -> Body {
    match pending {
        Pending::Raw(body) => body,
        Pending::Slot(slot) => {
            let forward = slot.take().await;
            if slot.touched().await {
                match forward.length {
                    Some(len) => {
                        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
                    }
                    None => hdrs::remove(headers, &header::CONTENT_LENGTH),
                }
            }
            if forward.decoded {
                hdrs::remove(headers, &header::CONTENT_ENCODING);
            }
            forward.body
        }
    }
}

struct Outgoing {
    method: Method,
    url: Uri,
    headers: HeaderMap,
    body: Body,
}

/// What `onResponse` may see of the request body that went upstream.
enum SentBody {
    Hidden,
    /// The proxied body; visible only if `onRequest` read all of it within [`RETAIN_LIMIT`].
    Slot(Arc<BodySlot>),
    /// A copy of the body `onRequest` built; dropped once it passes [`RETAIN_LIMIT`].
    Copy(BodyCopy),
}

/// The reply when a hook read more of a body than [`RETAIN_LIMIT`], then left it to be forwarded.
fn lost_body(hook: &str, which: &str) -> Response<Body> {
    let message = format!(
        "{hook} read over {} MiB of the {which} body without returning a new one, \
         so roxy cannot forward the original",
        RETAIN_LIMIT >> 20
    );
    tracing::warn!("{message}");
    text(StatusCode::BAD_GATEWAY, &message)
}

impl Ctx {
    async fn run_hook(&self, job: Job, reply: oneshot::Receiver<Outcome>) -> Outcome {
        let started = Instant::now();
        let permit = self.hook_slots.acquire().await;
        let outcome = self.engine.call(job, reply).await;
        drop(permit);
        self.metrics.add_overhead(started.elapsed());
        outcome
    }
}

async fn proxy(ctx: &Ctx, origin: &Origin, req: Request<Incoming>) -> Response<Body> {
    let (mut parts, incoming) = req.into_parts();
    let url = match target_url(origin, &parts) {
        Ok(url) => url,
        Err(message) => return text(StatusCode::BAD_REQUEST, &message),
    };
    ctx.metrics.record_request();
    let upgrade = take_upgrade(&mut parts);
    strip_hop_by_hop(&mut parts.headers);
    join_cookies(&mut parts.headers);
    hdrs::remove(&mut parts.headers, &header::HOST);
    let hooks = ctx.engine.hooks();
    let raw = body::from_incoming(incoming);

    let phase = request_phase(ctx, parts, url, raw, hooks.on_request, hooks.on_response);
    let res = match phase.await {
        Err(early) => *early,
        Ok((mut outgoing, sent)) => {
            let view = hooks.on_response.then(|| RequestView {
                method: outgoing.method.to_string(),
                url: outgoing.url.to_string(),
                headers: to_pairs(&outgoing.headers),
                body: None,
            });
            let method = outgoing.method.clone();
            let client = match &upgrade {
                Some((protocol, _)) => {
                    let headers = &mut outgoing.headers;
                    headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
                    headers.insert(header::UPGRADE, protocol.clone());
                    &ctx.upgrade_client
                }
                None => &ctx.client,
            };
            match send_upstream(client, outgoing, ctx.listen).await {
                Err(failed) => *failed,
                Ok(res) if res.status() == StatusCode::SWITCHING_PROTOCOLS && upgrade.is_some() => {
                    let (_, downstream) = upgrade.expect("checked above");
                    switch_protocols(downstream, res)
                }
                Ok(res) => {
                    if let Some(view) = view {
                        response_phase(ctx, view, sent, &method, res).await
                    } else {
                        let (mut parts, incoming) = res.into_parts();
                        strip_hop_by_hop(&mut parts.headers);
                        Response::from_parts(parts, body::from_incoming(incoming))
                    }
                }
            }
        }
    };
    ctx.metrics.record_response();
    res
}

/// Runs `onRequest`, yielding the request to send upstream or a response to send right away.
async fn request_phase(
    ctx: &Ctx,
    parts: http::request::Parts,
    url: Uri,
    raw: Body,
    on_request: bool,
    record: bool,
) -> Result<(Outgoing, SentBody), Box<Response<Body>>> {
    if !on_request {
        let out = original(parts, url, Pending::Raw(raw)).await;
        return Ok((out, SentBody::Hidden));
    }
    let exposes = !raw.is_end_stream() && !matches!(parts.method, Method::GET | Method::HEAD);
    let slot = Arc::new(BodySlot::new(raw, &parts.headers));
    let (job, reply) = Job::request(
        parts.method.to_string(),
        url.to_string(),
        to_pairs(&parts.headers),
        exposes.then(|| Arc::clone(&slot)),
    );
    let encoding = parts.headers.get(header::CONTENT_ENCODING).cloned();
    let head = parts.method == Method::HEAD;
    let outcome = ctx.run_hook(job, reply).await;
    if forwards_original(&outcome) && slot.failed().await {
        tracing::warn!("request body could not be read or decoded; rejecting the request");
        let message = "request body could not be read or decoded";
        return Err(Box::new(text(StatusCode::BAD_REQUEST, message)));
    }
    if forwards_original(&outcome) && slot.lost().await {
        return Err(Box::new(lost_body("onRequest", "request")));
    }
    let error = match outcome {
        Outcome::Continue(msg) => {
            match outgoing_from(msg, &parts.headers, &slot, encoding.as_ref(), record).await {
                Ok(sent) => return Ok(sent),
                Err(e) => format!("onRequest returned an unusable request: {e}"),
            }
        }
        Outcome::Respond(msg) => {
            return Err(Box::new(
                response_from(msg, None, Pending::Slot(slot), encoding.as_ref(), head).await,
            ));
        }
        Outcome::Failed(e) => format!("onRequest failed: {e}"),
    };
    tracing::warn!("{error}; passing the request through");
    let out = original(parts, url, Pending::Slot(Arc::clone(&slot))).await;
    Ok((out, SentBody::Slot(slot)))
}

/// Takes the client's side of a protocol upgrade (such as WebSocket) and the protocol asked for.
fn take_upgrade(parts: &mut http::request::Parts) -> Option<(HeaderValue, OnUpgrade)> {
    let asks = parts
        .headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    let protocol = parts.headers.get(header::UPGRADE)?.clone();
    if !asks {
        return None;
    }
    Some((protocol, parts.extensions.remove::<OnUpgrade>()?))
}

/// Relays bytes between client and upstream once the upstream agreed to switch protocols.
fn switch_protocols(downstream: OnUpgrade, mut res: Response<Incoming>) -> Response<Body> {
    let upstream = hyper::upgrade::on(&mut res);
    tokio::spawn(async move {
        match tokio::try_join!(downstream, upstream) {
            Ok((client, server)) => {
                let (mut client, mut server) = (TokioIo::new(client), TokioIo::new(server));
                if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut server).await {
                    tracing::debug!("upgraded connection ended: {e}");
                }
            }
            Err(e) => tracing::debug!("protocol upgrade failed: {e}"),
        }
    });
    let (parts, _) = res.into_parts();
    Response::from_parts(parts, body::empty())
}

async fn send_upstream(
    client: &UpstreamClient,
    outgoing: Outgoing,
    listen: SocketAddr,
) -> Result<Response<Incoming>, Box<Response<Body>>> {
    let target = outgoing.url.to_string();
    if targets_self(&outgoing.url, listen) {
        let message = format!("refusing to proxy {target} to roxy itself");
        tracing::warn!("{message}");
        return Err(Box::new(text(StatusCode::LOOP_DETECTED, &message)));
    }
    let mut upstream = Request::new(outgoing.body);
    *upstream.method_mut() = outgoing.method;
    *upstream.uri_mut() = outgoing.url;
    // The client upgrades to HTTP/2 itself when ALPN picks it.
    *upstream.version_mut() = Version::HTTP_11;
    *upstream.headers_mut() = outgoing.headers;
    client.request(upstream).await.map_err(|e| {
        let cause = std::error::Error::source(&e).map_or_else(String::new, |s| format!(": {s}"));
        tracing::warn!("upstream request to {target} failed: {e}{cause}");
        Box::new(text(
            StatusCode::BAD_GATEWAY,
            &format!("upstream request failed: {e}{cause}"),
        ))
    })
}

/// Runs `onResponse` on a final upstream response.
async fn response_phase(
    ctx: &Ctx,
    mut request: RequestView,
    sent: SentBody,
    method: &Method,
    res: Response<Incoming>,
) -> Response<Body> {
    let (mut parts, incoming) = res.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    let raw = body::from_incoming(incoming);
    if parts.status.is_informational() {
        return Response::from_parts(parts, raw);
    }
    let sent = match sent {
        SentBody::Hidden => None,
        SentBody::Slot(slot) => slot.complete_bytes().await.map(body::full),
        SentBody::Copy(copy) => copy.into_body(),
    };
    request.body = sent.map(|body| Arc::new(BodySlot::new(body, &HeaderMap::new())));
    let exposes = !raw.is_end_stream() && !has_null_body(parts.status) && method != Method::HEAD;
    // A byte range of an encoded body cannot be decoded on its own, so hooks read it raw.
    let partial = parts.status == StatusCode::PARTIAL_CONTENT;
    let codings = if partial {
        &HeaderMap::new()
    } else {
        &parts.headers
    };
    let slot = Arc::new(BodySlot::new(raw, codings));
    let (job, reply) = Job::response(
        parts.status.as_u16(),
        to_pairs(&parts.headers),
        exposes.then(|| Arc::clone(&slot)),
        request,
    );
    let encoding = parts.headers.get(header::CONTENT_ENCODING).cloned();
    let outcome = ctx.run_hook(job, reply).await;
    if forwards_original(&outcome) && slot.failed().await {
        tracing::warn!("upstream response body could not be read or decoded");
        let message = "upstream response body could not be read or decoded";
        return text(StatusCode::BAD_GATEWAY, message);
    }
    if forwards_original(&outcome) && slot.lost().await {
        return lost_body("onResponse", "response");
    }
    let error = match outcome {
        Outcome::Respond(msg) => {
            let head = method == Method::HEAD;
            let given = Some(&parts.headers);
            return response_from(msg, given, Pending::Slot(slot), encoding.as_ref(), head).await;
        }
        Outcome::Continue(_) => "onResponse returned a request".to_owned(),
        Outcome::Failed(e) => format!("onResponse failed: {e}"),
    };
    tracing::warn!("{error}; passing the response through");
    rebuild(parts, Pending::Slot(slot)).await
}

/// Whether handling `outcome` forwards the proxied body, which needs it to be intact.
const fn forwards_original(outcome: &Outcome) -> bool {
    match outcome {
        Outcome::Continue(msg) | Outcome::Respond(msg) => matches!(msg.body, BodyOut::Original),
        Outcome::Failed(_) => true,
    }
}

async fn original(parts: http::request::Parts, url: Uri, body: Pending) -> Outgoing {
    let mut headers = parts.headers;
    let body = pending_body(body, &mut headers).await;
    Outgoing {
        method: parts.method,
        url,
        headers,
        body,
    }
}

async fn rebuild(mut parts: http::response::Parts, body: Pending) -> Response<Body> {
    let body = pending_body(body, &mut parts.headers).await;
    Response::from_parts(parts, body)
}

async fn outgoing_from(
    msg: HookMessage,
    given: &HeaderMap,
    slot: &Arc<BodySlot>,
    encoding: Option<&HeaderValue>,
    record: bool,
) -> Result<(Outgoing, SentBody), String> {
    let method = msg
        .method
        .as_deref()
        .ok_or("missing method")?
        .parse::<Method>()
        .map_err(|e| e.to_string())?;
    let url = msg
        .url
        .as_deref()
        .ok_or("missing url")?
        .parse::<Uri>()
        .map_err(|e| e.to_string())?;
    if !matches!(url.scheme_str(), Some("http" | "https")) {
        return Err(format!("unsupported URL scheme in {url}"));
    }
    let mut headers = restore_layout(&from_pairs(&msg.headers), given);
    strip_hop_by_hop(&mut headers);
    hdrs::remove(&mut headers, &header::HOST);
    let built = match &msg.body {
        BodyOut::Stream { length, .. } => Some(*length),
        _ => None,
    };
    let original = matches!(msg.body, BodyOut::Original);
    let body = resolve_body(
        msg.body,
        Pending::Slot(Arc::clone(slot)),
        encoding,
        &mut headers,
    )
    .await;
    let (body, sent) = if let (Some(length), true) = (built, record) {
        let (body, copy) = body::tee(body, length);
        (body, SentBody::Copy(copy))
    } else if original {
        (body, SentBody::Slot(Arc::clone(slot)))
    } else {
        (body, SentBody::Hidden)
    };
    let out = Outgoing {
        method,
        url,
        headers,
        body,
    };
    Ok((out, sent))
}

/// `given` is the response the hook was handed, if any, whose header layout is kept.
async fn response_from(
    msg: HookMessage,
    given: Option<&HeaderMap>,
    original: Pending,
    encoding: Option<&HeaderValue>,
    head: bool,
) -> Response<Body> {
    let status = status_from(msg.status);
    let mut headers = from_pairs(&msg.headers);
    if let Some(given) = given {
        headers = restore_layout(&headers, given);
    }
    strip_hop_by_hop(&mut headers);
    let mut choice = msg.body;
    if (head || has_null_body(status)) && !matches!(choice, BodyOut::Original) {
        choice = BodyOut::Empty;
    }
    let body = resolve_body(choice, original, encoding, &mut headers).await;
    let mut res = Response::new(body);
    *res.status_mut() = status;
    *res.headers_mut() = headers;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_bad_statuses() {
        assert_eq!(status_from(Some(201.0)), StatusCode::CREATED);
        assert_eq!(status_from(Some(0.0)), StatusCode::BAD_GATEWAY);
        assert_eq!(status_from(Some(1000.0)), StatusCode::BAD_GATEWAY);
        assert_eq!(status_from(Some(150.0)), StatusCode::BAD_GATEWAY);
        assert_eq!(status_from(Some(200.5)), StatusCode::BAD_GATEWAY);
        assert_eq!(status_from(None), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn detects_urls_aimed_at_roxy_itself() {
        let listen: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let aimed = |url: &str| targets_self(&url.parse().unwrap(), listen);
        assert!(aimed("http://localhost:8080/v1/models"));
        assert!(aimed("http://LocalHost:8080/"));
        assert!(aimed("https://127.0.0.1:8080/"));
        assert!(!aimed("http://localhost:8081/"));
        assert!(!aimed("http://localhost/"));
        assert!(!aimed("http://[::1]:8080/"));
        assert!(!aimed("http://example.com:8080/"));
        let listen: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(targets_self(&"http://localhost/".parse().unwrap(), listen));
        assert!(!targets_self(
            &"https://localhost/".parse().unwrap(),
            listen
        ));
    }

    #[test]
    fn tunnel_urls_prefer_request_authority() {
        let origin = Origin::Tunnel {
            scheme: "https",
            authority: "example.com:443".parse().unwrap(),
        };
        let (parts, ()) = Request::builder()
            .uri("/a?b=1")
            .body(())
            .unwrap()
            .into_parts();
        assert_eq!(
            target_url(&origin, &parts).unwrap().to_string(),
            "https://example.com/a?b=1"
        );
        let (parts, ()) = Request::builder()
            .uri("/x")
            .header("host", "other.test")
            .body(())
            .unwrap()
            .into_parts();
        assert_eq!(
            target_url(&origin, &parts).unwrap().to_string(),
            "https://other.test/x"
        );
        let (parts, ()) = Request::builder().uri("/x").body(()).unwrap().into_parts();
        assert!(target_url(&Origin::Forward, &parts).is_err());
    }
}
