//! Body plumbing: a lazily-read body slot shared between the proxy and the JS hooks.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use async_compression::tokio::bufread::{
    BrotliDecoder, DeflateDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder,
};
use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt as _, TryStreamExt as _};
use http::HeaderMap;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty, Full, StreamBody};
use tokio::io::{AsyncBufRead, AsyncRead, BufReader, ReadBuf};
use tokio::sync::{Mutex, watch};
use tokio_util::io::{ReaderStream, StreamReader};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type Body = UnsyncBoxBody<Bytes, BoxError>;
type ByteStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;

/// The most bytes of one body roxy keeps for a second look: what hooks read from a
/// [`BodySlot`], or a [`BodyCopy`] of a script-built request body.
pub const RETAIN_LIMIT: usize = 4 * 1024 * 1024;

#[must_use]
pub fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed_unsync()
}

#[must_use]
pub fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub fn from_stream<S, E>(stream: S) -> Body
where
    S: Stream<Item = Result<Bytes, E>> + Send + 'static,
    E: Into<BoxError> + 'static,
{
    StreamBody::new(stream.map_ok(http_body::Frame::data).map_err(Into::into)).boxed_unsync()
}

pub fn from_incoming<B>(body: B) -> Body
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed_unsync()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Gzip,
    Zlib,
    Brotli,
    Zstd,
}

/// Parses `Content-Encoding`, returning codings in the order they were applied.
/// `None` means some coding is unknown, so the body cannot be decoded.
fn parse_codings(headers: &HeaderMap) -> Option<Vec<Coding>> {
    let mut codings = Vec::new();
    for value in headers.get_all(http::header::CONTENT_ENCODING) {
        for token in value.to_str().ok()?.split(',') {
            match token.trim().to_ascii_lowercase().as_str() {
                "" | "identity" => {}
                "gzip" | "x-gzip" => codings.push(Coding::Gzip),
                "deflate" => codings.push(Coding::Zlib),
                "br" => codings.push(Coding::Brotli),
                "zstd" => codings.push(Coding::Zstd),
                _ => return None,
            }
        }
    }
    Some(codings)
}

fn decode(raw: Body, codings: &[Coding]) -> ByteStream {
    let data = raw
        .into_data_stream()
        .map_err(|e| io::Error::other(e.to_string()));
    if codings.is_empty() {
        return Box::pin(data);
    }
    let mut reader: Pin<Box<dyn AsyncRead + Send>> = Box::pin(StreamReader::new(data));
    // Codings are listed in application order, so undo them from last to first.
    for coding in codings.iter().rev() {
        let buffered = BufReader::new(reader);
        reader = match coding {
            Coding::Gzip => Box::pin(multi_member(GzipDecoder::new(buffered))),
            Coding::Zlib => Box::pin(Deflate::Sniffing(Some(buffered))),
            Coding::Brotli => Box::pin(BrotliDecoder::new(buffered)),
            Coding::Zstd => Box::pin(ZstdDecoder::new(buffered)),
        };
    }
    Box::pin(ReaderStream::new(reader))
}

/// Decodes `deflate`, which servers send either zlib-wrapped (as specified) or raw.
enum Deflate<R> {
    Sniffing(Option<R>),
    Zlib(ZlibDecoder<R>),
    Raw(DeflateDecoder<R>),
}

/// Whether `head` starts with a zlib header: deflate method and a valid check value.
fn is_zlib(head: &[u8]) -> bool {
    match head {
        [cmf, flg, ..] => cmf & 0x0f == 8 && (u16::from(*cmf) << 8 | u16::from(*flg)) % 31 == 0,
        [cmf] => cmf & 0x0f == 8,
        [] => true,
    }
}

impl<R: AsyncBufRead + Unpin> AsyncRead for Deflate<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match &mut *self {
                Self::Sniffing(inner) => {
                    let reader = inner.as_mut().expect("set until sniffed");
                    let zlib = is_zlib(ready!(Pin::new(reader).poll_fill_buf(cx))?);
                    let reader = inner.take().expect("set until sniffed");
                    *self = if zlib {
                        Self::Zlib(ZlibDecoder::new(reader))
                    } else {
                        Self::Raw(DeflateDecoder::new(reader))
                    };
                }
                Self::Zlib(decoder) => return Pin::new(decoder).poll_read(cx, buf),
                Self::Raw(decoder) => return Pin::new(decoder).poll_read(cx, buf),
            }
        }
    }
}

fn multi_member<R: AsyncBufRead>(mut decoder: GzipDecoder<R>) -> GzipDecoder<R> {
    decoder.multiple_members(true);
    decoder
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Complete,
    Failed,
}

#[derive(Default)]
struct SlotState {
    raw: Option<Body>,
    codings: Option<Vec<Coding>>,
    decoded: Option<ByteStream>,
    delivered: Vec<Bytes>,
    retained: usize,
    /// `delivered` was discarded, so a read body can no longer be forwarded.
    dropped: bool,
    touched: bool,
    ended: Option<Ended>,
    taken: bool,
}

impl SlotState {
    fn retain(&mut self, chunk: &Bytes) {
        if self.dropped {
            return;
        }
        self.retained += chunk.len();
        if self.retained > RETAIN_LIMIT {
            self.discard();
        } else {
            self.delivered.push(chunk.clone());
        }
    }

    fn discard(&mut self) {
        self.dropped = true;
        self.delivered = Vec::new();
    }
}

fn concat(chunks: &[Bytes]) -> Bytes {
    let mut buf = BytesMut::with_capacity(chunks.iter().map(Bytes::len).sum());
    for chunk in chunks {
        buf.extend_from_slice(chunk);
    }
    buf.freeze()
}

fn lost_body() -> Body {
    let error = io::Error::other("body was read past the retain limit and cannot be forwarded");
    from_stream(futures::stream::once(async move { Err::<Bytes, _>(error) }))
}

/// A message body that stays untouched until a hook reads it.
///
/// Reads yield decoded bytes. The first [`RETAIN_LIMIT`] bytes read are remembered, so
/// the body can still be forwarded (decoded) after a hook consumed part or all of it.
/// Once reads pass the limit, or [`BodySlot::stop_retaining`] is called, nothing is
/// remembered: the read body is [`lost`](BodySlot::lost) and can no longer be forwarded.
pub struct BodySlot {
    state: Mutex<SlotState>,
}

impl std::fmt::Debug for BodySlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodySlot").finish_non_exhaustive()
    }
}

/// The body to forward once hooks are done, plus whether it was decoded on the way.
pub struct Forward {
    pub body: Body,
    pub decoded: bool,
    /// The exact length, known when a hook read the whole body.
    pub length: Option<u64>,
}

impl BodySlot {
    #[must_use]
    pub fn new(raw: Body, headers: &HeaderMap) -> Self {
        Self {
            state: Mutex::new(SlotState {
                raw: Some(raw),
                codings: parse_codings(headers),
                ..SlotState::default()
            }),
        }
    }

    /// Reads the next decoded chunk, or `None` at the end of the body.
    ///
    /// # Errors
    /// Fails when the body was already forwarded or the upstream stream errored.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the lock guards the stream being polled"
    )]
    pub async fn read_chunk(&self) -> io::Result<Option<Bytes>> {
        let mut state = self.state.lock().await;
        if state.taken {
            return Err(io::Error::other("body was already forwarded"));
        }
        if state.ended == Some(Ended::Complete) {
            return Ok(None);
        }
        state.touched = true;
        if state.decoded.is_none() {
            let raw = state.raw.take().unwrap_or_else(empty);
            let codings = state.codings.clone().unwrap_or_default();
            state.decoded = Some(decode(raw, &codings));
        }
        loop {
            let Some(stream) = state.decoded.as_mut() else {
                return Ok(None);
            };
            match stream.next().await {
                Some(Ok(chunk)) if chunk.is_empty() => {}
                Some(Ok(chunk)) => {
                    state.retain(&chunk);
                    return Ok(Some(chunk));
                }
                Some(Err(e)) => {
                    state.ended = Some(Ended::Failed);
                    return Err(e);
                }
                None => {
                    state.ended = Some(Ended::Complete);
                    state.decoded = None;
                    return Ok(None);
                }
            }
        }
    }

    /// Whether any hook has started reading this body.
    pub async fn touched(&self) -> bool {
        self.state.lock().await.touched
    }

    /// Whether reading failed, so the body can no longer be forwarded intact.
    pub async fn failed(&self) -> bool {
        self.state.lock().await.ended == Some(Ended::Failed)
    }

    /// Whether hooks read bytes that were not retained, so the body can no longer be forwarded.
    pub async fn lost(&self) -> bool {
        let state = self.state.lock().await;
        state.touched && state.dropped
    }

    /// Stops remembering reads, for a body the hook took over and will never be forwarded.
    pub async fn stop_retaining(&self) {
        self.state.lock().await.discard();
    }

    /// The whole decoded body, if a hook read it to the end and it was retained.
    pub async fn complete_bytes(&self) -> Option<Bytes> {
        let delivered = {
            let state = self.state.lock().await;
            if state.ended != Some(Ended::Complete) || state.dropped {
                return None;
            }
            state.delivered.clone()
        };
        Some(concat(&delivered))
    }

    /// Takes the body for forwarding: the original bytes if untouched, otherwise
    /// what hooks already read followed by the rest of the decoded stream.
    /// A [`lost`](Self::lost) body yields an error instead of forwarding a truncated one.
    pub async fn take(&self) -> Forward {
        let mut state = self.state.lock().await;
        state.taken = true;
        if !state.touched {
            return Forward {
                body: state.raw.take().unwrap_or_else(empty),
                decoded: false,
                length: None,
            };
        }
        let decoded = state.codings.as_ref().is_some_and(|c| !c.is_empty());
        if state.dropped {
            return Forward {
                body: lost_body(),
                decoded,
                length: None,
            };
        }
        let length = state
            .ended
            .is_some_and(|e| e == Ended::Complete)
            .then(|| state.delivered.iter().map(|c| c.len() as u64).sum());
        let prefix = futures::stream::iter(state.delivered.clone().into_iter().map(Ok));
        let rest = state.decoded.take();
        drop(state);
        let body = match rest {
            Some(rest) => from_stream(prefix.chain(rest)),
            None => from_stream::<_, io::Error>(prefix),
        };
        Forward {
            body,
            decoded,
            length,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Copied {
    Complete,
    Dropped,
}

struct Recording {
    chunks: Vec<Bytes>,
    size: u64,
    length: Option<u64>,
    ended: Option<Copied>,
}

impl Recording {
    fn record(&mut self, item: Option<&Result<Bytes, BoxError>>) {
        if self.ended.is_some() {
            return;
        }
        match item {
            Some(Ok(chunk)) => {
                self.size += chunk.len() as u64;
                if self.size > RETAIN_LIMIT as u64 {
                    self.ended = Some(Copied::Dropped);
                    self.chunks = Vec::new();
                    return;
                }
                self.chunks.push(chunk.clone());
                // hyper stops polling a sized body once it has sent `length` bytes.
                if self.length == Some(self.size) {
                    self.ended = Some(Copied::Complete);
                }
            }
            Some(Err(_)) => {
                self.ended = Some(Copied::Dropped);
                self.chunks = Vec::new();
            }
            None => self.ended = Some(Copied::Complete),
        }
    }
}

/// A copy of a forwarded body, kept only while it fits in [`RETAIN_LIMIT`].
pub struct BodyCopy(watch::Receiver<Recording>);

impl BodyCopy {
    /// The copied body, or `None` if it already outgrew the limit or the forwarded body failed.
    ///
    /// A copy still being forwarded is returned as a body that waits for the forward to
    /// finish, then yields the bytes or, if the copy was dropped or the forward stopped
    /// short, an error.
    #[must_use]
    pub fn into_body(mut self) -> Option<Body> {
        let ended = self.0.borrow().ended;
        match ended {
            Some(Copied::Complete) => Some(full(concat(&self.0.borrow().chunks))),
            Some(Copied::Dropped) => None,
            None => Some(from_stream(futures::stream::once(async move {
                let copied = self
                    .0
                    .wait_for(|r| r.ended.is_some())
                    .await
                    .ok()
                    .and_then(|r| (r.ended == Some(Copied::Complete)).then(|| concat(&r.chunks)));
                copied.ok_or_else(|| io::Error::other("the body copy was dropped"))
            }))),
        }
    }
}

/// Forwards `body`, whose size is `length` when known, while recording a [`BodyCopy`] of it.
/// Recording never holds back the forward.
#[must_use]
pub fn tee(body: Body, length: Option<u64>) -> (Body, BodyCopy) {
    let (tx, rx) = watch::channel(Recording {
        chunks: Vec::new(),
        size: 0,
        length,
        ended: (length == Some(0)).then_some(Copied::Complete),
    });
    // Ending the unfold drops `tx`, which ends the copy even if hyper keeps the body around.
    let state = (body.into_data_stream(), tx);
    let forwarded = futures::stream::unfold(state, |(mut stream, tx)| async move {
        let item = stream.next().await;
        tx.send_modify(|r| r.record(item.as_ref()));
        Some((item?, (stream, tx)))
    });
    (from_stream(forwarded), BodyCopy(rx))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn headers(encoding: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::CONTENT_ENCODING, encoding.parse().unwrap());
        h
    }

    async fn collect(body: Body) -> Vec<u8> {
        body.collect().await.unwrap().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn untouched_body_passes_through_encoded() {
        let encoded = gzip(b"hello");
        let slot = BodySlot::new(full(encoded.clone()), &headers("gzip"));
        assert!(!slot.touched().await);
        let fwd = slot.take().await;
        assert!(!fwd.decoded);
        assert_eq!(collect(fwd.body).await, encoded);
    }

    #[tokio::test]
    async fn read_body_is_decoded_and_forwarded_decoded() {
        let slot = BodySlot::new(full(gzip(b"hello world")), &headers("gzip"));
        let mut read = Vec::new();
        while let Some(c) = slot.read_chunk().await.unwrap() {
            read.extend_from_slice(&c);
        }
        assert_eq!(read, b"hello world");
        assert_eq!(slot.complete_bytes().await.unwrap(), "hello world");
        let fwd = slot.take().await;
        assert!(fwd.decoded);
        assert_eq!(fwd.length, Some(11));
        assert_eq!(collect(fwd.body).await, b"hello world");
        assert!(slot.read_chunk().await.is_err());
    }

    #[tokio::test]
    async fn partially_read_body_forwards_prefix_and_rest() {
        let chunks = futures::stream::iter(vec![
            Ok::<_, io::Error>(Bytes::from_static(b"ab")),
            Ok(Bytes::from_static(b"cd")),
        ]);
        let slot = BodySlot::new(from_stream(chunks), &HeaderMap::new());
        assert_eq!(slot.read_chunk().await.unwrap().unwrap(), "ab");
        assert!(slot.complete_bytes().await.is_none());
        let fwd = slot.take().await;
        assert!(!fwd.decoded);
        assert_eq!(fwd.length, None);
        assert_eq!(collect(fwd.body).await, b"abcd");
    }

    #[tokio::test]
    async fn stacked_and_unknown_codings() {
        let mut zl = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zl.write_all(&gzip(b"layered")).unwrap();
        let slot = BodySlot::new(full(zl.finish().unwrap()), &headers("gzip, deflate"));
        assert_eq!(slot.read_chunk().await.unwrap().unwrap(), "layered");

        let slot = BodySlot::new(full("raw"), &headers("compress"));
        assert_eq!(slot.read_chunk().await.unwrap().unwrap(), "raw");
        assert!(!slot.take().await.decoded);
    }

    #[tokio::test]
    async fn deflate_accepts_zlib_and_raw_streams() {
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(b"wrapped").unwrap();
        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(b"raw").unwrap();
        for (encoded, plain) in [
            (zlib.finish().unwrap(), "wrapped"),
            (raw.finish().unwrap(), "raw"),
        ] {
            let slot = BodySlot::new(full(encoded), &headers("deflate"));
            assert_eq!(slot.read_chunk().await.unwrap().unwrap(), plain);
        }
    }

    fn chunked(total: usize) -> Body {
        let chunks = (0..total.div_ceil(64 * 1024)).map(move |i| {
            let len = (total - i * 64 * 1024).min(64 * 1024);
            Ok::<_, io::Error>(Bytes::from(vec![b'a' + u8::try_from(i % 26).unwrap(); len]))
        });
        from_stream(futures::stream::iter(chunks))
    }

    #[tokio::test]
    async fn reads_past_the_limit_are_dropped_and_the_body_is_lost() {
        let total = 2 * RETAIN_LIMIT + 7;
        let slot = BodySlot::new(chunked(total), &HeaderMap::new());
        let mut read = 0;
        while let Some(c) = slot.read_chunk().await.unwrap() {
            read += c.len();
            assert!(slot.state.lock().await.delivered.len() * 64 * 1024 <= RETAIN_LIMIT);
        }
        assert_eq!(read, total);
        assert_eq!(slot.state.lock().await.delivered.len(), 0);
        assert!(slot.lost().await);
        assert!(slot.complete_bytes().await.is_none());
        let fwd = slot.take().await;
        assert_eq!(fwd.length, None);
        assert!(fwd.body.collect().await.is_err());
    }

    #[tokio::test]
    async fn stop_retaining_frees_reads_but_keeps_an_unread_body() {
        let slot = BodySlot::new(chunked(10), &HeaderMap::new());
        slot.stop_retaining().await;
        assert!(!slot.lost().await);
        assert_eq!(collect(slot.take().await.body).await.len(), 10);

        let slot = BodySlot::new(chunked(10), &HeaderMap::new());
        slot.read_chunk().await.unwrap();
        slot.stop_retaining().await;
        assert_eq!(slot.state.lock().await.delivered.len(), 0);
        assert!(slot.lost().await);
    }

    fn tee_all(body: Body) -> (Body, BodyCopy) {
        tee(body, None)
    }

    #[tokio::test]
    async fn tee_copies_small_bodies_and_drops_big_ones() {
        let (fwd, copy) = tee_all(chunked(100));
        let sent = collect(fwd).await;
        assert_eq!(collect(copy.into_body().unwrap()).await, sent);

        let total = RETAIN_LIMIT + 1;
        let (fwd, copy) = tee_all(chunked(total));
        assert_eq!(collect(fwd).await, collect(chunked(total)).await);
        assert_eq!(copy.0.borrow().chunks.len(), 0);
        assert!(copy.into_body().is_none());
    }

    #[tokio::test]
    async fn in_flight_copy_waits_for_the_forward() {
        let (fwd, copy) = tee_all(chunked(100));
        let copy = copy.into_body().unwrap();
        let (sent, copied) = tokio::join!(collect(fwd), copy.collect());
        assert_eq!(copied.unwrap().to_bytes(), sent);

        let (fwd, copy) = tee_all(chunked(RETAIN_LIMIT + 1));
        let copy = copy.into_body().unwrap();
        let (_, copied) = tokio::join!(collect(fwd), copy.collect());
        assert!(copied.is_err());
    }

    #[tokio::test]
    async fn sized_copy_completes_at_its_length() {
        let (fwd, copy) = tee(chunked(100), Some(100));
        let mut frames = fwd.into_data_stream();
        assert_eq!(frames.next().await.unwrap().unwrap().len(), 100);
        drop(frames);
        assert_eq!(collect(copy.into_body().unwrap()).await.len(), 100);

        let (fwd, copy) = tee(chunked(200 * 1024), Some(200 * 1024));
        let copy = copy.into_body().unwrap();
        let mut frames = fwd.into_data_stream();
        frames.next().await.unwrap().unwrap();
        drop(frames);
        assert!(copy.collect().await.is_err());

        assert!(tee(empty(), Some(0)).1.into_body().is_some());
    }
}
