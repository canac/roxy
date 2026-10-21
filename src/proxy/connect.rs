//! CONNECT tunnels: intercept TLS (h1 or h2 via ALPN) or plain HTTP, else relay bytes.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::ServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

use super::handler::{Ctx, Origin, handle as handle_request};
use crate::body::{self, Body};
use crate::ca::CertificateAuthority;

const TLS_HANDSHAKE: u8 = 0x16;

pub fn handle(ctx: Arc<Ctx>, req: Request<Incoming>) -> Response<Body> {
    let Some(authority) = req.uri().authority().cloned() else {
        let mut res = Response::new(body::full("CONNECT needs a host:port target\n"));
        *res.status_mut() = StatusCode::BAD_REQUEST;
        return res;
    };
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = tunnel(ctx, TokioIo::new(upgraded), authority.clone()).await {
                    tracing::debug!("tunnel to {authority} ended: {e}");
                }
            }
            Err(e) => tracing::debug!("CONNECT upgrade to {authority} failed: {e}"),
        }
    });
    Response::new(body::empty())
}

async fn tunnel<T>(ctx: Arc<Ctx>, mut io: T, authority: http::uri::Authority) -> io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut first = [0u8; 1];
    if io.read(&mut first).await? == 0 {
        return Ok(());
    }
    let io = Rewind::new(Bytes::copy_from_slice(&first), io);
    if first[0] == TLS_HANDSHAKE {
        let config = server_config(Arc::clone(&ctx.ca), authority.host().to_owned());
        let tls = TlsAcceptor::from(config).accept(io).await?;
        serve(
            ctx,
            tls,
            Origin::Tunnel {
                scheme: "https",
                authority,
            },
        )
        .await;
    } else if first[0].is_ascii_uppercase() {
        serve(
            ctx,
            io,
            Origin::Tunnel {
                scheme: "http",
                authority,
            },
        )
        .await;
    } else {
        let mut io = io;
        let mut upstream = TcpStream::connect(authority.as_str()).await?;
        tokio::io::copy_bidirectional(&mut io, &mut upstream).await?;
    }
    Ok(())
}

/// Serves HTTP/1.1 or HTTP/2 on `io`, sending each request through the hooks.
pub async fn serve<T>(ctx: Arc<Ctx>, io: T, origin: Origin)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| handle_request(Arc::clone(&ctx), origin.clone(), req));
    let builder = auto::Builder::new(TokioExecutor::new());
    if let Err(e) = builder
        .serve_connection_with_upgrades(TokioIo::new(io), service)
        .await
    {
        tracing::debug!("client connection ended: {e}");
    }
}

fn server_config(ca: Arc<CertificateAuthority>, fallback_host: String) -> Arc<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(LeafResolver { ca, fallback_host }));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

#[derive(Debug)]
struct LeafResolver {
    ca: Arc<CertificateAuthority>,
    fallback_host: String,
}

impl ResolvesServerCert for LeafResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = hello.server_name().unwrap_or(&self.fallback_host);
        self.ca
            .leaf_for(host)
            .map_err(|e| tracing::warn!("cannot mint certificate for {host}: {e:#}"))
            .ok()
    }
}

/// Replays bytes already read from `inner` before reading from it again.
struct Rewind<T> {
    prefix: Bytes,
    inner: T,
}

impl<T> Rewind<T> {
    const fn new(prefix: Bytes, inner: T) -> Self {
        Self { prefix, inner }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Rewind<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let chunk = self.prefix.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Rewind<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn rewind_replays_prefix() {
        let (mut a, b) = tokio::io::duplex(64);
        tokio::io::AsyncWriteExt::write_all(&mut a, b"llo")
            .await
            .unwrap();
        drop(a);
        let mut r = Rewind::new(Bytes::from_static(b"he"), b);
        let mut out = String::new();
        r.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "hello");
    }
}
