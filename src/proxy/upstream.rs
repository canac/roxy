//! Verified upstream client shared by all connections.

use std::sync::Arc;

use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;

use crate::body::Body;

pub type UpstreamClient = Client<HttpsConnector<HttpConnector>, Body>;

/// Mozilla's roots, the OS trust store, and any `extra` roots.
#[must_use]
pub fn root_store(extra: &[CertificateDer<'static>]) -> RootCertStore {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let native = rustls_native_certs::load_native_certs();
    for err in &native.errors {
        tracing::debug!("skipping OS root certificate: {err}");
    }
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    tracing::debug!(added, ignored, "loaded OS root certificates");
    for cert in extra {
        if let Err(e) = roots.add(cert.clone()) {
            tracing::warn!("ignoring extra root certificate: {e}");
        }
    }
    roots
}

/// A client that verifies upstream certificates against `roots` and speaks h1 or h2.
#[must_use]
pub fn client(roots: Arc<RootCertStore>) -> UpstreamClient {
    build(roots, false)
}

/// Like [`client`], but HTTP/1.1 only, as protocol upgrades such as WebSocket need.
#[must_use]
pub fn h1_client(roots: Arc<RootCertStore>) -> UpstreamClient {
    build(roots, true)
}

fn build(roots: Arc<RootCertStore>, h1_only: bool) -> UpstreamClient {
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_nodelay(true);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http();
    let https = if h1_only {
        https.enable_http1().wrap_connector(http)
    } else {
        https.enable_all_versions().wrap_connector(http)
    };
    Client::builder(TokioExecutor::new()).build(https)
}
