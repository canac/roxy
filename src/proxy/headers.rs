//! Header conversions between hyper and the script, plus hop-by-hop cleanup.

use http::header::{self, HeaderMap, HeaderName, HeaderValue};

use crate::engine::HeaderPairs;

const HOP_BY_HOP: [&str; 7] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "upgrade",
];

/// Removes headers that describe a single connection rather than the message.
/// `TE: trailers` is kept, since gRPC servers require it end to end.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let trailers = headers
        .get_all(header::TE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("trailers"));
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    retain(headers, |name| {
        !listed.contains(name)
            && !HOP_BY_HOP.contains(&name.as_str())
            && name != header::TRANSFER_ENCODING
    });
    if trailers {
        headers.insert(header::TE, HeaderValue::from_static("trailers"));
    }
}

/// Keeps only the headers whose name passes `keep`, in their original order.
pub fn retain(headers: &mut HeaderMap, mut keep: impl FnMut(&HeaderName) -> bool) {
    if headers.keys().all(&mut keep) {
        return;
    }
    let mut name = None;
    for (next, value) in std::mem::take(headers) {
        if next.is_some() {
            name = next;
        }
        if let Some(name) = name.as_ref().filter(|n| keep(n)) {
            headers.append(name.clone(), value);
        }
    }
}

/// Removes `name` without reordering the other headers, as `HeaderMap::remove` does.
pub fn remove(headers: &mut HeaderMap, name: &HeaderName) {
    if headers.contains_key(name) {
        retain(headers, |n| n != name);
    }
}

/// Lays out headers a hook returned like the `original` ones: names keep their original
/// order, and a value equal to the original values joined by `", "` (which is what the
/// script's `Headers` does to repeated headers) is split back into those values.
#[must_use]
pub fn restore_layout(returned: &HeaderMap, original: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(returned.len());
    for name in original.keys().chain(returned.keys()) {
        if out.contains_key(name) || !returned.contains_key(name) {
            continue;
        }
        let values: Vec<&HeaderValue> = returned.get_all(name).iter().collect();
        let before: Vec<&HeaderValue> = original.get_all(name).iter().collect();
        let joined = before
            .iter()
            .map(|v| v.as_bytes())
            .collect::<Vec<_>>()
            .join(&b", "[..]);
        let unchanged = before.len() > 1 && values.len() == 1 && values[0].as_bytes() == joined;
        let kept = if unchanged { before } else { values };
        for value in kept {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

/// Joins `Cookie` fields into one, as HTTP/2 clients split them but HTTP/1.1 servers and
/// the script's `Headers` (which joins with `", "`) expect a single `"; "`-separated value.
pub fn join_cookies(headers: &mut HeaderMap) {
    let values: Vec<&[u8]> = headers
        .get_all(header::COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    if values.len() < 2 {
        return;
    }
    if let Ok(joined) = HeaderValue::from_bytes(&values.join(&b"; "[..])) {
        headers.insert(header::COOKIE, joined);
    }
}

/// Header values are byte strings; map each byte to the char with the same code point.
pub fn to_pairs(headers: &HeaderMap) -> HeaderPairs {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.as_bytes().iter().map(|&b| char::from(b)).collect(),
            )
        })
        .collect()
}

/// Inverse of [`to_pairs`]. Invalid entries are skipped with a warning.
pub fn from_pairs(pairs: &[(String, String)]) -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(pairs.len());
    for (name, value) in pairs {
        let bytes: Option<Vec<u8>> = value.chars().map(|c| u8::try_from(c).ok()).collect();
        let parsed = (
            HeaderName::from_bytes(name.as_bytes()),
            bytes.and_then(|b| HeaderValue::from_bytes(&b).ok()),
        );
        if let (Ok(name), Some(value)) = parsed {
            headers.append(name, value);
        } else {
            tracing::warn!("dropping invalid header from script: {name:?}");
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_connection_listed_and_standard_hop_headers() {
        let mut h = HeaderMap::new();
        h.insert("connection", "keep-alive, x-custom".parse().unwrap());
        h.insert("x-custom", "1".parse().unwrap());
        h.insert("keep-alive", "timeout=5".parse().unwrap());
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("x-keep", "1".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert!(h.contains_key("x-keep"));
    }

    fn names(h: &HeaderMap) -> Vec<&str> {
        h.keys().map(HeaderName::as_str).collect()
    }

    #[test]
    fn removal_keeps_order() {
        let mut h = HeaderMap::new();
        for name in ["host", "user-agent", "proxy-connection", "accept", "x-last"] {
            h.insert(name, "1".parse().unwrap());
        }
        strip_hop_by_hop(&mut h);
        remove(&mut h, &header::HOST);
        assert_eq!(names(&h), ["user-agent", "accept", "x-last"]);
    }

    #[test]
    fn restores_order_and_split_values() {
        let mut original = HeaderMap::new();
        original.insert("user-agent", "ua".parse().unwrap());
        original.append("link", "<a>".parse().unwrap());
        original.append("link", "<b>".parse().unwrap());
        original.insert("accept", "*/*".parse().unwrap());
        let mut returned = HeaderMap::new();
        returned.insert("accept", "*/*".parse().unwrap());
        returned.insert("link", "<a>, <b>".parse().unwrap());
        returned.insert("x-added", "1".parse().unwrap());
        returned.insert("user-agent", "changed".parse().unwrap());
        let out = restore_layout(&returned, &original);
        assert_eq!(names(&out), ["user-agent", "link", "accept", "x-added"]);
        assert_eq!(out["user-agent"], "changed");
        let links: Vec<_> = out.get_all("link").iter().collect();
        assert_eq!(links, ["<a>", "<b>"]);
    }

    #[test]
    fn joins_split_cookies() {
        let mut h = HeaderMap::new();
        h.append("cookie", "a=1".parse().unwrap());
        h.append("cookie", "b=2".parse().unwrap());
        join_cookies(&mut h);
        assert_eq!(h.get_all("cookie").iter().count(), 1);
        assert_eq!(h["cookie"], "a=1; b=2");
    }

    #[test]
    fn keeps_te_trailers_and_trailer() {
        let mut h = HeaderMap::new();
        h.insert("connection", "te".parse().unwrap());
        h.insert("te", "gzip, trailers".parse().unwrap());
        h.insert("trailer", "grpc-status".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert_eq!(h["te"], "trailers");
        assert_eq!(h["trailer"], "grpc-status");

        let mut h = HeaderMap::new();
        h.insert("te", "gzip".parse().unwrap());
        strip_hop_by_hop(&mut h);
        assert!(h.is_empty());
    }

    #[test]
    fn latin1_round_trip_and_invalid_skipped() {
        let mut h = HeaderMap::new();
        h.append("set-cookie", "a=1".parse().unwrap());
        h.append("set-cookie", "b=2".parse().unwrap());
        h.insert("x-bin", HeaderValue::from_bytes(b"caf\xe9").unwrap());
        let pairs = to_pairs(&h);
        assert!(pairs.contains(&("x-bin".to_owned(), "café".to_owned())));
        assert_eq!(from_pairs(&pairs), h);

        let bad = vec![
            ("bad name".to_owned(), "v".to_owned()),
            ("x-emoji".to_owned(), "😀".to_owned()),
        ];
        assert!(from_pairs(&bad).is_empty());
    }
}
