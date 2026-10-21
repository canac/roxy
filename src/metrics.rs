//! Process-lifetime counters and their periodic log line.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, Default)]
pub struct Metrics {
    requests: AtomicU64,
    responses: AtomicU64,
    overhead_nanos: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub requests: u64,
    pub responses: u64,
    pub overhead: Duration,
}

impl std::fmt::Display for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "requests={} responses={} hook_overhead={:.3}ms",
            self.requests,
            self.responses,
            self.overhead.as_secs_f64() * 1000.0
        )
    }
}

impl Metrics {
    pub fn record_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_response(&self) {
        self.responses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_overhead(&self, elapsed: Duration) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        self.overhead_nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            requests: self.requests.load(Ordering::Relaxed),
            responses: self.responses.load(Ordering::Relaxed),
            overhead: Duration::from_nanos(self.overhead_nanos.load(Ordering::Relaxed)),
        }
    }

    /// Calls `report` every `interval`, skipping intervals with no new traffic.
    pub async fn report_periodically(&self, interval: Duration, mut report: impl FnMut(Snapshot)) {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        let mut last = self.snapshot();
        loop {
            ticker.tick().await;
            let now = self.snapshot();
            if now != last {
                report(now);
                last = now;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn idle_intervals_stay_quiet() {
        let metrics = Arc::new(Metrics::default());
        let reports = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let (metrics, reports) = (Arc::clone(&metrics), Arc::clone(&reports));
            async move {
                metrics
                    .report_periodically(Duration::from_secs(60), |s| {
                        reports.lock().unwrap().push(s.requests);
                    })
                    .await;
            }
        });
        tokio::time::sleep(Duration::from_secs(150)).await;
        assert!(reports.lock().unwrap().is_empty());
        metrics.record_request();
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert_eq!(*reports.lock().unwrap(), [1]);
        tokio::time::sleep(Duration::from_secs(300)).await;
        assert_eq!(*reports.lock().unwrap(), [1]);
        task.abort();
    }

    #[test]
    fn counts_accumulate() {
        let m = Metrics::default();
        m.record_request();
        m.record_request();
        m.record_response();
        m.add_overhead(Duration::from_millis(3));
        m.add_overhead(Duration::from_millis(2));
        let s = m.snapshot();
        assert_eq!(s.requests, 2);
        assert_eq!(s.responses, 1);
        assert_eq!(s.overhead, Duration::from_millis(5));
        assert_eq!(
            s.to_string(),
            "requests=2 responses=1 hook_overhead=5.000ms"
        );
    }
}
