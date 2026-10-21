//! OS file-change notifications for the script and everything it imports.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context as _, Result};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};

pub struct FileWatcher {
    watcher: RecommendedWatcher,
    files: Arc<Mutex<HashSet<PathBuf>>>,
    dirs: HashSet<PathBuf>,
}

/// Resolves symlinked directories (e.g. macOS `/var` -> `/private/var`) while
/// tolerating files that no longer exist.
fn normalize(path: &Path) -> PathBuf {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return path.to_path_buf();
    };
    parent
        .canonicalize()
        .map_or_else(|_| path.to_path_buf(), |p| p.join(name))
}

impl FileWatcher {
    /// Creates a watcher that calls `on_change` whenever a watched file changes.
    ///
    /// # Errors
    /// Fails when the OS watcher cannot be created.
    pub fn new(on_change: impl Fn() + Send + 'static) -> Result<Self> {
        let files: Arc<Mutex<HashSet<PathBuf>>> = Arc::default();
        let tracked = Arc::clone(&files);
        let watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            let Ok(event) = event else { return };
            if matches!(event.kind, EventKind::Access(_)) {
                return;
            }
            let Ok(files) = tracked.lock() else { return };
            if event.paths.iter().any(|p| files.contains(&normalize(p))) {
                on_change();
            }
        })
        .context("creating file watcher")?;
        Ok(Self {
            watcher,
            files,
            dirs: HashSet::new(),
        })
    }

    /// Replaces the watched set. Directories are watched so atomic-rename saves are seen.
    pub fn set_files(&mut self, files: impl IntoIterator<Item = PathBuf>) {
        let files: HashSet<PathBuf> = files.into_iter().map(|f| normalize(&f)).collect();
        let dirs: HashSet<PathBuf> = files
            .iter()
            .filter_map(|f| f.parent().map(Path::to_path_buf))
            .collect();
        for dir in self.dirs.difference(&dirs) {
            let _ = self.watcher.unwatch(dir);
        }
        for dir in dirs.difference(&self.dirs) {
            if let Err(e) = self.watcher.watch(dir, RecursiveMode::NonRecursive) {
                tracing::warn!("cannot watch {}: {e}", dir.display());
            }
        }
        self.dirs = dirs;
        if let Ok(mut watched) = self.files.lock() {
            *watched = files;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn reports_changes_to_watched_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.js");
        let unrelated = dir.path().join("b.js");
        std::fs::write(&target, "1").unwrap();
        std::fs::write(&unrelated, "1").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = FileWatcher::new(move || {
            let _ = tx.send(());
        })
        .unwrap();
        watcher.set_files([target.clone()]);
        std::thread::sleep(Duration::from_millis(200));
        while rx.try_recv().is_ok() {}

        std::fs::write(&unrelated, "2").unwrap();
        assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
        std::fs::write(&target, "2").unwrap();
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
    }
}
