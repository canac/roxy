//! A status line pinned to the bottom row of the terminal, below the log output.

use std::io::{self, StdoutLock, Write};
use std::sync::{Mutex, MutexGuard, PoisonError};

use terminal_size::{Height, Width, terminal_size_of};
use tracing_subscriber::fmt::MakeWriter;

struct State {
    line: String,
    /// Terminal rows the scroll region was set for; 0 means no region is set.
    rows: u16,
    cols: u16,
}

static STATE: Mutex<State> = Mutex::new(State {
    line: String::new(),
    rows: 0,
    cols: 0,
});

fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

impl State {
    /// Keeps the scroll region one row short of the terminal so logs never reach the status row.
    fn sync(&mut self, out: &mut StdoutLock<'_>) {
        let Some((Width(cols), Height(rows))) = terminal_size_of(&*out) else {
            return;
        };
        if rows == self.rows && cols == self.cols || rows < 2 {
            return;
        }
        self.reset(out);
        // Scroll up one line if the cursor sits on the row the status line is about to take.
        let _ = write!(out, "\n\x1b[1A\x1b7\x1b[1;{}r\x1b8", rows - 1);
        self.rows = rows;
        self.cols = cols;
        self.draw(out);
    }

    fn draw(&self, out: &mut StdoutLock<'_>) {
        if self.rows == 0 {
            return;
        }
        let end = self
            .line
            .char_indices()
            .nth(usize::from(self.cols.saturating_sub(1)))
            .map_or(self.line.len(), |(i, _)| i);
        let _ = write!(
            out,
            "\x1b7\x1b[{};1H\x1b[2K{}\x1b8",
            self.rows,
            &self.line[..end]
        );
    }

    fn reset(&mut self, out: &mut StdoutLock<'_>) {
        if self.rows == 0 {
            return;
        }
        let _ = write!(out, "\x1b7\x1b[{};1H\x1b[2K\x1b[r\x1b8", self.rows);
        self.rows = 0;
    }
}

/// Replaces the status line.
pub fn set(line: impl Into<String>) {
    let mut state = state();
    state.line = line.into();
    let mut out = io::stdout().lock();
    state.sync(&mut out);
    state.draw(&mut out);
    let _ = out.flush();
    drop(out);
    drop(state);
}

/// Refits the status line to the terminal after a resize.
pub fn redraw() {
    let mut state = state();
    let mut out = io::stdout().lock();
    state.sync(&mut out);
    let _ = out.flush();
    drop(out);
    drop(state);
}

/// Removes the status line and gives the whole terminal back to scrolling output.
pub fn clear() {
    let mut state = state();
    state.line.clear();
    let mut out = io::stdout().lock();
    state.reset(&mut out);
    let _ = out.flush();
    drop(out);
    drop(state);
}

/// Log writer that keeps log output above the status line.
#[derive(Debug, Clone, Copy, Default)]
pub struct Writer;

impl<'a> MakeWriter<'a> for Writer {
    type Writer = EventWriter;

    fn make_writer(&'a self) -> Self::Writer {
        let mut state = state();
        let mut out = io::stdout().lock();
        if state.rows != 0 {
            state.sync(&mut out);
        }
        drop(state);
        EventWriter { out }
    }
}

/// Holds stdout for one log event so it cannot interleave with a status redraw.
pub struct EventWriter {
    out: StdoutLock<'static>,
}

impl Write for EventWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.out.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

impl Drop for EventWriter {
    fn drop(&mut self) {
        let _ = self.out.flush();
    }
}
