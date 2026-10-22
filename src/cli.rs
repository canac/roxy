use std::num::NonZeroUsize;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub const DEFAULT_PORT: u16 = 8080;

/// Must equal `roxy::proxy::DEFAULT_MAX_CONCURRENT_HOOKS`; build.rs can't reach the library.
pub const DEFAULT_HOOK_LIMIT: NonZeroUsize = NonZeroUsize::new(256).expect("nonzero");

#[derive(Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run the proxy on 127.0.0.1 with a hook script.
    Run {
        /// JavaScript module exporting `onRequest` and/or `onResponse`.
        script: PathBuf,
        /// Port to listen on.
        #[arg(short, long, env = "ROXY_PORT", default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Most hooks allowed to run at once; the rest wait their turn.
        #[arg(long, default_value_t = DEFAULT_HOOK_LIMIT)]
        max_concurrent_hooks: NonZeroUsize,
        /// Set the system proxy on startup and clear it on shutdown (macOS).
        #[arg(long)]
        auto_register: bool,
    },
    /// Add roxy's CA certificate to the system trust store (macOS).
    Trust,
    /// Point the system web and secure web proxies at roxy (macOS).
    Register {
        /// Port roxy is listening on.
        #[arg(short, long, env = "ROXY_PORT", default_value_t = DEFAULT_PORT)]
        port: u16,
    },
    /// Turn the system web and secure web proxies off (macOS).
    Unregister,
}
