mod cli;

use std::fs::File;
use std::io::IsTerminal as _;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser as _;
use cli::{Cli, Cmd};
use roxy::proxy::{self, Proxy};
use roxy::{ca, status, system};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::BoxMakeWriter;

const _: () = assert!(cli::DEFAULT_HOOK_LIMIT.get() == proxy::DEFAULT_MAX_CONCURRENT_HOOKS);

fn main() -> ExitCode {
    let live = std::io::stdout().is_terminal();
    let writer = if live {
        BoxMakeWriter::new(status::Writer)
    } else {
        BoxMakeWriter::new(std::io::stdout)
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("ROXY_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(writer)
        .init();
    match dispatch(Cli::parse().command, live) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(command: Cmd, live: bool) -> Result<()> {
    match command {
        Cmd::Run {
            script,
            port,
            max_concurrent_hooks,
            auto_register,
        } => {
            let mut config = proxy::Config::new(script, port);
            config.max_concurrent_hooks = max_concurrent_hooks.get();
            if live {
                config.live_metrics = true;
                config.metrics_interval = Duration::from_secs(1);
            }
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("starting async runtime")?
                .block_on(run(config, auto_register))
        }
        Cmd::Trust => {
            let dir = ca::default_dir()?;
            ca::CertificateAuthority::load_or_create(&dir)?;
            let cert = ca::cert_path(&dir);
            system::trust(&cert)?;
            tracing::info!("trusted {}", cert.display());
            Ok(())
        }
        Cmd::Register { port } => {
            system::register(port)?;
            tracing::info!("system proxy set to 127.0.0.1:{port}");
            Ok(())
        }
        Cmd::Unregister => {
            system::unregister()?;
            tracing::info!("system proxy cleared");
            Ok(())
        }
    }
}

/// Each proxied connection needs a client and an upstream socket, so macOS's default
/// soft limit of 256 open files runs out with a browser's worth of connections.
const WANTED_OPEN_FILES: u64 = 10_240;

async fn run(config: proxy::Config, auto_register: bool) -> Result<()> {
    match rlimit::increase_nofile_limit(WANTED_OPEN_FILES) {
        Ok(limit) => tracing::debug!("open file limit is {limit}"),
        Err(e) => tracing::warn!("cannot raise the open file limit: {e}"),
    }
    if config.live_metrics {
        tokio::spawn(redraw_on_resize());
    }
    let proxy = Proxy::start(config).await?;
    let port = proxy.local_addr().port();
    let lock = if auto_register {
        match claim_system_proxy(port) {
            Ok(lock) => lock,
            Err(e) => {
                proxy.shutdown().await;
                return Err(e);
            }
        }
    } else {
        None
    };
    shutdown_signal().await;
    tracing::info!("shutting down");
    let unregistered = if auto_register {
        system::unregister_if_ours(port).map(|cleared| {
            if cleared > 0 {
                tracing::info!("system proxy cleared");
            }
        })
    } else {
        Ok(())
    };
    drop(lock); // release only after cleanup, so a new owner can't race our clear
    proxy.shutdown().await;
    unregistered
}

/// Registers the system proxy if no other `--auto-register` instance owns it.
fn claim_system_proxy(port: u16) -> Result<Option<File>> {
    let lock = system::try_lock_registration(&ca::default_dir()?)?;
    if lock.is_some() {
        system::register(port)?;
        tracing::info!("system proxy set to 127.0.0.1:{port}");
    } else {
        tracing::warn!(
            "another roxy instance is auto-registered; \
             run `roxy register --port {port}` to register this instance"
        );
    }
    Ok(lock)
}

async fn redraw_on_resize() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut resized) = signal(SignalKind::window_change()) else {
            return;
        };
        while resized.recv().await.is_some() {
            status::redraw();
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut term) = signal(SignalKind::terminate()) else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
