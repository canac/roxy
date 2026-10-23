#[path = "src/cli.rs"]
mod cli;
#[path = "src/engine/net_stub.rs"]
mod net_stub;

use clap::CommandFactory;
use cli::Cli;
use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs::create_dir_all;
use std::io::{Error, Result};
use std::path::PathBuf;

use deno_core::snapshot::{CreateSnapshotOptions, create_snapshot};
use deno_core::{Extension, ExtensionFileSource, ExtensionFileSourceCode};

fn main() -> Result<()> {
    // Don't rebuild when the generated completions change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/cli.rs");

    generate_completions()?;
    generate_manpage()?;
    generate_snapshot()?;

    Ok(())
}

fn generate_completions() -> Result<()> {
    use clap_complete::generate_to;
    use clap_complete::shells::{Bash, Elvish, Fish, PowerShell, Zsh};

    let cmd = &mut Cli::command();
    let bin_name = String::from(cmd.get_name());
    let out_dir = &PathBuf::from("contrib/completions");

    create_dir_all(out_dir)?;
    generate_to(Bash, cmd, &bin_name, out_dir)?;
    generate_to(Elvish, cmd, &bin_name, out_dir)?;
    generate_to(Fish, cmd, &bin_name, out_dir)?;
    generate_to(PowerShell, cmd, &bin_name, out_dir)?;
    generate_to(Zsh, cmd, &bin_name, out_dir)?;

    Ok(())
}

fn generate_manpage() -> Result<()> {
    let out_dir = &PathBuf::from("man/man1");
    create_dir_all(out_dir)?;
    clap_mangen::generate_to(Cli::command(), out_dir)
}

// The runtime's roxy_ext carries the ops; runtime.js only touches them after the snapshot loads.
deno_core::extension!(
    roxy_ext,
    deps = [deno_webidl, deno_web, deno_net, deno_fetch],
    esm_entry_point = "ext:roxy_ext/runtime.js",
    esm = [dir "src/engine", "runtime.js"],
);

/// Must list the same extensions, in the same order, as the runtime passes to `JsRuntime`.
fn snapshot_extensions() -> Vec<Extension> {
    vec![
        deno_webidl::deno_webidl::lazy_init(),
        deno_web::deno_web::lazy_init(),
        net_stub::deno_net::lazy_init(),
        deno_fetch::deno_fetch::lazy_init(),
        roxy_ext::init(),
    ]
}

/// Writes the startup snapshot plus the lazy sources it left out, so the binary never reads
/// extension JS from the build machine's disk.
fn generate_snapshot() -> Result<()> {
    let out_dir =
        PathBuf::from(std::env::var_os("OUT_DIR").ok_or_else(|| Error::other("OUT_DIR unset"))?);
    let extensions = snapshot_extensions();
    let js: Vec<_> = extensions
        .iter()
        .flat_map(|e| e.lazy_loaded_js_files.iter().cloned())
        .collect();
    let esm: Vec<_> = extensions
        .iter()
        .flat_map(|e| e.lazy_loaded_esm_files.iter().cloned())
        .collect();
    let output = create_snapshot(
        CreateSnapshotOptions {
            cargo_manifest_dir: env!("CARGO_MANIFEST_DIR"),
            startup_snapshot: None,
            skip_op_registration: false,
            extensions,
            extension_transpiler: None,
            with_runtime_cb: None,
        },
        None,
    )
    .map_err(Error::other)?;
    for path in &output.files_loaded_during_snapshot {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    std::fs::write(out_dir.join("snapshot.bin"), &output.output)?;

    let consumed: HashSet<_> = output.consumed_lazy_specifiers.into_iter().collect();
    let table = |files: &[ExtensionFileSource]| -> Result<String> {
        let mut files: Vec<_> = files
            .iter()
            .filter(|file| !consumed.contains(file.specifier))
            .collect();
        // deno_core binary-searches the residual tables.
        files.sort_by_key(|file| file.specifier);
        let mut table = String::from("&[");
        for file in files {
            let ExtensionFileSourceCode::LoadedFromFsDuringSnapshot(path) = file.code else {
                return Err(Error::other(format!(
                    "{} is not loaded from disk",
                    file.specifier
                )));
            };
            if !std::fs::read_to_string(path)?.is_ascii() {
                return Err(Error::other(format!("{path} is not ASCII")));
            }
            let _ = write!(table, "({:?}, include_str!({path:?})),", file.specifier);
        }
        Ok(table + "]")
    };
    std::fs::write(
        out_dir.join("residual.rs"),
        format!(
            "pub static RESIDUAL_LAZY_JS: &[(&str, &str)] = {};\npub static RESIDUAL_LAZY_ESM: &[(&str, &str)] = {};\n",
            table(&js)?,
            table(&esm)?,
        ),
    )
}
