#[path = "src/cli.rs"]
mod cli;

use clap::CommandFactory;
use cli::Cli;
use std::fs::create_dir_all;
use std::io::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    // Don't rebuild when the generated completions change
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/cli.rs");

    generate_completions()?;
    generate_manpage()?;

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
