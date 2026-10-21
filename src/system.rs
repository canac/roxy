//! macOS integration: trusting the CA and pointing the system web proxies at roxy.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result, bail, ensure};

/// One external command, kept as data so callers can inspect it before running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub program: &'static str,
    pub args: Vec<OsString>,
}

impl Invocation {
    fn new<I, S>(program: &'static str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            program,
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    fn run(&self) -> Result<String> {
        let output = Command::new(self.program)
            .args(&self.args)
            .output()
            .with_context(|| format!("running {}", self.program))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        ensure!(
            output.status.success(),
            "{} {:?} failed ({}): {}",
            self.program,
            self.args,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(stdout)
    }
}

fn require_macos(what: &str) -> Result<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        bail!("`roxy {what}` is only supported on macOS")
    }
}

/// The current user's login keychain.
///
/// # Errors
/// Fails when the home directory is unknown.
pub fn login_keychain() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join("Library/Keychains/login.keychain-db"))
        .context("could not determine the home directory")
}

/// Marks `cert` as a trusted root for the current user.
#[must_use]
pub fn trust_invocation(cert: &Path, keychain: &Path) -> Invocation {
    Invocation::new(
        "security",
        [
            OsString::from("add-trusted-cert"),
            "-r".into(),
            "trustRoot".into(),
            "-k".into(),
            keychain.into(),
            cert.into(),
        ],
    )
}

/// Parses `networksetup -listallnetworkservices`, skipping disabled (`*`) services.
#[must_use]
pub fn parse_services(output: &str) -> Vec<String> {
    output
        .lines()
        .skip(1)
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(str::to_owned)
        .collect()
}

/// Sets both the web and secure web proxy of every service to `127.0.0.1:port`.
#[must_use]
pub fn register_invocations(services: &[String], port: u16) -> Vec<Invocation> {
    let port = port.to_string();
    services
        .iter()
        .flat_map(|service| {
            ["-setwebproxy", "-setsecurewebproxy"].map(|flag| {
                Invocation::new(
                    "networksetup",
                    [flag, service.as_str(), "127.0.0.1", port.as_str(), "off"],
                )
            })
        })
        .collect()
}

/// Turns off the web and secure web proxy of every service.
#[must_use]
pub fn unregister_invocations(services: &[String]) -> Vec<Invocation> {
    services
        .iter()
        .flat_map(|service| {
            ["-setwebproxystate", "-setsecurewebproxystate"]
                .map(|flag| Invocation::new("networksetup", [flag, service.as_str(), "off"]))
        })
        .collect()
}

fn services() -> Result<Vec<String>> {
    let listed = Invocation::new("networksetup", ["-listallnetworkservices"]).run()?;
    let services = parse_services(&listed);
    ensure!(!services.is_empty(), "no enabled network services found");
    Ok(services)
}

/// Adds the CA certificate at `cert` to the user's trust store.
///
/// # Errors
/// Fails off macOS or when `security` fails.
pub fn trust(cert: &Path) -> Result<()> {
    require_macos("trust")?;
    trust_invocation(cert, &login_keychain()?).run()?;
    Ok(())
}

/// Points the system web and secure web proxies at `127.0.0.1:port`.
///
/// # Errors
/// Fails off macOS or when `networksetup` fails.
pub fn register(port: u16) -> Result<()> {
    require_macos("register")?;
    for invocation in register_invocations(&services()?, port) {
        invocation.run()?;
    }
    Ok(())
}

/// Turns the system web and secure web proxies off.
///
/// # Errors
/// Fails off macOS or when `networksetup` fails.
pub fn unregister() -> Result<()> {
    require_macos("unregister")?;
    for invocation in unregister_invocations(&services()?) {
        invocation.run()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(inv: &Invocation) -> Vec<&str> {
        inv.args.iter().map(|a| a.to_str().unwrap()).collect()
    }

    #[test]
    fn parses_enabled_services() {
        let out = "An asterisk (*) denotes that a network service is disabled.\n\
                   Wi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN\n\n";
        assert_eq!(parse_services(out), ["Wi-Fi", "USB 10/100/1000 LAN"]);
    }

    #[test]
    fn builds_register_and_unregister_commands() {
        let services = vec!["Wi-Fi".to_owned()];
        let reg = register_invocations(&services, 8080);
        assert_eq!(reg.len(), 2);
        assert_eq!(reg[0].program, "networksetup");
        assert_eq!(
            args(&reg[0]),
            ["-setwebproxy", "Wi-Fi", "127.0.0.1", "8080", "off"]
        );
        assert_eq!(args(&reg[1])[0], "-setsecurewebproxy");

        let unreg = unregister_invocations(&services);
        assert_eq!(args(&unreg[0]), ["-setwebproxystate", "Wi-Fi", "off"]);
        assert_eq!(args(&unreg[1]), ["-setsecurewebproxystate", "Wi-Fi", "off"]);
    }

    #[test]
    fn builds_trust_command() {
        let inv = trust_invocation(Path::new("/c/ca.pem"), Path::new("/k/login.keychain-db"));
        assert_eq!(inv.program, "security");
        assert_eq!(
            args(&inv),
            [
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-k",
                "/k/login.keychain-db",
                "/c/ca.pem"
            ]
        );
    }
}
