//! macOS integration: trusting the CA and pointing the system web proxies at roxy.

use std::ffi::OsString;
use std::fs::{self, File, TryLockError};
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

/// Which of a service's two proxies a setting belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Web,
    SecureWeb,
}

impl ProxyKind {
    const ALL: [Self; 2] = [Self::Web, Self::SecureWeb];

    const fn get_flag(self) -> &'static str {
        match self {
            Self::Web => "-getwebproxy",
            Self::SecureWeb => "-getsecurewebproxy",
        }
    }

    const fn state_flag(self) -> &'static str {
        match self {
            Self::Web => "-setwebproxystate",
            Self::SecureWeb => "-setsecurewebproxystate",
        }
    }
}

/// One proxy as reported by `networksetup -getwebproxy` or `-getsecurewebproxy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySetting {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
}

/// Reads the web and secure web proxy of `service`, in [`ProxyKind::ALL`] order.
#[must_use]
pub fn get_invocations(service: &str) -> [Invocation; 2] {
    ProxyKind::ALL.map(|kind| Invocation::new("networksetup", [kind.get_flag(), service]))
}

/// Parses `networksetup -getwebproxy` output. Returns `None` when a field is missing or invalid.
#[must_use]
pub fn parse_proxy(output: &str) -> Option<ProxySetting> {
    let (mut enabled, mut server, mut port) = (None, None, None);
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Enabled" => enabled = Some(value == "Yes"),
            "Server" => server = Some(value.to_owned()),
            "Port" => port = Some(value.parse().ok()?),
            _ => {}
        }
    }
    Some(ProxySetting {
        enabled: enabled?,
        server: server?,
        port: port?,
    })
}

/// Turns off each enabled proxy in `settings` that points at `127.0.0.1:port`.
#[must_use]
pub fn clear_invocations_if_ours(
    settings: &[(String, ProxyKind, ProxySetting)],
    port: u16,
) -> Vec<Invocation> {
    settings
        .iter()
        .filter(|(_, _, s)| s.enabled && s.server == "127.0.0.1" && s.port == port)
        .map(|(service, kind, _)| {
            Invocation::new("networksetup", [kind.state_flag(), service.as_str(), "off"])
        })
        .collect()
}

/// Tries to become the instance that is auto-registered.
///
/// Returns `Some(file)` when this process now holds the lock. The lock lasts until
/// the file is dropped. Returns `None` when another process holds it.
///
/// # Errors
/// Fails when the directory or lock file cannot be created or locked.
pub fn try_lock_registration(dir: &Path) -> Result<Option<File>> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("auto-register.lock");
    let file = File::create(&path).with_context(|| format!("opening {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => Err(e).context("locking auto-register.lock"),
    }
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

/// Turns off only the system proxies that still point at `127.0.0.1:port`, returning how many.
///
/// # Errors
/// Fails off macOS or when `networksetup` fails.
pub fn unregister_if_ours(port: u16) -> Result<usize> {
    require_macos("register")?;
    let mut settings = Vec::new();
    for service in services()? {
        for (kind, invocation) in ProxyKind::ALL.into_iter().zip(get_invocations(&service)) {
            let output = invocation.run()?;
            if let Some(setting) = parse_proxy(&output) {
                settings.push((service.clone(), kind, setting));
            } else {
                tracing::warn!(
                    "skipping unparseable {} output for {service}",
                    kind.get_flag()
                );
            }
        }
    }
    let clears = clear_invocations_if_ours(&settings, port);
    if clears.is_empty() {
        tracing::debug!("no system proxy points at 127.0.0.1:{port}");
    }
    for invocation in &clears {
        invocation.run()?;
    }
    Ok(clears.len())
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

    fn setting(enabled: bool, server: &str, port: u16) -> ProxySetting {
        ProxySetting {
            enabled,
            server: server.to_owned(),
            port,
        }
    }

    fn entry(service: &str, kind: ProxyKind, s: ProxySetting) -> (String, ProxyKind, ProxySetting) {
        (service.to_owned(), kind, s)
    }

    #[test]
    fn parses_proxy_output() {
        let out = "Enabled: Yes\nServer: 127.0.0.1\nPort: 8080\nAuthenticated Proxy Enabled: 0\n";
        assert_eq!(parse_proxy(out), Some(setting(true, "127.0.0.1", 8080)));

        let out = "Enabled: No\nServer: 127.0.0.1\nPort: 8080\nAuthenticated Proxy Enabled: 0\n";
        assert_eq!(parse_proxy(out), Some(setting(false, "127.0.0.1", 8080)));

        let out = "Enabled: Yes\nServer: proxy.example.com\nPort: 3128\n";
        assert_eq!(
            parse_proxy(out),
            Some(setting(true, "proxy.example.com", 3128))
        );
    }

    #[test]
    fn rejects_incomplete_proxy_output() {
        assert_eq!(parse_proxy("Enabled: Yes\nServer: 127.0.0.1\n"), None);
        assert_eq!(parse_proxy("Server: 127.0.0.1\nPort: 8080\n"), None);
        assert_eq!(parse_proxy("Enabled: Yes\nPort: 8080\n"), None);
        assert_eq!(
            parse_proxy("Enabled: Yes\nServer: 127.0.0.1\nPort: http\n"),
            None
        );
        assert_eq!(parse_proxy(""), None);
    }

    #[test]
    fn builds_get_commands() {
        let [web, secure] = get_invocations("Wi-Fi");
        assert_eq!(web.program, "networksetup");
        assert_eq!(args(&web), ["-getwebproxy", "Wi-Fi"]);
        assert_eq!(secure.program, "networksetup");
        assert_eq!(args(&secure), ["-getsecurewebproxy", "Wi-Fi"]);
    }

    #[test]
    fn clears_both_kinds_when_both_match() {
        let settings = [
            entry("Wi-Fi", ProxyKind::Web, setting(true, "127.0.0.1", 8080)),
            entry(
                "Wi-Fi",
                ProxyKind::SecureWeb,
                setting(true, "127.0.0.1", 8080),
            ),
        ];
        let clears = clear_invocations_if_ours(&settings, 8080);
        assert_eq!(clears.len(), 2);
        assert_eq!(args(&clears[0]), ["-setwebproxystate", "Wi-Fi", "off"]);
        assert_eq!(
            args(&clears[1]),
            ["-setsecurewebproxystate", "Wi-Fi", "off"]
        );
    }

    #[test]
    fn clears_only_the_matching_kind() {
        let settings = [
            entry("Wi-Fi", ProxyKind::Web, setting(true, "127.0.0.1", 9090)),
            entry(
                "Wi-Fi",
                ProxyKind::SecureWeb,
                setting(true, "127.0.0.1", 8080),
            ),
        ];
        let clears = clear_invocations_if_ours(&settings, 8080);
        assert_eq!(clears.len(), 1);
        assert_eq!(
            args(&clears[0]),
            ["-setsecurewebproxystate", "Wi-Fi", "off"]
        );
    }

    #[test]
    fn leaves_other_ports_alone() {
        let settings = [
            entry("Wi-Fi", ProxyKind::Web, setting(true, "127.0.0.1", 8081)),
            entry(
                "Wi-Fi",
                ProxyKind::SecureWeb,
                setting(true, "127.0.0.1", 8081),
            ),
        ];
        assert_eq!(clear_invocations_if_ours(&settings, 8080), Vec::new());
    }

    #[test]
    fn leaves_disabled_proxies_alone() {
        let settings = [
            entry("Wi-Fi", ProxyKind::Web, setting(false, "127.0.0.1", 8080)),
            entry(
                "Wi-Fi",
                ProxyKind::SecureWeb,
                setting(false, "127.0.0.1", 8080),
            ),
        ];
        assert_eq!(clear_invocations_if_ours(&settings, 8080), Vec::new());
    }

    #[test]
    fn clears_matches_across_services() {
        let settings = [
            entry("Wi-Fi", ProxyKind::Web, setting(true, "127.0.0.1", 8080)),
            entry(
                "Wi-Fi",
                ProxyKind::SecureWeb,
                setting(true, "10.0.0.1", 8080),
            ),
            entry(
                "Ethernet",
                ProxyKind::Web,
                setting(false, "127.0.0.1", 8080),
            ),
            entry(
                "Ethernet",
                ProxyKind::SecureWeb,
                setting(true, "127.0.0.1", 8080),
            ),
        ];
        let clears = clear_invocations_if_ours(&settings, 8080);
        assert_eq!(clears.len(), 2);
        assert_eq!(args(&clears[0]), ["-setwebproxystate", "Wi-Fi", "off"]);
        assert_eq!(
            args(&clears[1]),
            ["-setsecurewebproxystate", "Ethernet", "off"]
        );
    }

    #[test]
    fn registration_lock_is_exclusive_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let first = try_lock_registration(dir.path()).unwrap();
        assert!(first.is_some());
        assert!(try_lock_registration(dir.path()).unwrap().is_none());
        drop(first);
        assert!(try_lock_registration(dir.path()).unwrap().is_some());
    }

    #[test]
    fn registration_lock_creates_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        assert!(try_lock_registration(&nested).unwrap().is_some());
        assert!(nested.join("auto-register.lock").is_file());
    }
}
