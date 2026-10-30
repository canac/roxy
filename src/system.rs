//! System integration: trusting the CA on macOS, Linux and Windows, and pointing the macOS
//! system web proxies at roxy.

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

    /// Runs `program` as root, through `sudo` unless `root` says roxy already is.
    fn elevated<I, S>(root: bool, program: &'static str, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let inv = Self::new(program, args);
        if root {
            return inv;
        }
        Self::new("sudo", std::iter::once(program.into()).chain(inv.args))
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

/// Marks `cert` as a trusted root for the current macOS user.
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

/// Adds `cert` to the current Windows user's trusted root store, which needs no admin rights.
#[must_use]
pub fn windows_trust_invocation(cert: &Path) -> Invocation {
    Invocation::new(
        "certutil",
        [
            OsString::from("-user"),
            "-addstore".into(),
            "Root".into(),
            cert.into(),
        ],
    )
}

/// A Linux distribution's system CA store.
#[derive(Debug, PartialEq, Eq)]
pub struct LinuxStore {
    /// Directory of extra trusted roots.
    pub anchors: &'static str,
    /// Name to give the certificate in `anchors`, with the extension the update command expects.
    pub file_name: &'static str,
    /// Command that rebuilds the system bundle from `anchors`.
    pub update: (&'static str, &'static [&'static str]),
}

/// Known Linux CA stores, in the order they are probed.
pub const LINUX_STORES: [LinuxStore; 3] = [
    LinuxStore {
        anchors: "/etc/pki/ca-trust/source/anchors",
        file_name: "roxy.pem",
        update: ("update-ca-trust", &["extract"]),
    },
    LinuxStore {
        anchors: "/usr/local/share/ca-certificates",
        file_name: "roxy.crt",
        update: ("update-ca-certificates", &[]),
    },
    LinuxStore {
        anchors: "/etc/ca-certificates/trust-source/anchors",
        file_name: "roxy.crt",
        update: ("trust", &["extract-compat"]),
    },
];

/// The first of [`LINUX_STORES`] whose anchors directory `exists`.
#[must_use]
pub fn linux_store(exists: impl Fn(&Path) -> bool) -> Option<&'static LinuxStore> {
    LINUX_STORES
        .iter()
        .find(|store| exists(Path::new(store.anchors)))
}

/// Copies `cert` into `store` and rebuilds the system bundle, through `sudo` unless `root`.
#[must_use]
pub fn linux_system_invocations(cert: &Path, store: &LinuxStore, root: bool) -> [Invocation; 2] {
    let dest = format!("{}/{}", store.anchors, store.file_name);
    let (program, args) = store.update;
    [
        Invocation::elevated(root, "cp", [cert.as_os_str(), dest.as_ref()]),
        Invocation::elevated(root, program, args),
    ]
}

/// Adds `cert` as a trusted CA to the NSS database at `nssdb`, which Chrome reads on Linux.
#[must_use]
pub fn nss_invocation(cert: &Path, nssdb: &Path) -> Invocation {
    let mut db = OsString::from("sql:");
    db.push(nssdb);
    Invocation::new(
        "certutil",
        [
            OsString::from("-d"),
            db,
            "-A".into(),
            "-t".into(),
            "C,,".into(),
            "-n".into(),
            "roxy".into(),
            "-i".into(),
            cert.into(),
        ],
    )
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

fn is_root() -> bool {
    Invocation::new("id", ["-u"])
        .run()
        .is_ok_and(|uid| uid.trim() == "0")
}

fn trust_linux(cert: &Path) -> Result<()> {
    let mut trusted = if let Some(store) = linux_store(Path::is_dir) {
        for invocation in linux_system_invocations(cert, store, is_root()) {
            invocation.run()?;
        }
        tracing::info!("added to the system trust store in {}", store.anchors);
        true
    } else {
        tracing::warn!("no known system CA directory found, skipping the system trust store");
        false
    };
    if let Some(nssdb) = dirs::home_dir()
        .map(|h| h.join(".pki/nssdb"))
        .filter(|d| d.is_dir())
    {
        if on_path("certutil") {
            nss_invocation(cert, &nssdb).run()?;
            tracing::info!("added to the NSS database in {}", nssdb.display());
            trusted = true;
        } else {
            tracing::warn!(
                "install certutil (libnss3-tools or nss-tools) and rerun `roxy trust` to trust roxy in Chrome"
            );
        }
    }
    ensure!(trusted, "found no trust store to add the CA to");
    Ok(())
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

/// Hosts that `register` adds to the proxy bypass list, so local servers (including roxy's
/// own port) are reached directly instead of through roxy.
pub const LOOPBACK_BYPASS: [&str; 4] = ["localhost", "*.localhost", "127.0.0.1", "::1"];

const BYPASS_RECORD: &str = "bypass-added";

/// Reads the proxy bypass domains of `service`.
#[must_use]
pub fn get_bypass_invocation(service: &str) -> Invocation {
    Invocation::new("networksetup", ["-getproxybypassdomains", service])
}

/// Replaces the proxy bypass domains of `service` with `domains`.
#[must_use]
pub fn set_bypass_invocation(service: &str, domains: &[String]) -> Invocation {
    let mut args = vec!["-setproxybypassdomains", service];
    if domains.is_empty() {
        args.push("Empty");
    } else {
        args.extend(domains.iter().map(String::as_str));
    }
    Invocation::new("networksetup", args)
}

/// Parses `networksetup -getproxybypassdomains` output, one domain per line.
#[must_use]
pub fn parse_bypass(output: &str) -> Vec<String> {
    if output.starts_with("There aren't any bypass domains") {
        return Vec::new();
    }
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A `(service, domain)` pair that `register` added to a bypass list.
pub type BypassEntry = (String, String);

/// Adds the [`LOOPBACK_BYPASS`] hosts missing from each service's current bypass list.
/// Returns the commands to run and the entries they add.
#[must_use]
pub fn bypass_additions(current: &[(String, Vec<String>)]) -> (Vec<Invocation>, Vec<BypassEntry>) {
    let mut invocations = Vec::new();
    let mut added = Vec::new();
    for (service, domains) in current {
        let missing: Vec<String> = LOOPBACK_BYPASS
            .iter()
            .filter(|host| !domains.iter().any(|d| d.eq_ignore_ascii_case(host)))
            .map(|&host| host.to_owned())
            .collect();
        if missing.is_empty() {
            continue;
        }
        let merged: Vec<String> = domains.iter().chain(&missing).cloned().collect();
        invocations.push(set_bypass_invocation(service, &merged));
        added.extend(missing.into_iter().map(|host| (service.clone(), host)));
    }
    (invocations, added)
}

/// Removes the `recorded` entries from each listed service's current bypass list.
/// Returns the commands to run and the recorded entries for services not in `current`.
#[must_use]
pub fn bypass_removals(
    current: &[(String, Vec<String>)],
    recorded: &[BypassEntry],
) -> (Vec<Invocation>, Vec<BypassEntry>) {
    let mut invocations = Vec::new();
    for (service, domains) in current {
        let ours = |d: &String| recorded.iter().any(|(s, r)| s == service && r == d);
        let kept: Vec<String> = domains.iter().filter(|d| !ours(d)).cloned().collect();
        if kept.len() != domains.len() {
            invocations.push(set_bypass_invocation(service, &kept));
        }
    }
    let remaining = recorded
        .iter()
        .filter(|(s, _)| !current.iter().any(|(service, _)| service == s))
        .cloned()
        .collect();
    (invocations, remaining)
}

/// Reads the bypass entries `register` added, from `dir`. A missing record is empty.
///
/// # Errors
/// Fails when the record exists but cannot be read.
pub fn read_bypass_record(dir: &Path) -> Result<Vec<BypassEntry>> {
    let path = dir.join(BYPASS_RECORD);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    Ok(text
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(service, domain)| (service.to_owned(), domain.to_owned()))
        .collect())
}

/// Saves `entries` to `dir`, deleting the record when there are none.
///
/// # Errors
/// Fails when the record cannot be written or removed.
pub fn write_bypass_record(dir: &Path, entries: &[BypassEntry]) -> Result<()> {
    let path = dir.join(BYPASS_RECORD);
    if entries.is_empty() {
        return match fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("removing {}", path.display()))
            }
            _ => Ok(()),
        };
    }
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let text: String = entries
        .iter()
        .flat_map(|(service, domain)| [service.as_str(), "\t", domain.as_str(), "\n"])
        .collect();
    fs::write(&path, text).with_context(|| format!("writing {}", path.display()))
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

/// Services whose proxies are all off once those pointing at `127.0.0.1:port` are cleared.
/// A service missing either setting is left out, since its state is unknown.
#[must_use]
pub fn services_left_off(settings: &[(String, ProxyKind, ProxySetting)], port: u16) -> Vec<String> {
    let mut off: Vec<String> = Vec::new();
    for (service, _, _) in settings {
        let own: Vec<&ProxySetting> = settings
            .iter()
            .filter(|(s, _, _)| s == service)
            .map(|(_, _, setting)| setting)
            .collect();
        let stays_on =
            |s: &&ProxySetting| s.enabled && !(s.server == "127.0.0.1" && s.port == port);
        if own.len() == ProxyKind::ALL.len() && !own.iter().any(stays_on) && !off.contains(service)
        {
            off.push(service.clone());
        }
    }
    off
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

/// Adds the CA certificate at `cert` to the OS trust stores.
///
/// That is the login keychain on macOS, the user's root store on Windows, and on Linux the
/// system store (through `sudo`) plus Chrome's NSS database when `certutil` is installed.
///
/// # Errors
/// Fails on an unsupported OS or when a trust command fails.
pub fn trust(cert: &Path) -> Result<()> {
    if cfg!(target_os = "macos") {
        trust_invocation(cert, &login_keychain()?).run()?;
    } else if cfg!(windows) {
        windows_trust_invocation(cert).run()?;
    } else if cfg!(target_os = "linux") {
        trust_linux(cert)?;
    } else {
        bail!("`roxy trust` is not supported on this OS");
    }
    Ok(())
}

fn bypass_lists(services: &[String]) -> Result<Vec<(String, Vec<String>)>> {
    services
        .iter()
        .map(|service| {
            let output = get_bypass_invocation(service).run()?;
            Ok((service.clone(), parse_bypass(&output)))
        })
        .collect()
}

/// Takes the bypass entries `register` added (recorded in `dir`) back out of `services`.
fn restore_bypass(dir: &Path, services: &[String]) -> Result<()> {
    let recorded = read_bypass_record(dir)?;
    let services: Vec<String> = services
        .iter()
        .filter(|service| recorded.iter().any(|(s, _)| s == *service))
        .cloned()
        .collect();
    let (invocations, remaining) = bypass_removals(&bypass_lists(&services)?, &recorded);
    for invocation in &invocations {
        invocation.run()?;
    }
    write_bypass_record(dir, &remaining)
}

/// Points the system web and secure web proxies at `127.0.0.1:port`, first adding
/// [`LOOPBACK_BYPASS`] to each bypass list and recording what was added in `dir`.
///
/// # Errors
/// Fails off macOS or when `networksetup` or the record fails.
pub fn register(port: u16, dir: &Path) -> Result<()> {
    require_macos("register")?;
    let services = services()?;
    let (invocations, added) = bypass_additions(&bypass_lists(&services)?);
    let mut recorded = read_bypass_record(dir)?;
    for entry in added {
        if !recorded.contains(&entry) {
            recorded.push(entry);
        }
    }
    write_bypass_record(dir, &recorded)?;
    for invocation in invocations
        .iter()
        .chain(&register_invocations(&services, port))
    {
        invocation.run()?;
    }
    Ok(())
}

/// Turns the system web and secure web proxies off and removes the bypass entries
/// `register` added.
///
/// # Errors
/// Fails off macOS or when `networksetup` or the record fails.
pub fn unregister(dir: &Path) -> Result<()> {
    require_macos("unregister")?;
    let services = services()?;
    for invocation in unregister_invocations(&services) {
        invocation.run()?;
    }
    restore_bypass(dir, &services)
}

/// Turns off only the system proxies that still point at `127.0.0.1:port`, returning how many.
/// Services left with no proxy on also lose the bypass entries `register` added.
///
/// # Errors
/// Fails off macOS or when `networksetup` or the record fails.
pub fn unregister_if_ours(port: u16, dir: &Path) -> Result<usize> {
    require_macos("register")?;
    let services = services()?;
    let mut settings = Vec::new();
    for service in &services {
        for (kind, invocation) in ProxyKind::ALL.into_iter().zip(get_invocations(service)) {
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
    restore_bypass(dir, &services_left_off(&settings, port))?;
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

    fn lists(entries: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        entries
            .iter()
            .map(|(service, domains)| {
                let domains = domains.iter().map(|&d| d.to_owned()).collect();
                ((*service).to_owned(), domains)
            })
            .collect()
    }

    fn record(entries: &[(&str, &str)]) -> Vec<BypassEntry> {
        entries
            .iter()
            .map(|(s, d)| ((*s).to_owned(), (*d).to_owned()))
            .collect()
    }

    #[test]
    fn parses_bypass_output() {
        assert_eq!(
            parse_bypass("*.local\n169.254/16\n"),
            ["*.local", "169.254/16"]
        );
        let none = "There aren't any bypass domains set on Wi-Fi.\n";
        assert_eq!(parse_bypass(none), Vec::<String>::new());
    }

    #[test]
    fn builds_bypass_commands() {
        assert_eq!(
            args(&get_bypass_invocation("Wi-Fi")),
            ["-getproxybypassdomains", "Wi-Fi"]
        );
        let set = set_bypass_invocation("Wi-Fi", &["a".to_owned(), "b".to_owned()]);
        assert_eq!(args(&set), ["-setproxybypassdomains", "Wi-Fi", "a", "b"]);
        let clear = set_bypass_invocation("Wi-Fi", &[]);
        assert_eq!(args(&clear), ["-setproxybypassdomains", "Wi-Fi", "Empty"]);
    }

    #[test]
    fn adds_missing_loopback_hosts_after_existing_ones() {
        let current = lists(&[
            ("Wi-Fi", &["*.local", "169.254/16"]),
            (
                "Ethernet",
                &["LOCALHOST", "*.localhost", "127.0.0.1", "::1"],
            ),
            ("USB", &["127.0.0.1"]),
        ]);
        let (invocations, added) = bypass_additions(&current);
        assert_eq!(invocations.len(), 2);
        assert_eq!(
            args(&invocations[0]),
            [
                "-setproxybypassdomains",
                "Wi-Fi",
                "*.local",
                "169.254/16",
                "localhost",
                "*.localhost",
                "127.0.0.1",
                "::1"
            ]
        );
        assert_eq!(
            args(&invocations[1]),
            [
                "-setproxybypassdomains",
                "USB",
                "127.0.0.1",
                "localhost",
                "*.localhost",
                "::1"
            ]
        );
        assert_eq!(
            added,
            record(&[
                ("Wi-Fi", "localhost"),
                ("Wi-Fi", "*.localhost"),
                ("Wi-Fi", "127.0.0.1"),
                ("Wi-Fi", "::1"),
                ("USB", "localhost"),
                ("USB", "*.localhost"),
                ("USB", "::1"),
            ])
        );
    }

    #[test]
    fn removes_only_recorded_entries_of_listed_services() {
        let current = lists(&[
            ("Wi-Fi", &["*.local", "localhost", "example.test", "::1"]),
            ("USB", &["127.0.0.1"]),
        ]);
        let recorded = record(&[
            ("Wi-Fi", "localhost"),
            ("Wi-Fi", "::1"),
            ("USB", "localhost"),
            ("Ethernet", "localhost"),
        ]);
        let (invocations, remaining) = bypass_removals(&current, &recorded);
        assert_eq!(invocations.len(), 1);
        assert_eq!(
            args(&invocations[0]),
            ["-setproxybypassdomains", "Wi-Fi", "*.local", "example.test"]
        );
        assert_eq!(remaining, record(&[("Ethernet", "localhost")]));

        let current = lists(&[("Wi-Fi", &["localhost"])]);
        let (invocations, _) = bypass_removals(&current, &record(&[("Wi-Fi", "localhost")]));
        assert_eq!(
            args(&invocations[0]),
            ["-setproxybypassdomains", "Wi-Fi", "Empty"]
        );
    }

    #[test]
    fn bypass_record_round_trips_and_deletes_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_bypass_record(dir.path()).unwrap(), Vec::new());
        let entries = record(&[("USB 10/100/1000 LAN", "localhost"), ("Wi-Fi", "::1")]);
        write_bypass_record(dir.path(), &entries).unwrap();
        assert_eq!(read_bypass_record(dir.path()).unwrap(), entries);
        write_bypass_record(dir.path(), &[]).unwrap();
        assert!(!dir.path().join(BYPASS_RECORD).exists());
        write_bypass_record(dir.path(), &[]).unwrap();
    }

    #[test]
    fn services_left_off_skip_ones_still_proxied_or_unknown() {
        let settings = [
            entry("Wi-Fi", ProxyKind::Web, setting(true, "127.0.0.1", 8080)),
            entry(
                "Wi-Fi",
                ProxyKind::SecureWeb,
                setting(false, "10.0.0.1", 3128),
            ),
            entry("USB", ProxyKind::Web, setting(true, "127.0.0.1", 8080)),
            entry(
                "USB",
                ProxyKind::SecureWeb,
                setting(true, "127.0.0.1", 9090),
            ),
            entry(
                "Ethernet",
                ProxyKind::Web,
                setting(false, "127.0.0.1", 8080),
            ),
        ];
        assert_eq!(services_left_off(&settings, 8080), ["Wi-Fi"]);
    }

    #[test]
    fn builds_windows_trust_command() {
        let inv = windows_trust_invocation(Path::new(r"C:\roxy\ca.pem"));
        assert_eq!(inv.program, "certutil");
        assert_eq!(
            args(&inv),
            ["-user", "-addstore", "Root", r"C:\roxy\ca.pem"]
        );
    }

    #[test]
    fn picks_the_first_existing_linux_store() {
        let debian = linux_store(|p| p == Path::new("/usr/local/share/ca-certificates"));
        assert_eq!(debian, Some(&LINUX_STORES[1]));
        let fedora_and_debian = linux_store(|p| {
            p == Path::new("/usr/local/share/ca-certificates")
                || p == Path::new("/etc/pki/ca-trust/source/anchors")
        });
        assert_eq!(fedora_and_debian, Some(&LINUX_STORES[0]));
        assert_eq!(linux_store(|_| false), None);
    }

    #[test]
    fn builds_linux_system_commands_through_sudo() {
        let cert = Path::new("/home/u/.local/share/roxy/ca.pem");
        let [copy, update] = linux_system_invocations(cert, &LINUX_STORES[1], false);
        assert_eq!(copy.program, "sudo");
        assert_eq!(
            args(&copy),
            [
                "cp",
                "/home/u/.local/share/roxy/ca.pem",
                "/usr/local/share/ca-certificates/roxy.crt"
            ]
        );
        assert_eq!(update.program, "sudo");
        assert_eq!(args(&update), ["update-ca-certificates"]);

        let [_, update] = linux_system_invocations(cert, &LINUX_STORES[0], false);
        assert_eq!(args(&update), ["update-ca-trust", "extract"]);
        let [_, update] = linux_system_invocations(cert, &LINUX_STORES[2], false);
        assert_eq!(args(&update), ["trust", "extract-compat"]);
    }

    #[test]
    fn builds_linux_system_commands_as_root() {
        let cert = Path::new("/root/.local/share/roxy/ca.pem");
        let [copy, update] = linux_system_invocations(cert, &LINUX_STORES[0], true);
        assert_eq!(copy.program, "cp");
        assert_eq!(
            args(&copy),
            [
                "/root/.local/share/roxy/ca.pem",
                "/etc/pki/ca-trust/source/anchors/roxy.pem"
            ]
        );
        assert_eq!(update.program, "update-ca-trust");
        assert_eq!(args(&update), ["extract"]);
    }

    #[test]
    fn builds_nss_command() {
        let inv = nss_invocation(Path::new("/c/ca.pem"), Path::new("/home/u/.pki/nssdb"));
        assert_eq!(inv.program, "certutil");
        assert_eq!(
            args(&inv),
            [
                "-d",
                "sql:/home/u/.pki/nssdb",
                "-A",
                "-t",
                "C,,",
                "-n",
                "roxy",
                "-i",
                "/c/ca.pem"
            ]
        );
    }
}
