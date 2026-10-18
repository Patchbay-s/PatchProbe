//! Trait `Platform` et son implémentation pour l'OS courant (sélection par `cfg(target_os)`).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use patchprobe_core::engine::{PingReply, SystemProbe};
use patchprobe_core::iface::choose_active_interface;
use patchprobe_core::parsers::{arp, ping, route};
use patchprobe_core::range::InterfaceInfo;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::process::{find_executable, run};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlatformError {
    #[error("{0} : non pris en charge dans cette version.")]
    Unsupported(&'static str),
    #[error("URL refusée : {0}")]
    InvalidUrl(String),
    #[error("{0}")]
    Failed(String),
}

/// Configuration IPv4 d'une interface (hors périmètre v1 : lecture/écriture non implémentées).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipv4Config {
    pub service: String,
    pub dhcp: bool,
    pub ip: Option<String>,
    pub subnet_mask: Option<String>,
    pub router: Option<String>,
}

/// Profil IP statique nommé — port de `NetworkProfile.swift` (hors périmètre v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkProfile {
    pub id: String,
    pub name: String,
    pub service: String,
    pub ip: String,
    pub subnet_mask: String,
    pub router: String,
}

/// Opérations dépendantes de l'OS. Étend `SystemProbe` (ping, ARP) utilisé par le moteur.
#[async_trait]
pub trait Platform: SystemProbe {
    fn os_name(&self) -> &'static str;

    /// Interfaces IPv4 de la machine.
    fn interfaces(&self) -> Vec<InterfaceInfo>;

    /// Passerelle par défaut (scopée à l'interface préférée quand c'est possible).
    async fn default_gateway(&self, preferred: Option<&InterfaceInfo>) -> Option<Ipv4Addr>;

    /// Interface active (IP et masque) : celle du sous-réseau de la passerelle si possible.
    async fn active_interface(&self) -> Option<InterfaceInfo> {
        let interfaces = self.interfaces();
        let guess = choose_active_interface(&interfaces, None);
        let gateway = self.default_gateway(guess.as_ref()).await;
        choose_active_interface(&interfaces, gateway)
    }

    /// Ouvre une URL http(s) dans le navigateur par défaut.
    fn open_url(&self, url: &str) -> Result<(), PlatformError>;

    /// Ouvre un terminal sur `ssh [utilisateur@]ip [-p port]`. `terminal` vaut `auto` (terminal
    /// par défaut du système) ou l'identifiant choisi dans les réglages.
    fn open_ssh(&self, ip: Ipv4Addr, user: Option<&str>, port: u16, terminal: &str) -> Result<(), PlatformError>;

    /// Ouvre `ftp://ip[:port]` avec l'application FTP par défaut du système.
    fn open_ftp(&self, ip: Ipv4Addr, port: u16) -> Result<(), PlatformError>;

    // --- Hors périmètre de la première version : signatures seulement. ---

    async fn ipv4_config(&self, _service: &str) -> Result<Ipv4Config, PlatformError> {
        Err(PlatformError::Unsupported("Lecture de la configuration IP"))
    }

    async fn apply_dhcp(&self, _service: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Passage en DHCP"))
    }

    async fn apply_static_profile(&self, _profile: &NetworkProfile) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Profils IP statiques"))
    }

    fn install_menu_bar_icon(&self) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Icône de barre des menus"))
    }
}

/// Valide une URL avant de la confier au système : http/https uniquement, pas d'espace ni de
/// caractère de contrôle (un hostname réseau malveillant ne doit pas devenir un argument).
pub fn validate_url(url: &str) -> Result<&str, PlatformError> {
    let ok_scheme = url.starts_with("http://") || url.starts_with("https://");
    let ok_chars =
        url.chars().all(|c| c.is_ascii_graphic()) && !url.contains(['"', '\'', '`', '<', '>', '\\', '^', '|']);
    if ok_scheme && ok_chars && url.len() <= 2048 {
        Ok(url)
    } else {
        Err(PlatformError::InvalidUrl(url.to_owned()))
    }
}

/// Nom d'utilisateur SSH accepté : pas de `-` initial (injection d'option) ni de caractère
/// spécial, puisqu'il est transmis à un terminal.
pub fn validate_ssh_user(user: &str) -> Result<&str, PlatformError> {
    let ok = !user.is_empty()
        && user.len() <= 32
        && !user.starts_with(['-', '.'])
        && user.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(user)
    } else {
        Err(PlatformError::Failed(format!("Nom d'utilisateur SSH refusé : « {user} »")))
    }
}

/// Arguments de `ssh` pour une cible validée (`-p` seulement hors port 22).
pub fn ssh_args(ip: Ipv4Addr, user: Option<&str>, port: u16) -> Result<Vec<String>, PlatformError> {
    if port == 0 {
        return Err(PlatformError::Failed("Port SSH invalide.".into()));
    }
    let target = match user.map(str::trim).filter(|u| !u.is_empty()) {
        Some(user) => format!("{}@{ip}", validate_ssh_user(user)?),
        None => ip.to_string(),
    };
    let mut args = vec!["ssh".to_owned()];
    if port != 22 {
        args.push("-p".into());
        args.push(port.to_string());
    }
    args.push(target);
    Ok(args)
}

/// URL FTP construite uniquement à partir d'une IPv4 et d'un port.
pub fn ftp_url(ip: Ipv4Addr, port: u16) -> Result<String, PlatformError> {
    if port == 0 {
        return Err(PlatformError::Failed("Port FTP invalide.".into()));
    }
    Ok(if port == 21 { format!("ftp://{ip}") } else { format!("ftp://{ip}:{port}") })
}

fn spawn_detached(program: &str, args: &[&str]) -> Result<(), PlatformError> {
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| PlatformError::Failed(format!("impossible de lancer {program} : {e}")))
}

/// Implémentation pour l'OS de compilation.
#[derive(Debug, Clone, Default)]
pub struct SystemPlatform {
    ping_path: Option<PathBuf>,
    arp_path: Option<PathBuf>,
}

const SBIN_DIRS: &[&str] = &["/sbin", "/usr/sbin", "/bin", "/usr/bin", "C:\\Windows\\System32"];

impl SystemPlatform {
    pub fn new() -> Self {
        // Bac à sable : la table ARP est toujours vide, inutile de lancer `arp` pour chaque hôte.
        let arp_path = if crate::is_sandboxed() { None } else { find_executable("arp", SBIN_DIRS) };
        Self { ping_path: find_executable("ping", SBIN_DIRS), arp_path }
    }

    /// Arguments d'un ping unique sans privilèges, selon l'OS.
    pub fn ping_args(ip: Ipv4Addr, timeout: Duration) -> Vec<String> {
        let secs = timeout.as_secs().max(1).to_string();
        let target = ip.to_string();
        if cfg!(target_os = "windows") {
            let ms = timeout.as_millis().clamp(200, 10_000).to_string();
            vec!["-n".into(), "1".into(), "-w".into(), ms, target]
        } else if cfg!(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")) {
            // macOS : -t = délai global en secondes.
            vec!["-n".into(), "-c".into(), "1".into(), "-t".into(), secs, target]
        } else {
            vec!["-n".into(), "-c".into(), "1".into(), "-W".into(), secs, target]
        }
    }

    async fn run_text(&self, program: &str, args: &[&str], timeout: Duration) -> Option<String> {
        let path = find_executable(program, SBIN_DIRS)?;
        run(&path, args, timeout, None).await.ok().map(|o| o.stdout)
    }

    #[cfg(target_os = "linux")]
    async fn read_neighbors(&self) -> HashMap<Ipv4Addr, String> {
        if let Ok(content) = tokio::fs::read_to_string("/proc/net/arp").await {
            let table = arp::parse_proc_net_arp(&content);
            if !table.is_empty() {
                return table;
            }
        }
        match self.run_text("ip", &["-4", "neigh", "show"], Duration::from_secs(5)).await {
            Some(out) => arp::parse_ip_neigh(&out),
            None => HashMap::new(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn read_neighbors(&self) -> HashMap<Ipv4Addr, String> {
        let Some(path) = &self.arp_path else { return HashMap::new() };
        let args: &[&str] = if cfg!(target_os = "windows") { &["-a"] } else { &["-an"] };
        match run(path, args, Duration::from_secs(10), None).await {
            Ok(out) if cfg!(target_os = "windows") => arp::parse_windows_arp(&out.stdout),
            Ok(out) => arp::parse_bsd_arp(&out.stdout),
            Err(_) => HashMap::new(),
        }
    }
}

#[async_trait]
impl SystemProbe for SystemPlatform {
    async fn ping(&self, ip: Ipv4Addr, timeout: Duration) -> PingReply {
        let Some(path) = &self.ping_path else { return PingReply::default() };
        let args = Self::ping_args(ip, timeout);
        // Marge : le binaire peut dépasser légèrement son propre délai.
        let output = run(path, &args, timeout + Duration::from_secs(2), None).await;
        let Ok(output) = output else { return PingReply::default() };
        let parsed = ping::parse_ping(&output.stdout);
        PingReply { alive: parsed.replied(), latency_ms: parsed.latency_ms, ttl: parsed.ttl }
    }

    async fn arp_lookup(&self, ip: Ipv4Addr) -> Option<String> {
        if cfg!(target_os = "linux") {
            return self.read_neighbors().await.remove(&ip);
        }
        let path = self.arp_path.as_ref()?;
        let target = ip.to_string();
        let args: Vec<&str> = if cfg!(target_os = "windows") { vec!["-a", &target] } else { vec!["-n", &target] };
        let output = run(path, &args, Duration::from_secs(5), None).await.ok()?;
        arp::parse_any(&output.stdout).remove(&ip)
    }

    async fn arp_table(&self) -> HashMap<Ipv4Addr, String> {
        self.read_neighbors().await
    }
}

#[async_trait]
impl Platform for SystemPlatform {
    fn os_name(&self) -> &'static str {
        std::env::consts::OS
    }

    fn interfaces(&self) -> Vec<InterfaceInfo> {
        let Ok(list) = if_addrs::get_if_addrs() else { return Vec::new() };
        list.into_iter()
            .filter_map(|iface| match iface.addr {
                if_addrs::IfAddr::V4(v4) => Some(InterfaceInfo::new(iface.name, v4.ip, v4.netmask)),
                if_addrs::IfAddr::V6(_) => None,
            })
            .collect()
    }

    async fn default_gateway(&self, preferred: Option<&InterfaceInfo>) -> Option<Ipv4Addr> {
        let timeout = Duration::from_secs(5);
        if cfg!(target_os = "linux") {
            let name = preferred.map(|p| p.name.as_str());
            if let Ok(content) = tokio::fs::read_to_string("/proc/net/route").await {
                if let Some(gw) = route::parse_proc_net_route(&content, name) {
                    return Some(gw);
                }
            }
            let out = self.run_text("ip", &["-4", "route", "show", "default"], timeout).await?;
            return route::parse_ip_route_default(&out, name);
        }
        if cfg!(target_os = "windows") {
            let out = self.run_text("route", &["print", "-4", "0.0.0.0"], timeout).await?;
            return route::parse_windows_route_print(&out, preferred.map(|p| p.ip));
        }
        // macOS/BSD : d'abord la route scopée à l'interface (un VPN peut détourner la route
        // par défaut globale), puis la route globale.
        if let Some(iface) = preferred {
            let scoped = self.run_text("route", &["-n", "get", "-ifscope", &iface.name, "default"], timeout).await;
            if let Some(gw) = scoped.as_deref().and_then(route::parse_bsd_route_get) {
                return Some(gw);
            }
        }
        let out = self.run_text("route", &["-n", "get", "default"], timeout).await?;
        route::parse_bsd_route_get(&out)
    }

    fn open_url(&self, url: &str) -> Result<(), PlatformError> {
        open_with_system(validate_url(url)?)
    }

    fn open_ftp(&self, ip: Ipv4Addr, port: u16) -> Result<(), PlatformError> {
        open_with_system(&ftp_url(ip, port)?)
    }

    fn open_ssh(&self, ip: Ipv4Addr, user: Option<&str>, port: u16, terminal: &str) -> Result<(), PlatformError> {
        let args = ssh_args(ip, user, port)?;
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        // Les arguments sont validés (lettres, chiffres, `.`, `_`, `-`, `@`, `:`) : aucun
        // métacaractère de shell ou d'AppleScript ne peut y figurer.
        if cfg!(target_os = "windows") {
            open_ssh_windows(&args, terminal)
        } else if cfg!(target_os = "macos") {
            open_ssh_macos(&args, terminal)
        } else {
            open_ssh_linux(&args, terminal)
        }
    }
}

fn unknown_terminal(terminal: &str) -> PlatformError {
    PlatformError::Failed(format!("Terminal inconnu : « {terminal} »"))
}

/// Windows : Windows Terminal (terminal par défaut de Windows 11) s'il est installé, sinon
/// l'invite de commandes. Le terminal choisi dans les réglages prime.
fn open_ssh_windows(args: &[&str], terminal: &str) -> Result<(), PlatformError> {
    let wt =
        || find_executable("wt", &[]).ok_or_else(|| PlatformError::Failed("Windows Terminal est introuvable.".into()));
    match terminal {
        "auto" if find_executable("wt", &[]).is_some() => spawn_detached("wt", args),
        "auto" | "cmd" => {
            let mut command = vec!["/k"];
            command.extend_from_slice(args);
            spawn_in_new_console("cmd", &command)
        }
        "wt" => wt().and_then(|_| spawn_detached("wt", args)),
        "powershell" => {
            let mut command = vec!["-NoExit", "-Command"];
            command.extend_from_slice(args);
            spawn_in_new_console("powershell", &command)
        }
        other => Err(unknown_terminal(other)),
    }
}

/// macOS : l'app associée au schéma `ssh://` (Terminal par défaut, ou celle choisie par
/// l'utilisateur dans Réglages Système), sauf choix explicite dans les réglages.
fn open_ssh_macos(args: &[&str], terminal: &str) -> Result<(), PlatformError> {
    let command = args.join(" ");
    match terminal {
        "auto" => {
            let target = args.last().copied().unwrap_or_default();
            let port = args.windows(2).find(|pair| pair[0] == "-p").map(|pair| pair[1]);
            let url = match port {
                Some(port) => format!("ssh://{target}:{port}"),
                None => format!("ssh://{target}"),
            };
            spawn_detached("open", &[&url])
        }
        "terminal" => spawn_detached(
            "osascript",
            &["-e", &format!("tell application \"Terminal\"\nactivate\ndo script \"{command}\"\nend tell")],
        ),
        "iterm" => spawn_detached(
            "osascript",
            &[
                "-e",
                &format!(
                    "tell application \"iTerm\"\nactivate\ncreate window with default profile command \"{command}\"\nend tell"
                ),
            ],
        ),
        other => Err(unknown_terminal(other)),
    }
}

fn open_ssh_linux(args: &[&str], terminal: &str) -> Result<(), PlatformError> {
    let terminals: [(&str, &[&str]); 5] = [
        ("x-terminal-emulator", &["-e"]),
        ("gnome-terminal", &["--"]),
        ("konsole", &["-e"]),
        ("xfce4-terminal", &["-x"]),
        ("xterm", &["-e"]),
    ];
    if terminal != "auto" && !terminals.iter().any(|(name, _)| *name == terminal) {
        return Err(unknown_terminal(terminal));
    }
    for (name, prefix) in terminals {
        if (terminal != "auto" && terminal != name) || find_executable(name, SBIN_DIRS).is_none() {
            continue;
        }
        let mut command: Vec<&str> = prefix.to_vec();
        command.extend_from_slice(args);
        return spawn_detached(name, &command);
    }
    Err(PlatformError::Failed("terminal introuvable pour lancer ssh".into()))
}

/// Lance un programme console dans sa propre fenêtre (sans passer par `cmd /c start`).
#[cfg(windows)]
fn spawn_in_new_console(program: &str, args: &[&str]) -> Result<(), PlatformError> {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map(|_| ())
        .map_err(|e| PlatformError::Failed(format!("impossible de lancer {program} : {e}")))
}

#[cfg(not(windows))]
fn spawn_in_new_console(program: &str, args: &[&str]) -> Result<(), PlatformError> {
    spawn_detached(program, args)
}

fn open_with_system(url: &str) -> Result<(), PlatformError> {
    if cfg!(target_os = "windows") {
        // Pas de `cmd /c start` : `&` serait interprété par cmd.exe.
        spawn_detached("rundll32", &["url.dll,FileProtocolHandler", url])
    } else if cfg!(target_os = "macos") {
        spawn_detached("open", &[url])
    } else {
        spawn_detached("xdg-open", &[url])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation() {
        assert!(validate_url("http://192.0.2.1").is_ok());
        assert!(validate_url("https://192.0.2.1:8443/").is_ok());
        for bad in
            ["file:///etc/passwd", "javascript:alert(1)", "http://x y", "http://a\"&calc", "http://a\n", "ftp://x", ""]
        {
            assert!(validate_url(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ssh_arguments_are_validated() {
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        assert_eq!(ssh_args(ip, None, 22).unwrap(), ["ssh", "192.0.2.10"]);
        assert_eq!(ssh_args(ip, Some(" admin "), 2222).unwrap(), ["ssh", "-p", "2222", "admin@192.0.2.10"]);
        assert_eq!(ssh_args(ip, Some(""), 22).unwrap(), ["ssh", "192.0.2.10"]);
        for bad in ["-oProxyCommand=calc", "a b", "a;b", "a&b", "a\"b", "a$(x)", ".hidden", "é", &"x".repeat(33)] {
            assert!(ssh_args(ip, Some(bad), 22).is_err(), "{bad:?}");
        }
        assert!(ssh_args(ip, None, 0).is_err());
    }

    #[test]
    fn ftp_url_is_built_from_ip_and_port() {
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        assert_eq!(ftp_url(ip, 21).unwrap(), "ftp://192.0.2.10");
        assert_eq!(ftp_url(ip, 2121).unwrap(), "ftp://192.0.2.10:2121");
        assert!(ftp_url(ip, 0).is_err());
    }

    #[test]
    fn ping_args_are_os_specific() {
        let args = SystemPlatform::ping_args(Ipv4Addr::new(198, 51, 100, 1), Duration::from_millis(1500));
        assert_eq!(args.last().map(String::as_str), Some("198.51.100.1"));
        if cfg!(target_os = "linux") {
            assert_eq!(args, ["-n", "-c", "1", "-W", "1", "198.51.100.1"]);
        }
    }

    #[tokio::test]
    async fn unsupported_features_say_so() {
        let platform = SystemPlatform::new();
        assert!(matches!(platform.ipv4_config("Wi-Fi").await, Err(PlatformError::Unsupported(_))));
        assert!(matches!(platform.install_menu_bar_icon(), Err(PlatformError::Unsupported(_))));
        assert!(platform.open_url("file:///etc/passwd").is_err());
    }

    #[tokio::test]
    async fn local_probes_do_not_panic_or_hang() {
        let platform = SystemPlatform::new();
        let interfaces = platform.interfaces();
        assert!(interfaces.iter().all(|i| i.prefix_len <= 32));
        let _ = platform.active_interface().await;
        let _ = platform.arp_table().await;
        let reply =
            tokio::time::timeout(Duration::from_secs(8), platform.ping(Ipv4Addr::LOCALHOST, Duration::from_secs(1)))
                .await
                .expect("le ping ne doit pas bloquer");
        if reply.alive {
            assert!(reply.ttl.is_some());
        }
    }
}
