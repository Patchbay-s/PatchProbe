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
        let url = validate_url(url)?;
        let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "windows") {
            // Pas de `cmd /c start` : `&` serait interprété par cmd.exe.
            ("rundll32", vec!["url.dll,FileProtocolHandler", url])
        } else if cfg!(target_os = "macos") {
            ("open", vec![url])
        } else {
            ("xdg-open", vec![url])
        };
        let mut cmd = std::process::Command::new(program);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd.spawn()
            .map(|_| ())
            .map_err(|e| PlatformError::Failed(format!("impossible d'ouvrir le navigateur ({program}) : {e}")))
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
