//! `Host` et ses dérivés (clés de tri, libellés, URL navigateur) — port de `Host.swift` et des
//! helpers d'URL de `ScanViewModel.swift`.

use std::cmp::Ordering;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::device_type::DeviceType;
use crate::ttl;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostStatus {
    #[default]
    Unknown,
    Scanning,
    Up,
    Down,
}

impl HostStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Up => "Actif",
            Self::Down => "Inactif",
            Self::Scanning => "Scan en cours",
            Self::Unknown => "Inconnu",
        }
    }

    /// Ordre de tri : actif < en cours < inconnu < inactif.
    pub fn sort_key(self) -> u8 {
        match self {
            Self::Up => 0,
            Self::Scanning => 1,
            Self::Unknown => 2,
            Self::Down => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    /// Identifiant de la technique qui a fourni le nom (ex. `gatewayDns`), pour l'UI.
    pub hostname_source: Option<String>,
    pub status: HostStatus,
    pub latency_ms: Option<f64>,
    pub open_ports: Vec<u16>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    /// Vrai si le fabricant vient d'une correction manuelle par MAC.
    pub vendor_overridden: bool,
    pub ttl: Option<u8>,
    pub is_likely_routed: bool,
    pub probable_os: Option<String>,
    pub device_type: DeviceType,
}

impl Host {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            hostname: None,
            hostname_source: None,
            status: HostStatus::Unknown,
            latency_ms: None,
            open_ports: Vec::new(),
            mac: None,
            vendor: None,
            vendor_overridden: false,
            ttl: None,
            is_likely_routed: false,
            probable_os: None,
            device_type: DeviceType::Unknown,
        }
    }

    /// Applique un TTL de ping : routé + OS probable.
    pub fn apply_ttl(&mut self, ttl_value: Option<u8>) {
        self.ttl = ttl_value;
        self.is_likely_routed = ttl::is_likely_routed(ttl_value);
        self.probable_os = ttl::probable_os(ttl_value).map(str::to_owned);
    }

    /// Recalcule les champs dérivés (type d'appareil).
    pub fn refresh_derived(&mut self) {
        self.device_type = DeviceType::classify(
            self.vendor.as_deref(),
            self.hostname.as_deref(),
            self.probable_os.as_deref(),
            &self.open_ports,
        );
    }

    pub fn status_label(&self) -> &'static str {
        self.status.label()
    }

    /// Les trois premiers octets en /24, pour le groupement par sous-réseau.
    pub fn subnet_key(&self) -> String {
        let [a, b, c, _] = self.ip.octets();
        format!("{a}.{b}.{c}.0/24")
    }

    pub fn latency_sort_key(&self) -> f64 {
        self.latency_ms.unwrap_or(f64::MAX)
    }

    /// URL « meilleure supposition » : https si 443, sinon http si 80, sinon premier port ouvert,
    /// sinon http:// simple.
    pub fn browser_url(&self) -> String {
        for preferred in [443, 80] {
            if self.open_ports.contains(&preferred) {
                return url_for(self.ip, preferred);
            }
        }
        match self.open_ports.first() {
            Some(port) => url_for(self.ip, *port),
            None => format!("http://{}", self.ip),
        }
    }
}

/// Ports conventionnellement servis en TLS ; tout le reste est supposé HTTP.
pub fn scheme_for_port(port: u16) -> &'static str {
    if matches!(port, 443 | 8443 | 9443 | 4443) {
        "https"
    } else {
        "http"
    }
}

/// `scheme://ip[:port]`, port omis quand c'est celui par défaut du schéma.
pub fn url_for(ip: Ipv4Addr, port: u16) -> String {
    let scheme = scheme_for_port(port);
    let default_port = if scheme == "https" { 443 } else { 80 };
    if port == default_port {
        format!("{scheme}://{ip}")
    } else {
        format!("{scheme}://{ip}:{port}")
    }
}

/// Comparaison de chaînes insensible à la casse et « naturelle » sur les nombres (approximation
/// de `localizedStandardCompare`).
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let mut left = a.chars().peekable();
    let mut right = b.chars().peekable();
    loop {
        match (left.peek().copied(), right.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(l), Some(r)) if l.is_ascii_digit() && r.is_ascii_digit() => {
                let ln = take_number(&mut left);
                let rn = take_number(&mut right);
                let ordering = ln
                    .trim_start_matches('0')
                    .len()
                    .cmp(&rn.trim_start_matches('0').len())
                    .then_with(|| ln.trim_start_matches('0').cmp(rn.trim_start_matches('0')));
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (Some(l), Some(r)) => {
                let ordering = l.to_lowercase().cmp(r.to_lowercase());
                if ordering != Ordering::Equal {
                    return ordering;
                }
                left.next();
                right.next();
            }
        }
    }
}

fn take_number(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut digits = String::new();
    while let Some(c) = chars.peek().copied().filter(char::is_ascii_digit) {
        digits.push(c);
        chars.next();
    }
    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str) -> Host {
        Host::new(ip.parse().unwrap())
    }

    #[test]
    fn ip_ordering_is_numeric() {
        assert!(host("192.0.2.2").ip < host("192.0.2.10").ip);
    }

    #[test]
    fn status_sort_order() {
        let ranks: Vec<u8> = [HostStatus::Up, HostStatus::Scanning, HostStatus::Unknown, HostStatus::Down]
            .map(HostStatus::sort_key)
            .to_vec();
        let mut sorted = ranks.clone();
        sorted.sort_unstable();
        assert_eq!(ranks, sorted);
    }

    #[test]
    fn labels_and_subnet_key() {
        assert_eq!(HostStatus::Up.label(), "Actif");
        assert_eq!(HostStatus::Down.label(), "Inactif");
        assert_eq!(host("198.51.100.5").subnet_key(), "198.51.100.0/24");
        assert_eq!(host("192.0.2.4").latency_sort_key(), f64::MAX);
    }

    #[test]
    fn scheme_guessing() {
        assert_eq!(scheme_for_port(443), "https");
        assert_eq!(scheme_for_port(8443), "https");
        assert_eq!(scheme_for_port(80), "http");
        assert_eq!(scheme_for_port(8080), "http");
        assert_eq!(scheme_for_port(22), "http");
    }

    #[test]
    fn url_omits_default_port_only() {
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        assert_eq!(url_for(ip, 80), "http://192.0.2.1");
        assert_eq!(url_for(ip, 443), "https://192.0.2.1");
        assert_eq!(url_for(ip, 8080), "http://192.0.2.1:8080");
        assert_eq!(url_for(ip, 8443), "https://192.0.2.1:8443");
    }

    #[test]
    fn browser_url_fallback_chain() {
        let mut h = host("198.51.100.1");
        assert_eq!(h.browser_url(), "http://198.51.100.1");
        h.open_ports = vec![8123];
        assert_eq!(h.browser_url(), "http://198.51.100.1:8123");
        h.open_ports = vec![8080, 80];
        assert_eq!(h.browser_url(), "http://198.51.100.1");
        h.open_ports = vec![80, 8080, 443];
        assert_eq!(h.browser_url(), "https://198.51.100.1");
    }

    #[test]
    fn apply_ttl_sets_os_and_routing() {
        let mut h = host("198.51.100.1");
        h.apply_ttl(Some(127));
        assert!(h.is_likely_routed);
        assert_eq!(h.probable_os.as_deref(), Some("Windows"));
        h.refresh_derived();
        assert_eq!(h.device_type, DeviceType::Computer);
    }

    #[test]
    fn natural_compare() {
        assert_eq!(natural_cmp("apple", "Zyxel"), Ordering::Less);
        assert_eq!(natural_cmp("host2", "host10"), Ordering::Less);
        assert_eq!(natural_cmp("abc", "abc"), Ordering::Equal);
        assert_eq!(natural_cmp("b", "A"), Ordering::Greater);
    }

    #[test]
    fn serializes_camel_case() {
        let json = serde_json::to_value(host("198.51.100.1")).unwrap();
        assert_eq!(json["ip"], "198.51.100.1");
        assert_eq!(json["status"], "unknown");
        assert!(json.get("openPorts").is_some());
        assert_eq!(json["deviceType"], "unknown");
    }
}
