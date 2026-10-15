//! Parsing des plages à scanner (CIDR, plage, IP unique) — port de `ScanRange.swift`.
//!
//! La taille est vérifiée sur les bornes avant toute matérialisation : une faute de frappe comme
//! `198.51.100.0/8` est refusée immédiatement au lieu de construire 16 millions d'adresses.

use std::fmt;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Plafond du nombre d'adresses d'une plage : 65 536, soit un /16.
pub const MAX_ADDRESSES: u64 = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RangeError {
    #[error("Plage vide.")]
    Empty,
    #[error("Adresse IPv4 invalide : « {0} ».")]
    InvalidAddress(String),
    #[error("Préfixe CIDR invalide : « {0} » (attendu entre 0 et 32).")]
    InvalidPrefix(String),
    #[error("Fin de plage invalide : « {0} » (attendu une IP ou un dernier octet 0-255).")]
    InvalidEnd(String),
    #[error("Plage inversée : {start} est après {end}.")]
    Inverted { start: Ipv4Addr, end: Ipv4Addr },
    #[error("Plage trop grande : {count} adresses (maximum {max}, soit un /16).")]
    TooLarge { count: u64, max: u64 },
}

/// Plage inclusive d'adresses IPv4, déjà validée (non vide, plafonnée).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRange {
    start: u32,
    end: u32,
}

impl ScanRange {
    /// Accepte `192.0.2.0/24`, `192.0.2.1-192.0.2.254`, `192.0.2.1-254` ou une IP seule.
    pub fn parse(raw: &str) -> Result<Self, RangeError> {
        let input = raw.trim();
        if input.is_empty() {
            return Err(RangeError::Empty);
        }
        if let Some((base, prefix)) = input.split_once('/') {
            return Self::parse_cidr(base.trim(), prefix.trim());
        }
        if let Some((start, end)) = input.split_once('-') {
            return Self::parse_dash(start.trim(), end.trim());
        }
        let ip = parse_ipv4(input).ok_or_else(|| RangeError::InvalidAddress(input.to_owned()))?;
        Ok(Self { start: ip, end: ip })
    }

    fn parse_cidr(base: &str, prefix: &str) -> Result<Self, RangeError> {
        let base = parse_ipv4(base).ok_or_else(|| RangeError::InvalidAddress(base.to_owned()))?;
        let prefix_len: u32 =
            prefix.parse().ok().filter(|p| *p <= 32).ok_or_else(|| RangeError::InvalidPrefix(prefix.to_owned()))?;
        let (network, broadcast) = network_bounds(base, prefix_len);
        let host_bits = 32 - prefix_len;
        // /31 (point-à-point) et /32 : toutes les adresses ; sinon on exclut réseau et broadcast.
        let (start, end) = if host_bits >= 2 { (network + 1, broadcast - 1) } else { (network, broadcast) };
        Self::checked(start, end)
    }

    fn parse_dash(start: &str, end: &str) -> Result<Self, RangeError> {
        let start_value = parse_ipv4(start).ok_or_else(|| RangeError::InvalidAddress(start.to_owned()))?;
        let end_value = if let Some(full) = parse_ipv4(end) {
            full
        } else if let Some(last_octet) = parse_octet(end) {
            (start_value & 0xFFFF_FF00) | u32::from(last_octet)
        } else {
            return Err(RangeError::InvalidEnd(end.to_owned()));
        };
        if start_value > end_value {
            return Err(RangeError::Inverted { start: Ipv4Addr::from(start_value), end: Ipv4Addr::from(end_value) });
        }
        Self::checked(start_value, end_value)
    }

    fn checked(start: u32, end: u32) -> Result<Self, RangeError> {
        let count = u64::from(end) - u64::from(start) + 1;
        if count > MAX_ADDRESSES {
            return Err(RangeError::TooLarge { count, max: MAX_ADDRESSES });
        }
        Ok(Self { start, end })
    }

    pub fn first(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.start)
    }

    pub fn last(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.end)
    }

    /// Nombre d'adresses (toujours ≥ 1 et ≤ [`MAX_ADDRESSES`]).
    pub fn len(&self) -> u64 {
        u64::from(self.end) - u64::from(self.start) + 1
    }

    /// Une `ScanRange` n'est jamais vide (invariant de construction).
    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn iter(&self) -> impl Iterator<Item = Ipv4Addr> + Clone + Send + 'static {
        (self.start..=self.end).map(Ipv4Addr::from)
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (self.start..=self.end).contains(&u32::from(ip))
    }
}

impl fmt::Display for ScanRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.first())
        } else {
            write!(f, "{}-{}", self.first(), self.last())
        }
    }
}

/// Parse strict d'une IPv4 pointée : exactement 4 octets décimaux (zéros de tête tolérés, comme
/// `UInt8("01")` côté Swift), sans espace ni signe.
pub fn parse_ipv4(text: &str) -> Option<u32> {
    let mut value: u32 = 0;
    let mut count = 0;
    for part in text.split('.') {
        let octet = parse_octet(part)?;
        value = (value << 8) | u32::from(octet);
        count += 1;
    }
    (count == 4).then_some(value)
}

fn parse_octet(text: &str) -> Option<u8> {
    if text.is_empty() || text.len() > 3 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Adresse réseau et broadcast (en u32) pour une base et un préfixe ≤ 32.
fn network_bounds(base: u32, prefix_len: u32) -> (u32, u32) {
    let mask = prefix_mask(prefix_len);
    let network = base & mask;
    (network, network | !mask)
}

fn prefix_mask(prefix_len: u32) -> u32 {
    match prefix_len {
        0 => 0,
        p if p >= 32 => u32::MAX,
        p => u32::MAX << (32 - p),
    }
}

/// Longueur de préfixe d'un masque pointé (`255.255.255.0` → 24). Comme la version Swift, compte
/// simplement les bits à 1.
pub fn prefix_from_mask(mask: Ipv4Addr) -> u8 {
    // count_ones() d'un u32 vaut au plus 32 : la conversion ne peut pas échouer.
    u8::try_from(u32::from(mask).count_ones()).unwrap_or(32)
}

/// Configuration IPv4 d'une interface locale — port de `NetworkInterfaceInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub prefix_len: u8,
}

impl InterfaceInfo {
    pub fn new(name: impl Into<String>, ip: Ipv4Addr, netmask: Ipv4Addr) -> Self {
        Self { name: name.into(), ip, netmask, prefix_len: prefix_from_mask(netmask) }
    }

    /// Plage CIDR, ex. `192.0.2.0/24`.
    pub fn cidr(&self) -> String {
        let (network, _) = network_bounds(u32::from(self.ip), u32::from(self.prefix_len));
        format!("{}/{}", Ipv4Addr::from(network), self.prefix_len)
    }

    /// Plage par défaut en notation tiret (`192.0.2.1-254`), réseau et broadcast exclus ;
    /// forme complète si la plage ne tient pas dans un seul octet ; l'adresse seule pour un /32.
    pub fn scan_range_text(&self) -> String {
        let prefix = u32::from(self.prefix_len.min(32));
        let host_bits = 32 - prefix;
        if host_bits == 0 {
            return self.ip.to_string();
        }
        let (network, broadcast) = network_bounds(u32::from(self.ip), prefix);
        let (first, last) = if host_bits >= 2 { (network + 1, broadcast - 1) } else { (network, broadcast) };
        let start = Ipv4Addr::from(first);
        if first & 0xFFFF_FF00 == last & 0xFFFF_FF00 {
            format!("{start}-{}", last & 0xFF)
        } else {
            format!("{start}-{}", Ipv4Addr::from(last))
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = prefix_mask(u32::from(self.prefix_len));
        u32::from(ip) & mask == u32::from(self.ip) & mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(input: &str) -> Vec<String> {
        ScanRange::parse(input).unwrap().iter().map(|ip| ip.to_string()).collect()
    }

    #[test]
    fn parses_single_ip() {
        assert_eq!(ips("192.0.2.10"), ["192.0.2.10"]);
        assert_eq!(ips("  192.0.2.10 \n"), ["192.0.2.10"]);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(ScanRange::parse(""), Err(RangeError::Empty));
        assert!(matches!(ScanRange::parse("not an ip"), Err(RangeError::InvalidAddress(_))));
        assert!(matches!(ScanRange::parse("999.1.1.1"), Err(RangeError::InvalidAddress(_))));
        assert!(ScanRange::parse("1.2.3").is_err());
        assert!(ScanRange::parse("192.0.2.1.2").is_err());
        assert!(ScanRange::parse("1.2.3.-4").is_err());
        assert!(ScanRange::parse("1.2..4").is_err());
        assert!(matches!(ScanRange::parse("198.51.100.0/33"), Err(RangeError::InvalidPrefix(_))));
        assert!(matches!(ScanRange::parse("198.51.100.0/x"), Err(RangeError::InvalidPrefix(_))));
        assert!(matches!(ScanRange::parse("198.51.100.1-abc"), Err(RangeError::InvalidEnd(_))));
        assert!(matches!(ScanRange::parse("198.51.100.1-256"), Err(RangeError::InvalidEnd(_))));
    }

    #[test]
    fn cidr_24_excludes_network_and_broadcast() {
        let r = ScanRange::parse("192.0.2.0/24").unwrap();
        assert_eq!(r.len(), 254);
        assert_eq!(r.first().to_string(), "192.0.2.1");
        assert_eq!(r.last().to_string(), "192.0.2.254");
    }

    #[test]
    fn cidr_28_and_non_aligned_base() {
        let r = ScanRange::parse("198.51.100.0/28").unwrap();
        assert_eq!(r.len(), 14);
        assert_eq!(r.first().to_string(), "198.51.100.1");
        assert_eq!(r.last().to_string(), "198.51.100.14");
        // Base non alignée : le masque est appliqué.
        assert_eq!(ScanRange::parse("198.51.100.7/28").unwrap(), r);
    }

    #[test]
    fn cidr_32_and_31() {
        assert_eq!(ips("198.51.100.5/32"), ["198.51.100.5"]);
        assert_eq!(ips("198.51.100.4/31"), ["198.51.100.4", "198.51.100.5"]);
    }

    #[test]
    fn full_and_short_dash_ranges() {
        assert_eq!(ips("192.0.2.1-192.0.2.3"), ["192.0.2.1", "192.0.2.2", "192.0.2.3"]);
        let r = ScanRange::parse("198.51.100.1-255").unwrap();
        assert_eq!(r.len(), 255);
        assert_eq!(r.last().to_string(), "198.51.100.255");
        assert_eq!(ips("198.51.100.1 - 3"), ["198.51.100.1", "198.51.100.2", "198.51.100.3"]);
    }

    #[test]
    fn rejects_inverted_range() {
        assert!(matches!(ScanRange::parse("192.0.2.10-192.0.2.1"), Err(RangeError::Inverted { .. })));
        assert!(matches!(ScanRange::parse("192.0.2.10-2"), Err(RangeError::Inverted { .. })));
    }

    #[test]
    fn size_cap_is_one_slash_16() {
        assert_eq!(ScanRange::parse("0.0.0.0/16").unwrap().len(), 65_534);
        assert_eq!(ScanRange::parse("0.0.0.0-0.0.255.255").unwrap().len(), 65_536);
        assert!(matches!(ScanRange::parse("0.0.0.0-0.1.0.0"), Err(RangeError::TooLarge { count: 65_537, .. })));
        assert!(matches!(ScanRange::parse("198.51.100.0/15"), Err(RangeError::TooLarge { .. })));
        assert!(matches!(ScanRange::parse("198.51.100.0/8"), Err(RangeError::TooLarge { .. })));
        assert!(matches!(ScanRange::parse("0.0.0.0/0"), Err(RangeError::TooLarge { .. })));
        assert!(matches!(ScanRange::parse("0.0.0.1-255.255.255.254"), Err(RangeError::TooLarge { .. })));
    }

    #[test]
    fn ipv4_round_trip() {
        for ip in ["0.0.0.0", "255.255.255.255", "192.0.2.1", "203.0.113.96"] {
            let value = parse_ipv4(ip).unwrap();
            assert_eq!(Ipv4Addr::from(value).to_string(), ip);
        }
        assert_eq!(parse_ipv4("192.000.002.001"), Some(0xC000_0201));
    }

    #[test]
    fn prefix_length_from_mask() {
        assert_eq!(prefix_from_mask(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_from_mask(Ipv4Addr::new(255, 255, 255, 240)), 28);
        assert_eq!(prefix_from_mask(Ipv4Addr::new(255, 255, 255, 255)), 32);
        assert_eq!(prefix_from_mask(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    fn iface(ip: [u8; 4], mask: [u8; 4]) -> InterfaceInfo {
        InterfaceInfo::new("en0", Ipv4Addr::from(ip), Ipv4Addr::from(mask))
    }

    #[test]
    fn interface_cidr_and_scan_range_text() {
        let info = iface([192, 0, 2, 42], [255, 255, 255, 0]);
        assert_eq!(info.cidr(), "192.0.2.0/24");
        assert_eq!(info.scan_range_text(), "192.0.2.1-254");
        let hotspot = iface([198, 51, 100, 6], [255, 255, 255, 240]);
        assert_eq!(hotspot.scan_range_text(), "198.51.100.1-14");
        let single = iface([198, 51, 100, 5], [255, 255, 255, 255]);
        assert_eq!(single.scan_range_text(), "198.51.100.5");
        let wide = iface([0, 0, 2, 5], [255, 255, 0, 0]);
        assert_eq!(wide.scan_range_text(), "0.0.0.1-0.0.255.254");
        assert!(wide.contains(Ipv4Addr::new(0, 0, 200, 1)));
        assert!(!wide.contains(Ipv4Addr::new(0, 1, 0, 1)));
    }

    #[test]
    fn scan_range_text_round_trips_through_parse() {
        let info = iface([198, 51, 100, 5], [255, 255, 255, 0]);
        assert_eq!(ScanRange::parse(&info.scan_range_text()).unwrap().len(), 254);
        let wide = iface([0, 0, 2, 5], [255, 255, 0, 0]);
        assert_eq!(ScanRange::parse(&wide.scan_range_text()).unwrap().len(), 65_534);
    }

    #[test]
    fn display_and_contains() {
        let r = ScanRange::parse("198.51.100.0/30").unwrap();
        assert_eq!(r.to_string(), "198.51.100.1-198.51.100.2");
        assert!(r.contains(Ipv4Addr::new(198, 51, 100, 2)));
        assert!(!r.contains(Ipv4Addr::new(198, 51, 100, 3)));
        assert_eq!(ScanRange::parse("192.0.2.4").unwrap().to_string(), "192.0.2.4");
    }
}
